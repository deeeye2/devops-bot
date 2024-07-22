from flask import Flask, request, jsonify
from tqdm import tqdm
from datetime import datetime
import psutil
import threading
import time
import distro
import subprocess
import boto3
import platform
import click
import os
import yaml
import json
import requests
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from .encryption_utils import setup_vault, encrypt_vault, decrypt_vault, VAULT_FOLDER
from botocore.exceptions import NoCredentialsError, PartialCredentialsError

cli = click.Group()

API_BASE_URL = "https://devopsbot-testserver.online"

MASTER_INFO_FILE = os.path.expanduser("~/.devops_master_info")

# Initialize Flask app
app = Flask(__name__)


# Ensure private folder
def ensure_private_folder():
    """Ensure the private folder for storing master info exists with restricted permissions."""
    private_folder = os.path.dirname(MASTER_INFO_FILE)
    if not os.path.exists(private_folder):
        os.makedirs(private_folder, mode=0o700, exist_ok=True)  # rwx------ permissions

# Save master info
def save_master_info(instance_id, public_ip, security_group, key_pair):
    """Save master instance information to a file."""
    ensure_private_folder()
    master_info = {
        'instance_id': instance_id,
        'public_ip': public_ip,
        'security_group': security_group,
        'key_pair': key_pair
    }
    with open(MASTER_INFO_FILE, 'w') as f:
        json.dump(master_info, f)
    os.chmod(MASTER_INFO_FILE, 0o600)  # rw-------



# Get instance metadata
def get_instance_metadata():
    """Fetch instance metadata from AWS metadata service."""
    metadata_url = "http://169.254.169.254/latest/meta-data/"
    token_url = "http://169.254.169.254/latest/api/token"

    try:
        # Fetch IMDSv2 token
        token_response = requests.put(token_url, headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
        token_response.raise_for_status()
        token = token_response.text

        headers = {"X-aws-ec2-metadata-token": token}
        endpoints = ["instance-id", "public-ipv4", "security-groups", "public-keys/0/openssh-key"]

        metadata = {}
        for endpoint in endpoints:
            response = requests.get(metadata_url + endpoint, headers=headers)
            response.raise_for_status()
            if endpoint == "public-keys/0/openssh-key":
                metadata[endpoint] = response.text.split()[2]
            else:
                metadata[endpoint] = response.text

        return metadata["instance-id"], metadata["public-ipv4"], metadata["security-groups"], metadata["public-keys/0/openssh-key"]
    except RequestException as e:
        raise Exception(f"Error fetching metadata: {e}")

# Click group definition
@click.group()
def cli():
    """DevOps Bot CLI."""
    pass


@cli.command(name="master-setup", help="Setup master instance information.")
def setup_master():
    """Setup master instance information."""
    try:
        instance_id, public_ip, security_group, key_pair = get_instance_metadata()
        save_master_info(instance_id, public_ip, security_group, key_pair)
        click.echo(f"Master setup complete with instance ID: {instance_id}, public IP: {public_ip}, security group: {security_group}, key pair: {key_pair}")
    except Exception as e:
        click.echo(f"Failed to setup master: {e}")



def load_master_info():
    """Load master instance information from a file."""
    try:
        with open(MASTER_INFO_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return None

def load_aws_credentials():
    """Load AWS credentials from a file."""
    try:
        with open(os.path.expanduser("~/.aws_credentials"), "r") as cred_file:
            return json.load(cred_file)
    except FileNotFoundError:
        return None

def save_token(token):
    with open(os.path.expanduser("~/.devops_bot_token"), "w") as token_file:
        token_file.write(token)

def load_token():
    try:
        with open(os.path.expanduser("~/.devops_bot_token"), "r") as token_file:
            return token_file.read().strip()
    except FileNotFoundError:
        return None


def save_aws_credentials(access_key, secret_key, region):
    credentials = {
        'aws_access_key_id': access_key,
        'aws_secret_access_key': secret_key,
        'region_name': region
    }
    with open(os.path.expanduser("~/.aws_credentials"), "w") as cred_file:
        json.dump(credentials, cred_file)


@cli.command(help="Greet the user.")
def greet():
    click.echo("Hello from DevOps Bot!")


@cli.command(help="Show version information.")
def version():
    click.echo("devops-bot, version 0.1")



@cli.command(help="Create a directory at the specified path.")
@click.argument('path')
def mkdir(path):
    try:
        os.makedirs(path, exist_ok=True)
        click.echo(f"Directory '{path}' created successfully.")
    except Exception as e:
        click.echo(f"Failed to create directory '{path}': {e}")



@cli.command(help="Solve an issue using the knowledge base.")
@click.argument('issue')
def solve(issue):
    try:
        with open(os.path.join(os.path.dirname(__file__), 'knowledge_base.json'), 'r') as file:
            knowledge_base = json.load(file)
        for entry in knowledge_base['issues']:
            if issue.lower() in entry['problem'].lower():
                click.echo(f"Solution: {entry['solution']}")
                return
        click.echo("Issue not found in knowledge base.")
    except Exception as e:
        click.echo(f"Failed to solve issue '{issue}': {e}")



@cli.command(help="Login to the DevOps Bot.")
def login():
    username = click.prompt('Enter your username')
    password = click.prompt('Enter your password', hide_input=True)
    response = requests.post(f"{API_BASE_URL}/api/login", headers={'Content-Type': 'application/json'}, json={"username": username, "password": password})
    if response.status_code == 200:
        token = response.json().get('token')
        if token:
            save_token(token)
            click.echo(f"Login successful! Your token is: {token}")
            verify_token(username, token)
        else:
            click.echo("Failed to retrieve token.")
    else:
        click.echo("Invalid username or password")



def verify_token(username, token):
    for _ in range(12):  # 1 minute with 5-second intervals
        response = requests.post(f"{API_BASE_URL}/api/verify_token", headers={'Content-Type': 'application/json'}, json={"username": username, "token": token})
        if response.status_code == 200:
            click.echo(f"Token verified successfully for {username}.")
            return
        time.sleep(5)
    click.echo("Token verification failed.")


@cli.command(help="Generate configuration files.")
@click.argument('resource_type')
@click.argument('manifest_type', required=False)
@click.option('--params', type=str, help="Parameters for the resource, in key=value format, separated by spaces.")
def create(resource_type, manifest_type, params):
    """Generate configuration files."""
    token = load_token()
    if not token:
        click.echo("No token found. Please log in first.")
        return

    headers = {'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    data = {}

    if params:
        for param in params.split():
            key, value = param.split('=')
            data[key] = value

    response = requests.post(f"{API_BASE_URL}/generate/{resource_type}/{manifest_type}", headers=headers, json=data)

    if response.status_code == 200:
        response_data = response.json()
        if 'data' in response_data:
            yaml_content = response_data['data']
            with open(f"{resource_type}_{manifest_type}.yaml", "w") as f:
                f.write(yaml_content)
            click.echo(f"{resource_type}_{manifest_type}.yaml file has been generated and saved.")
        else:
            click.echo("Unexpected response format.")
    else:
        click.echo("Failed to generate file.")
        click.echo(response.json().get('message'))


@cli.command(help="Configure AWS credentials.")
@click.option('--aws_access_key_id', required=True, help="AWS Access Key ID")
@click.option('--aws_secret_access_key', required=True, help="AWS Secret Access Key")
@click.option('--region', required=True, help="AWS Region")
def configure_aws(aws_access_key_id, aws_secret_access_key, region):
    save_aws_credentials(aws_access_key_id, aws_secret_access_key, region)
    click.echo("AWS credentials configured successfully.")



@cli.command(help="Create AWS instances.")
@click.option('--params', required=True, help='Parameters for the AWS instance (e.g., "image_id=ami-0abcdef1234567890 instance_type=t2.micro")')
@click.option('--count', default=1, help="Number of instances to create")
@click.option('--tag1', help='First tag for the instances (e.g., "Key1=Value1")')
@click.option('--tag2', help='Second tag for the instances (e.g., "Key2=Value2")')
@click.option('--tag3', help='Third tag for the instances (e.g., "Key3=Value3")')
@click.option('--tag4', help='Fourth tag for the instances (e.g., "Key4=Value4")')
@click.option('--tag5', help='Fifth tag for the instances (e.g., "Key5=Value5")')
@click.option('--security_group', help='Security group for the instances')
@click.option('--key_name', help='Key pair name for the instances')
def create_aws_instance(params, count, tag1, tag2, tag3, tag4, tag5, security_group, key_name):
    aws_credentials = load_aws_credentials()
    if not aws_credentials:
        click.echo("No AWS credentials found. Please configure them first using 'devops-bot configure-aws'.")
        return

    params_dict = dict(param.split('=') for param in params.split())
    tags = [tag1, tag2, tag3, tag4, tag5]
    tags_list = [{'Key': tag.split('=')[0], 'Value': tag.split('=')[1]} for tag in tags if tag]
    tag_specifications = [{'ResourceType': 'instance', 'Tags': tags_list}] if tags_list else []

    try:
        ec2 = boto3.client('ec2', **aws_credentials)
        run_instances_params = {
            'ImageId': params_dict.get('image_id'),
            'InstanceType': params_dict.get('instance_type'),
            'MinCount': count,
            'MaxCount': count,
            'TagSpecifications': tag_specifications if tag_specifications else None
        }
        if security_group:
            run_instances_params['SecurityGroupIds'] = [security_group]
        if key_name:
            run_instances_params['KeyName'] = key_name

        response = ec2.run_instances(**run_instances_params)
        instance_ids = [instance['InstanceId'] for instance in response['Instances']]
        click.echo(f"Instances created successfully: {', '.join(instance_ids)}")
    except NoRegionError:
        click.echo("You must specify a region.")
    except NoCredentialsError:
        click.echo("AWS credentials not found.")
    except PartialCredentialsError:
        click.echo("Incomplete AWS credentials.")
    except Exception as e:
        click.echo(f"Error creating instances: {e}")




@cli.command(help="List all EC2 instances and their statuses.")
@click.option('--provider', required=True, help='Cloud provider to list instances from (e.g., aws)')
def list_instances(provider):
    if provider == 'aws':
        aws_credentials = load_aws_credentials()
        if not aws_credentials:
            click.echo("No AWS credentials found. Please configure them first using 'devops-bot configure-aws'.")
            return

        try:
            ec2 = boto3.client('ec2', **aws_credentials)
            response = ec2.describe_instances()

            running_instances = []
            stopped_instances = []

            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    state = instance['State']['Name']
                    if state == 'running':
                        running_instances.append(instance_id)
                    elif state == 'stopped':
                        stopped_instances.append(instance_id)

            click.echo(f"Provider: AWS")
            click.echo(f"Running instances ({len(running_instances)}): {', '.join(running_instances)}")
            click.echo(f"Stopped instances ({len(stopped_instances)}): {', '.join(stopped_instances)}")
        except NoRegionError:
            click.echo("You must specify a region.")
        except NoCredentialsError:
            click.echo("AWS credentials not found.")
        except PartialCredentialsError:
            click.echo("Incomplete AWS credentials.")
        except Exception as e:
            click.echo(f"Error listing instances: {e}")
    else:
        click.echo(f"Provider '{provider}' is not supported yet.")



# New Command: Stop EC2 Instances
@cli.command(help="Stop AWS instances.")
@click.option('--instance_ids', required=True, help='Space-separated IDs of the AWS instances to stop')
def stop_aws_instances(instance_ids):
    aws_credentials = load_aws_credentials()
    if not aws_credentials:
        click.echo("No AWS credentials found. Please configure them first using 'devops-bot configure-aws'.")
        return

    instance_ids_list = instance_ids.split()
    try:
        ec2 = boto3.client('ec2', **aws_credentials)
        response = ec2.stop_instances(
            InstanceIds=instance_ids_list
        )
        stopped_instance_ids = [instance['InstanceId'] for instance in response['StoppingInstances']]
        click.echo(f"Instances stopped successfully: {', '.join(stopped_instance_ids)}")
    except NoRegionError:
        click.echo("You must specify a region.")
    except NoCredentialsError:
        click.echo("AWS credentials not found.")
    except PartialCredentialsError:
        click.echo("Incomplete AWS credentials.")
    except Exception as e:
        click.echo(f"Error stopping instances: {e}")


# New Command: Start EC2 Instances
@cli.command(help="Start AWS instances.")
@click.option('--instance_ids', required=True, help='Space-separated IDs of the AWS instances to start')
def start_aws_instances(instance_ids):
    aws_credentials = load_aws_credentials()
    if not aws_credentials:
        click.echo("No AWS credentials found. Please configure them first using 'devops-bot configure-aws'.")
        return

    instance_ids_list = instance_ids.split()
    try:
        ec2 = boto3.client('ec2', **aws_credentials)
        response = ec2.start_instances(
            InstanceIds=instance_ids_list
        )
        started_instance_ids = [instance['InstanceId'] for instance in response['StartingInstances']]
        click.echo(f"Instances started successfully: {', '.join(started_instance_ids)}")
    except NoRegionError:
        click.echo("You must specify a region.")
    except NoCredentialsError:
        click.echo("AWS credentials not found.")
    except PartialCredentialsError:
        click.echo("Incomplete AWS credentials.")
    except Exception as e:
        click.echo(f"Error starting instances: {e}")


# Other necessary imports...

MAX_RETRIES = 30
RETRY_INTERVAL = 10
WAIT_TIME_AFTER_CREATION = 120  # 2 minutes

def wait_for_instance_ready(ec2, instance_id):
    """Wait until the instance is in a running state and has passed status checks."""
    for _ in tqdm(range(MAX_RETRIES), desc="Waiting for instance to be ready", unit="s"):
        try:
            response = ec2.describe_instances(InstanceIds=[instance_id])
            instance = response['Reservations'][0]['Instances'][0]
            state = instance['State']['Name']
            if state == 'running':
                click.echo(f"Instance {instance_id} is running.")
                return True
        except Exception as e:
            click.echo(f"Error checking instance status: {e}")
        time.sleep(RETRY_INTERVAL)
    raise Exception(f"Instance {instance_id} did not reach 'running' state within the timeout period.")

def execute_commands_on_instance(instance_id, commands):
    """Execute commands on an instance."""
    ssm = boto3.client('ssm', **load_aws_credentials())
    for platform, cmds in commands.items():
        if platform in ["default", "linux", "ubuntu", "rhel"]:
            try:
                for command in tqdm(cmds, desc=f"Executing commands on instance {instance_id}", unit="cmd"):
                    click.echo(f"Executing command on instance {instance_id} (Platform: {platform}): {command}")
                    response = ssm.send_command(
                        InstanceIds=[instance_id],
                        DocumentName="AWS-RunShellScript",
                        Parameters={'commands': [command]}
                    )
                    command_id = response['Command']['CommandId']
                    check_command_status(ssm, instance_id, command_id)
            except Exception as e:
                click.echo(f"Error executing command on instance {instance_id}: {e}")
                time.sleep(RETRY_INTERVAL)


def check_command_status(ssm, instance_id, command_id):
    """Check the status of the SSM command."""
    for _ in range(MAX_RETRIES):
        response = ssm.get_command_invocation(CommandId=command_id, InstanceId=instance_id)
        status = response['Status']
        if status in ['Success', 'Failed']:
            click.echo(f"Command status on instance {instance_id}: {status}")
            if status == 'Failed':
                raise Exception(f"Command failed with status: {status}")
            return
        time.sleep(RETRY_INTERVAL)
    raise Exception(f"Command status check failed after {MAX_RETRIES * RETRY_INTERVAL} seconds.")

@cli.command(name="dob-screenplay", help="Execute a DOB screenplay to create and manage worker instances.")
@click.argument('script')
def dob_screenplay(script):
    """Execute a DOB screenplay."""
    if not os.path.exists(script):
        click.echo(f"Script file '{script}' does not exist.")
        return

    with open(script, 'r') as f:
        screenplay = yaml.safe_load(f)

    aws_credentials = load_aws_credentials()
    if not aws_credentials:
        click.echo("No AWS credentials found. Please configure them first using 'devops-bot configure-aws'.")
        return

    ec2 = boto3.client('ec2', **aws_credentials)

    try:
        # Create instances
        for instance in screenplay['instances']:
            instance_params = {
                'ImageId': instance['image_id'],
                'InstanceType': instance['instance_type'],
                'MinCount': instance['count'],
                'MaxCount': instance['count'],
                'SecurityGroupIds': [load_master_info()['security_group']],
                'KeyName': load_master_info()['key_pair'],
                'TagSpecifications': [{
                    'ResourceType': 'instance',
                    'Tags': [
                        {'Key': 'Role', 'Value': 'Worker'},
                        {'Key': 'WorkerID', 'Value': instance.get('worker_id', 'worker')}
                    ]
                }]
            }

            response = ec2.run_instances(**instance_params)
            instance_ids = [inst['InstanceId'] for inst in response['Instances']]
            click.echo(f"Instances created successfully: {', '.join(instance_ids)}")

            for instance_id in instance_ids:
                wait_for_instance_ready(ec2, instance_id)
                time.sleep(WAIT_TIME_AFTER_CREATION)

                # Execute commands
                platform = instance.get('platform', 'default')
                platform_commands = screenplay['commands'].get(platform, screenplay['commands']['default'])
                for command in platform_commands:
                    execute_commands_on_instance(instance_id, command)
                    
    except Exception as e:
        click.echo(f"Error creating instances: {e}")



def wait_for_instance_ready(ec2, instance_id):
    """Wait for an instance to be in the 'running' state and display progress."""
    waiter = ec2.get_waiter('instance_running')
    with tqdm(total=30, desc=f"Waiting for instance {instance_id} to be ready", unit='s') as pbar:
        for _ in range(30):
            try:
                waiter.wait(InstanceIds=[instance_id])
                click.echo(f"Instance {instance_id} is running.")
                break
            except Exception as e:
                pbar.update(1)
                time.sleep(1)
        else:
            click.echo(f"Timeout waiting for instance {instance_id} to be ready.")
            
def execute_commands_on_instance(instance_id, command):
    """Execute a command on the specified instance using AWS SSM."""
    ssm = boto3.client('ssm')
    try:
        response = ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunShellScript",
            Parameters={'commands': [command]}
        )
        command_id = response['Command']['CommandId']
        time.sleep(5)  # Wait for the command to start
        output = check_command_status(ssm, instance_id, command_id)
        click.echo(f"Output of the command '{command}' on instance {instance_id}: {output}")
    except Exception as e:
        click.echo(f"Error executing command on instance {instance_id}: {e}")

def check_command_status(ssm, instance_id, command_id):
    """Check the status of the command and return the output."""
    while True:
        time.sleep(5)
        result = ssm.list_command_invocations(
            CommandId=command_id,
            InstanceId=instance_id,
            Details=True
        )
        if result['CommandInvocations']:
            inv = result['CommandInvocations'][0]
            if inv['Status'] == 'Success':
                return inv['CommandPlugins'][0]['Output']
            elif inv['Status'] == 'Failed':
                return inv['CommandPlugins'][0]['Output']
        else:
            continue

    return "No output"


cli.add_command(dob_screenplay)

@click.group()
def vault():
    """Manage the vault for sensitive information."""
    pass

@vault.command(name="vault-setup", help="Setup the vault for sensitive information.")
@click.option('--password', prompt=True, hide_input=True, confirmation_prompt=True, help='Password for encryption')
def setup(password):
    setup_vault(password)
    click.echo("Vault has been set up.")

@vault.command(help="Encrypt files in the vault.")
@click.option('--password', prompt=True, hide_input=True, help='Password for encryption')
def encrypt(password):
    encrypt_vault(password)
    click.echo("Files in the vault have been encrypted.")

@vault.command(help="Decrypt files in the vault.")
@click.option('--password', prompt=True, hide_input=True, help='Password for decryption')
def decrypt(password):
    decrypt_vault(password)
    click.echo("Files in the vault have been decrypted.")
cli.add_command(vault)

# Command to start the master server
@cli.command(help="Start the master server.")
@click.option('--host', default='0.0.0.0', help='Host to bind the server')
@click.option('--port', default=5001, help='Port to bind the server')
def start_master(host, port):
    app.run(host=host, port=port)


# Route to register worker
@app.route('/register_worker', methods=['POST'])
def register_worker_route():
    data = request.get_json()
    worker_id = data['worker_id']
    worker_url = data['worker_url']
    register_worker(worker_id, worker_url)
    return jsonify({'message': 'Worker registered successfully'})

# Register worker (Placeholder for actual implementation)
def register_worker(worker_id, worker_url):
    # Implement the logic to register the worker
    pass

# Route to list workers (Placeholder for actual implementation)
@app.route('/list_workers', methods=['GET'])
def list_workers_route():
    # Implement the logic to list all registered workers
    pass

# Command to start a worker node
@cli.command(help="Start worker node.")
@click.option('--master_url', required=True, help='URL of the master node')
@click.option('--worker_id', required=True, help='Unique ID for the worker node')
@click.option('--host', default='0.0.0.0', help='Host to run the worker node on')
@click.option('--port', default=5001, help='Port to run the worker node on')
def start_worker(master_url, worker_id, host, port):
    worker_app = Flask(__name__)

    @worker_app.route('/execute_task', methods=['POST'])
    def execute_task():
        data = request.json
        command = data['command']
        os.system(command)
        return jsonify({"status": "completed", "command": command})

    def register_worker():
        requests.post(f"{master_url}/register_worker", json={
            "worker_id": worker_id,
            "worker_url": f"http://{host}:{port}"
        })

    threading.Thread(target=register_worker).start()
    worker_app.run(host=host, port=port)

# Function to register a worker with the master
def register_worker(master_url, worker_id, worker_url):
    response = requests.post(f"{master_url}/register_worker", json={
        "worker_id": worker_id,
        "worker_url": worker_url
    })
    if response.status_code == 200:
        click.echo(f"Worker {worker_id} registered successfully with master.")
    else:
        click.echo(f"Failed to register worker {worker_id} with master. Error: {response.text}")


@cli.command(name="list-workers", help="List all registered workers with detailed information.")
def list_workers():
    """List all registered workers."""
    aws_credentials = load_aws_credentials()
    if not aws_credentials:
        click.echo("No AWS credentials found. Please configure them first using 'devops-bot configure-aws'.")
        return

    try:
        ec2 = boto3.client('ec2', **aws_credentials)
        response = ec2.describe_instances(Filters=[{'Name': 'tag:Role', 'Values': ['Worker']}])

        workers = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                if instance['State']['Name'] != 'terminated':
                    worker_info = {
                        'Worker ID': instance['InstanceId'],
                        'AMI': instance['ImageId'],
                        'IP Address': instance.get('PublicIpAddress', 'N/A'),
                        'CPU': instance['InstanceType'],
                        'RAM': instance['InstanceType'],  # Placeholder as actual RAM info is not directly available from EC2 API
                        'Free Space': 'N/A',  # Placeholder as this requires an agent on the worker
                        'Task': 'N/A',  # Placeholder as this requires an agent on the worker
                        'Created At': instance['LaunchTime'].strftime('%Y-%m-%d %H:%M:%S')
                    }
                    workers.append(worker_info)

        if workers:
            for worker in workers:
                for key, value in worker.items():
                    click.echo(f"{key}: {value}")
                click.echo('-' * 40)
        else:
            click.echo("No workers found.")
    except boto3.exceptions.Boto3Error as e:
        click.echo(f"Error listing workers: {e}")

   


@cli.command(name="stop-worker", help="Stop a worker instance.")
@click.option('--worker_id', required=True, help='Unique ID for the worker node')
def stop_worker(worker_id):
    """Stop a worker instance."""
    aws_credentials = load_aws_credentials()
    if not aws_credentials:
        click.echo("No AWS credentials found. Please configure them first using 'devops-bot configure-aws'.")
        return

    try:
        ec2 = boto3.client('ec2', **aws_credentials)
        response = ec2.stop_instances(InstanceIds=[worker_id])
        click.echo(f"Worker instance {worker_id} stopped successfully.")
    except boto3.exceptions.Boto3Error as e:
        click.echo(f"Error stopping worker instance: {e}")




@cli.command(name="assign-task", help="Assign a task to a specific worker.")
@click.option('--worker_id', required=True, help='Unique ID for the worker node')
@click.option('--task', required=True, help='Task command to be executed by the worker')
def assign_task(worker_id, task):
    """Assign a task to a specific worker."""
    aws_credentials = load_aws_credentials()
    if not aws_credentials:
        click.echo("No AWS credentials found. Please configure them first using 'devops-bot configure-aws'.")
        return

    try:
        ec2 = boto3.client('ec2', **aws_credentials)
        response = ec2.describe_instances(InstanceIds=[worker_id])
        worker_ip = response['Reservations'][0]['Instances'][0]['PublicIpAddress']
        
        response = requests.post(f"http://{worker_ip}:5001/execute_task", json={"command": task})
        if response.status_code == 200:
            click.echo(f"Task assigned to worker {worker_id} successfully.")
        else:
            click.echo(f"Failed to assign task. Error: {response.text}")
    except boto3.exceptions.Boto3Error as e:
        click.echo(f"Error assigning task: {e}")



@cli.command(name="create-worker", help="Create one or more worker instances and register them with the master.")
@click.option('--master_url', required=True, help='URL of the master node')
@click.option('--params', required=True, help='Parameters for the AWS instance (e.g., "image_id=ami-0abcdef1234567890 instance_type=t2.micro")')
@click.option('--count', default=1, help='Number of worker instances to create')
def create_worker(master_url, params, count):
    """Create one or more worker instances and register them with the master."""
    aws_credentials = load_aws_credentials()
    if not aws_credentials:
        click.echo("No AWS credentials found. Please configure them first using 'devops-bot configure-aws'.")
        return

    master_info = load_master_info()
    if not master_info:
        click.echo("No master information found. Please run 'devops-bot master-setup' first.")
        return

    params_dict = dict(param.split('=') for param in params.split())
    worker_ids = []
    try:
        ec2 = boto3.client('ec2', **aws_credentials)
        response = ec2.run_instances(
            ImageId=params_dict.get('image_id'),
            InstanceType=params_dict.get('instance_type'),
            MinCount=count,
            MaxCount=count,
            SecurityGroupIds=[master_info['security_group']],
            KeyName=master_info['key_pair'],
            TagSpecifications=[{
                'ResourceType': 'instance',
                'Tags': [{'Key': 'Role', 'Value': 'Worker'}]
            }]
        )
        instance_ids = [instance['InstanceId'] for instance in response['Instances']]
        for index, instance_id in enumerate(instance_ids, start=1):
            worker_id = f"worker{index}"
            click.echo(f"Worker instance created successfully: {instance_id} with Worker ID: {worker_id}")

            # Wait for the instance to be in the running state
            waiter = ec2.get_waiter('instance_running')
            waiter.wait(InstanceIds=[instance_id])

            try:
                public_ip = get_instance_public_ip(ec2, instance_id)
                click.echo(f"Public IP for instance {instance_id} is {public_ip}")
            except Exception as e:
                click.echo(f"Error: {e}")
                continue

            worker_url = f"http://{public_ip}:5001"
            click.echo(f"Worker URL: {worker_url}")

            register_worker(master_url, worker_id, worker_url)
            worker_ids.append(worker_id)

    except boto3.exceptions.Boto3Error as e:
        click.echo(f"Error creating worker instances: {e}")



@cli.command(name="delete-worker", help="Delete one or more AWS worker instances.")
@click.option('--instance_ids', required=True, help='Space-separated IDs of the AWS instances to delete')
def delete_worker(instance_ids):
    """Delete one or more AWS worker instances."""
    aws_credentials = load_aws_credentials()
    if not aws_credentials:
        click.echo("No AWS credentials found. Please configure them first using 'devops-bot configure-aws'.")
        return

    instance_ids_list = instance_ids.split()
    try:
        ec2 = boto3.client('ec2', **aws_credentials)
        response = ec2.terminate_instances(
            InstanceIds=instance_ids_list
        )
        terminated_instance_ids = [instance['InstanceId'] for instance in response['TerminatingInstances']]
        click.echo(f"Instances deleted successfully: {', '.join(terminated_instance_ids)}")
    except boto3.exceptions.NoRegionError:
        click.echo("You must specify a region.")
    except boto3.exceptions.NoCredentialsError:
        click.echo("AWS credentials not found.")
    except boto3.exceptions.PartialCredentialsError:
        click.echo("Incomplete AWS credentials.")
    except Exception as e:
        click.echo(f"Error deleting instances: {e}")


def get_instance_public_ip(ec2, instance_id):
    """Fetch public IP address of an instance."""
    max_retries = 20  # Increased number of retries
    retry_interval = 10  # seconds

    for _ in range(max_retries):
        try:
            response = ec2.describe_instances(InstanceIds=[instance_id])
            instance = response['Reservations'][0]['Instances'][0]
            state = instance['State']['Name']
            public_ip = instance.get('PublicIpAddress')
            if state == 'running' and public_ip:
                return public_ip
        except boto3.exceptions.Boto3Error as e:
            pass  # Ignore errors and retry
        time.sleep(retry_interval)

    raise Exception(f"Instance {instance_id} did not reach 'running' state with a public IP within the timeout period.")



def register_worker(master_url, worker_id, worker_url):
    response = requests.post(f"{master_url}/register_worker", json={
        "worker_id": worker_id,
        "worker_url": worker_url
    })
    if response.status_code == 200:
        click.echo(f"Worker {worker_id} registered successfully with master.")
    else:
        click.echo(f"Failed to register worker {worker_id} with master. Error: {response.text}")
    




cli.command(name="download-s3", help="Download a file from S3.")
@click.argument('bucket_name')
@click.argument('s3_key')
@click.argument('file_path')
def download_s3(bucket_name, s3_key, file_path):
    """Download a file from S3."""
    try:
        credentials = load_aws_credentials()
        s3 = boto3.client('s3', aws_access_key_id=credentials['aws_access_key_id'], aws_secret_access_key=credentials['aws_secret_access_key'], region_name=credentials['region_name'])
        s3.download_file(bucket_name, s3_key, file_path)
        click.echo(f"File {s3_key} from bucket {bucket_name} downloaded to {file_path}.")
    except NoCredentialsError:
        click.echo("AWS credentials not found. Please run 'devops-bot configure-aws'.")
    except PartialCredentialsError:
        click.echo("Incomplete AWS credentials.")
    except Exception as e:
        click.echo(f"Error downloading file: {e}")

@cli.command(name="upload-s3", help="Upload a file to S3.")
@click.argument('file_path')
@click.argument('bucket_name')
@click.argument('s3_key')
def upload_s3(file_path, bucket_name, s3_key):
    """Upload a file to S3."""
    try:
        credentials = load_aws_credentials()
        s3 = boto3.client('s3', aws_access_key_id=credentials['aws_access_key_id'], aws_secret_access_key=credentials['aws_secret_access_key'], region_name=credentials['region_name'])
        s3.upload_file(file_path, bucket_name, s3_key)
        click.echo(f"File {file_path} uploaded to bucket {bucket_name} as {s3_key}.")
    except NoCredentialsError:
        click.echo("AWS credentials not found. Please run 'devops-bot configure-aws'.")
    except PartialCredentialsError:
        click.echo("Incomplete AWS credentials.")
    except Exception as e:
        click.echo(f"Error uploading file: {e}")

@cli.command(name="list-s3-buckets", help="List all S3 buckets.")
def list_s3_buckets():
    """List all S3 buckets."""
    try:
        credentials = load_aws_credentials()
        s3 = boto3.client('s3', aws_access_key_id=credentials['aws_access_key_id'], aws_secret_access_key=credentials['aws_secret_access_key'], region_name=credentials['region_name'])
        response = s3.list_buckets()
        buckets = [bucket['Name'] for bucket in response['Buckets']]
        click.echo("Buckets:")
        for bucket in buckets:
            click.echo(f" - {bucket}")
    except NoCredentialsError:
        click.echo("AWS credentials not found. Please run 'devops-bot configure-aws'.")
    except PartialCredentialsError:
        click.echo("Incomplete AWS credentials.")
    except Exception as e:
        click.echo(f"Error listing buckets: {e}")



@cli.command(name="list-s3-objects", help="List objects in an S3 bucket.")
@click.argument('bucket_name')
def list_s3_objects(bucket_name):
    """List objects in an S3 bucket."""
    try:
        credentials = load_aws_credentials()
        s3 = boto3.client('s3', aws_access_key_id=credentials['aws_access_key_id'], aws_secret_access_key=credentials['aws_secret_access_key'], region_name=credentials['region_name'])
        response = s3.list_objects_v2(Bucket=bucket_name)
        if 'Contents' in response:
            objects = [obj['Key'] for obj in response['Contents']]
            click.echo(f"Objects in bucket {bucket_name}:")
            for obj in objects:
                click.echo(f" - {obj}")
        else:
            click.echo(f"No objects found in bucket {bucket_name}.")
    except NoCredentialsError:
        click.echo("AWS credentials not found. Please run 'devops-bot configure-aws'.")
    except PartialCredentialsError:
        click.echo("Incomplete AWS credentials.")
    except Exception as e:
        click.echo(f"Error listing objects: {e}")


@cli.command(name="create-s3-bucket", help="Create one or more S3 buckets.")
@click.argument('bucket_names', nargs=-1)
@click.option('--region', default=None, help='AWS region to create the bucket in.')
@click.option('--count', default=1, help='Number of buckets to create.')
def create_s3_bucket(bucket_names, region, count):
    """Create one or more S3 buckets."""
    try:
        credentials = load_aws_credentials()
        s3 = boto3.client('s3', aws_access_key_id=credentials['aws_access_key_id'], aws_secret_access_key=credentials['aws_secret_access_key'], region_name=credentials['region_name'])
        for bucket_name in bucket_names:
            for i in range(count):
                unique_bucket_name = f"{bucket_name}-{i}" if count > 1 else bucket_name
                if region and region != "us-east-1":
                    s3.create_bucket(Bucket=unique_bucket_name, CreateBucketConfiguration={'LocationConstraint': region})
                else:
                    s3.create_bucket(Bucket=unique_bucket_name)
                click.echo(f"Bucket {unique_bucket_name} created successfully.")
    except NoCredentialsError:
        click.echo("AWS credentials not found. Please run 'devops-bot configure-aws'.")
    except PartialCredentialsError:
        click.echo("Incomplete AWS credentials.")
    except Exception as e:
        click.echo(f"Error creating bucket: {e}")

@cli.command(name="delete-s3-bucket", help="Delete one or more S3 buckets.")
@click.argument('bucket_names', nargs=-1)
def delete_s3_bucket(bucket_names):
    """Delete one or more S3 buckets."""
    try:
        credentials = load_aws_credentials()
        s3 = boto3.client('s3', aws_access_key_id=credentials['aws_access_key_id'], aws_secret_access_key=credentials['aws_secret_access_key'], region_name=credentials['region_name'])
        for bucket_name in bucket_names:
            s3.delete_bucket(Bucket=bucket_name)
            click.echo(f"Bucket {bucket_name} deleted successfully.")
    except NoCredentialsError:
        click.echo("AWS credentials not found. Please run 'devops-bot configure-aws'.")
    except PartialCredentialsError:
        click.echo("Incomplete AWS credentials.")
    except Exception as e:
        click.echo(f"Error deleting bucket: {e}")

@cli.command(name="delete-s3-object", help="Delete an object from an S3 bucket.")
@click.argument('bucket_name')
@click.argument('s3_key')
def delete_s3_object(bucket_name, s3_key):
    """Delete an object from an S3 bucket."""
    try:
        credentials = load_aws_credentials()
        s3 = boto3.client('s3', aws_access_key_id=credentials['aws_access_key_id'], aws_secret_access_key=credentials['aws_secret_access_key'], region_name=credentials['region_name'])
        s3.delete_object(Bucket=bucket_name, Key=s3_key)
        click.echo(f"Object {s3_key} deleted from bucket {bucket_name}.")
    except NoCredentialsError:
        click.echo("AWS credentials not found. Please run 'devops-bot configure-aws'.")
    except PartialCredentialsError:
        click.echo("Incomplete AWS credentials.")
    except Exception as e:
        click.echo(f"Error deleting object: {e}")

@cli.command(name="copy-s3-object", help="Copy an object from one S3 bucket to another.")
@click.argument('source_bucket')
@click.argument('source_key')
@click.argument('dest_bucket')
@click.argument('dest_key')
def copy_s3_object(source_bucket, source_key, dest_bucket, dest_key):
    """Copy an object from one S3 bucket to another."""
    try:
        credentials = load_aws_credentials()
        s3 = boto3.client('s3', aws_access_key_id=credentials['aws_access_key_id'], aws_secret_access_key=credentials['aws_secret_access_key'], region_name=credentials['region_name'])
        copy_source = {'Bucket': source_bucket, 'Key': source_key}
        s3.copy_object(CopySource=copy_source, Bucket=dest_bucket, Key=dest_key)
        click.echo(f"Object {source_key} from bucket {source_bucket} copied to {dest_key} in bucket {dest_bucket}.")
    except NoCredentialsError:
        click.echo("AWS credentials not found. Please run 'devops-bot configure-aws'.")
    except PartialCredentialsError:
        click.echo("Incomplete AWS credentials.")
    except Exception as e:
        click.echo(f"Error copying object: {e}")


@click.command(name="system-monitor", help="Monitor system information.")
def system_monitor():
    """Monitor and display system information."""
    system_info = {
        "CPU Usage": psutil.cpu_percent(interval=1),
        "Memory Usage": psutil.virtual_memory().percent,
        "Disk Usage": psutil.disk_usage('/').percent,
        "Network Stats": psutil.net_io_counters(),
        "Boot Time": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
    }

    click.echo("System Monitoring Information:")
    for key, value in system_info.items():
        click.echo(f"{key}: {value}")

cli.add_command(system_monitor)



if __name__ == '__main__':

    cli.add_command(install)
    cli.add_command(setup_master)
    cli.add_command(setup)
    cli.add_command(greet)
    cli.add_command(setup_master)
    cli.add_command(delete_worker)
    cli.add_command(stop_worker)
    cli.add_command(list_workers)
    cli.add_command(assign_task)
    cli.add_command(create_worker)
    cli.add_command(dob_screenplay)
    cli.add_command(install)
    cli.add_command(download_s3)
    cli.add_command(upload_s3)
    cli.add_command(list_s3_buckets)
    cli.add_command(list_s3_objects)
    cli.add_command(create_s3_bucket)
    cli.add_command(delete_s3_bucket)
    cli.add_command(delete_s3_object)
    cli.add_command(copy_s3_object)
    cli.add_command(system_monitor)
    
    cli()

