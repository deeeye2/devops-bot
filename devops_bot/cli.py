import os
import warnings
import base64
import json
import click
import time
from datetime import datetime

import paramiko
from socket import gethostbyname, gaierror
import yaml
import uuid
from tabulate import tabulate
import boto3
from botocore.exceptions import ClientError
from cryptography.utils import CryptographyDeprecationWarning
from tqdm import tqdm
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from flask import Flask, jsonify, request
from botocore.exceptions import (ClientError, NoCredentialsError,
                                 PartialCredentialsError)
from socket import gaierror, gethostbyname
from getpass import getpass
from base64 import urlsafe_b64decode, urlsafe_b64encode
import re

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

BASE_DIR = os.path.expanduser("~/.etc/devops-bot")
KEY_FILE = os.path.join(BASE_DIR, "key.key")
AWS_CREDENTIALS_FILE = os.path.join(BASE_DIR, "aws_credentials.json")
HOSTS_FILE = "/etc/hosts"
SSH_KEY_FILE = os.path.expanduser("~/.ssh/id_rsa.pub")
VARIABLES_FILE = os.path.join(BASE_DIR, "roost.dob")
VERSION_BUCKET_NAME = "devops-bot-version-bucket"
VERSION_DIR = os.path.join(BASE_DIR, "version")

FOLDERS = [
    "molt.dob",
    "roost.dob",
    "peacock.dob",
    "ostrich.dob",
    "parrot.dob",
    "pelican.dob"
]

def ensure_folder(path, mode=0o700):
    if not os.path.exists(path):
        os.makedirs(path, mode=mode, exist_ok=True)

# Ensure folders are created at startup
ensure_folder(BASE_DIR)
ensure_folder(VERSION_DIR)

@click.group()
def cli():
    pass

app = Flask(__name__)

def generate_token():
    return secrets.token_urlsafe(32)

def save_key(key):
    ensure_folder(BASE_DIR)
    with open(KEY_FILE, 'w') as key_file:
        key_file.write(key)
    os.chmod(KEY_FILE, 0o600)  # Set file permissions to be readable and writable only by the owner

def get_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return urlsafe_b64encode(kdf.derive(password.encode()))

def load_key():
    if not os.path.exists(KEY_FILE):
        raise FileNotFoundError("Encryption key not found.")
    with open(KEY_FILE, 'r') as key_file:
        return key_file.read()

def generate_key():
    key = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
    save_key(key)
    return key

# Ensure the key file is present or generate a new key if not
if not os.path.exists(KEY_FILE):
    generate_key()

def encrypt_data(data, key):
    fernet = Fernet(key.encode('utf-8'))
    encrypted = fernet.encrypt(data.encode('utf-8'))
    return encrypted

def decrypt_data(encrypted_data, key):
    fernet = Fernet(key.encode('utf-8'))
    decrypted = fernet.decrypt(encrypted_data)
    return decrypted.decode('utf-8')

def check_bucket_exists(bucket_name):
    credentials = load_aws_credentials()
    s3 = boto3.client('s3', **credentials)
    try:
        s3.head_bucket(Bucket=bucket_name)
        return True
    except ClientError:
        return False

# Generate a 32-byte encryption key
key = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
print("Encryption Key:", key)

def load_aws_credentials():
    if os.path.exists(AWS_CREDENTIALS_FILE):
        key = load_key()
        with open(AWS_CREDENTIALS_FILE, 'rb') as cred_file:
            encrypted_credentials = cred_file.read()
        decrypted_credentials = decrypt_data(encrypted_credentials, key)
        return json.loads(decrypted_credentials)
    else:
        click.echo("AWS credentials not found. Please provide them.")
        access_key = click.prompt('AWS Access Key ID')
        secret_key = click.prompt('AWS Secret Access Key')
        region = click.prompt('AWS Region')
        save_aws_credentials(access_key, secret_key, region)
        return load_aws_credentials()

def save_aws_credentials(access_key, secret_key, region):
    ensure_folder(BASE_DIR)
    key = load_key()
    credentials = {
        'aws_access_key_id': access_key,
        'aws_secret_access_key': secret_key,
        'region_name': region
    }
    encrypted_credentials = encrypt_data(json.dumps(credentials), key)
    with open(AWS_CREDENTIALS_FILE, 'wb') as cred_file:
        cred_file.write(encrypted_credentials)
    os.chmod(AWS_CREDENTIALS_FILE, 0o600)
    click.echo("AWS credentials encrypted and saved locally.")

def add_host_entry(user_id, private_ip):
    entry = f"{private_ip} {user_id}\n"
    with open(HOSTS_FILE, 'a') as hosts_file:
        hosts_file.write(entry)
    click.echo(f"Added {user_id} with IP {private_ip} to {HOSTS_FILE}")

def get_host_entry(identifier):
    with open(HOSTS_FILE, 'r') as hosts_file:
        for line in hosts_file:
            if identifier in line:
                return line.split()[0], line.split()[1]
    raise ValueError(f"No entry found for identifier {identifier}")

def ssh_connect_test(hostname, username):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, username=username)
        client.close()
        return True, "Connection successful"
    except Exception as e:
        return False, str(e)

def initialize_directories():
    if not os.path.exists(BASE_DIR):
        os.makedirs(BASE_DIR, mode=0o755)
        click.echo(f"Created base directory: {BASE_DIR}")
    else:
        click.echo(f"Base directory already exists: {BASE_DIR}")

    for folder in FOLDERS:
        folder_path = os.path.join(BASE_DIR, folder)
        if not os.path.exists(folder_path):
            os.makedirs(folder_path, mode=0o755)
            click.echo(f"Created folder: {folder_path}")
        else:
            raise click.ClickException(f"Folder already exists: {folder_path}")

def create_version_bucket():
    credentials = load_aws_credentials()
    if not credentials:
        click.echo("No AWS credentials found. Please configure them first.")
        return None

    s3 = boto3.client('s3', **credentials)
    try:
        if click.confirm(
            "Do you want to create a new bucket for version information?",
                default=True):
            s3.create_bucket(Bucket=VERSION_BUCKET_NAME)
            click.echo(
                f"S3 bucket '{VERSION_BUCKET_NAME}' created successfully.")
    except ClientError as e:
        click.echo(click.style(f"Failed to create S3 bucket: {e}", fg="red"))

def save_version_info_to_bucket(version_id, comment, content):
    key = load_key()
    credentials = load_aws_credentials()
    if not credentials:
        click.echo("No AWS credentials found. Please configure them first.")
        return None

    version_info = {
        'version_id': version_id,
        'comment': comment,
        'content': [serialize_instance_info(instance) for instance in content]
    }
    encrypted_version_info = encrypt_data(json.dumps(version_info), key)

    s3 = boto3.client('s3', **credentials)
    try:
        s3.put_object(
            Bucket=VERSION_BUCKET_NAME,
            Key=f"{version_id}.enc",
            Body=encrypted_version_info)
        click.echo(
            f"Version information saved in S3 bucket with ID {version_id}.")
    except ClientError as e:
        click.echo(
            click.style(
                f"Failed to save version information to bucket: {e}",
                fg="red"))

def serialize_instance_info(instance):
    return {
        'InstanceId': instance.get('InstanceId', 'N/A'),
        'InstanceType': instance.get('InstanceType', 'N/A'),
        'PublicIpAddress': instance.get('PublicIpAddress', 'N/A'),
        'PrivateIpAddress': instance.get('PrivateIpAddress', 'N/A'),
        'State': instance.get('State', {}).get('Name', 'N/A'),
        'ImageId': instance.get('ImageId', 'N/A'),
        'KeyName': instance.get('KeyName', 'N/A'),
        'SecurityGroups': instance.get('SecurityGroups', []),
        'Tags': instance.get('Tags', []),
        'SubnetId': instance.get('SubnetId', 'N/A'),
        'BlockDeviceMappings': instance.get('BlockDeviceMappings', []),
        'IamInstanceProfile': instance.get('IamInstanceProfile', {}).get('Arn', 'N/A'),
        'UserData': instance.get('UserData', 'N/A')
    }

# Ensure version folder
def ensure_version_folder():
    if not os.path.exists(VERSION_DIR):
        os.makedirs(VERSION_DIR, mode=0o700, exist_ok=True)

def list_versions():
    if not os.path.exists(KEY_FILE):
        click.echo(
            "No encryption key found. Please run 'dob configure-aws' to set up your credentials.")
        return []

    key = load_key()
    versions = []

    # Check local versions
    logging.info(f"Checking local directory: {VERSION_DIR}")
    for file_name in os.listdir(VERSION_DIR):
        if file_name.endswith(".enc"):
            logging.info(f"Found file locally: {file_name}")
            version_id = file_name.split(".")[0]
            version_info = load_version_info(version_id)
            if version_info:
                timestamp = datetime.fromtimestamp(
                    os.path.getmtime(
                        os.path.join(
                            VERSION_DIR,
                            f"{version_id}.enc"))).strftime('%Y-%m-%d %H:%M:%S')
                instance_count = len(version_info['content'])
                versions.append(
                    (version_id,
                     version_info.get(
                         'comment',
                         ''),
                        timestamp,
                        instance_count))

    # Check versions in S3
    try:
        credentials = load_aws_credentials()
        s3 = boto3.client('s3', **credentials)
        response = s3.list_objects_v2(Bucket=VERSION_BUCKET_NAME)

        for obj in response.get('Contents', []):
            file_name = obj['Key']
            if file_name.endswith(".enc"):
                logging.info(f"Found file in S3: {file_name}")
                version_id = file_name.split(".")[0]
                version_info = load_version_info(version_id)
                if version_info:
                    timestamp = obj['LastModified'].strftime('%Y-%m-%d %H:%M:%S')
                    instance_count = len(version_info['content'])
                    versions.append(
                        (version_id,
                         version_info.get(
                             'comment',
                             ''),
                            timestamp,
                            instance_count))
    except Exception as e:
        logging.error(f"Failed to check S3: {e}")
        click.echo(f"Failed to access S3 bucket {VERSION_BUCKET_NAME}. Using local versions only.")

    logging.info(f"Final versions found: {versions}")
    return versions

# Load version info
def load_version_info(version_id):
    key = load_key()
    local_version_file = os.path.join(VERSION_DIR, f"{version_id}.enc")

    if os.path.exists(local_version_file):
        # Load version from the local filesystem
        with open(local_version_file, 'rb') as version_file:
            encrypted_version_info = version_file.read()
        decrypted_version_info = decrypt_data(encrypted_version_info, key)
        return json.loads(decrypted_version_info)

    else:
        # Attempt to load the version from the S3 bucket
        try:
            credentials = load_aws_credentials()
            s3 = boto3.client('s3', **credentials)
            response = s3.get_object(
                Bucket=VERSION_BUCKET_NAME,
                Key=f"{version_id}.enc"
            )
            encrypted_version_info = response['Body'].read()
            decrypted_version_info = decrypt_data(encrypted_version_info, key)
            return json.loads(decrypted_version_info)

        except ClientError as e:
            click.echo(click.style(f"No version information found for ID {version_id}.", fg="red"))
            return None

def save_version_info_locally(version_id, comment, content):
    ensure_folder(VERSION_DIR)
    key = load_key()
    version_info = {
        'version_id': version_id,
        'comment': comment,
        'content': content
    }
    encrypted_version_info = encrypt_data(json.dumps(version_info), key)
    with open(os.path.join(VERSION_DIR, f"{version_id}.enc"), 'wb') as version_file:
        version_file.write(encrypted_version_info)
    click.echo(f"Version information saved locally with ID {version_id}.")

def create_ec2_instances(
        instance_type,
        ami_id,
        key_name,
        security_group,
        count,
        tags,
        user_data=None):
    credentials = load_aws_credentials()
    if not credentials:
        click.echo("No AWS credentials found. Please configure them first.")
        return None

    ec2 = boto3.client('ec2', **credentials)
    try:
        instances = ec2.run_instances(
            InstanceType=instance_type,
            ImageId=ami_id,
            KeyName=key_name,
            SecurityGroupIds=[security_group],
            MinCount=count,
            MaxCount=count,
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [{'Key': key, 'Value': value} for key, value in tags.items()]
                }
            ],
            UserData=user_data
        )
        return instances['Instances']
    except ClientError as e:
        click.echo(click.style(f"Failed to create instances: {e}", fg="red"))
        return None

MAX_RETRIES = 30
RETRY_INTERVAL = 10
WAIT_TIME_AFTER_CREATION = 120  # 2 minutes

def fetch_instance_details(instance_ids, credentials):
    ec2 = boto3.client('ec2', **credentials)
    max_retries = 10
    wait_time = 60

    for _ in range(max_retries):
        try:
            response = ec2.describe_instances(InstanceIds=instance_ids)
            all_running = True
            for reservation in response['Reservations']:
                for instance in reservation['Instances']:
                    if instance['State']['Name'] != 'running':
                        all_running = False
                        break
                if not all_running:
                    break
            if all_running:
                return response['Reservations']
            else:
                time.sleep(wait_time)  # Wait before retrying
        except ClientError as e:
            if e.response['Error']['Code'] == 'InvalidInstanceID.NotFound':
                time.sleep(wait_time)  # Wait before retrying
            else:
                raise e
    raise Exception(
        f"Instances {instance_ids} did not reach running state within the allotted time.")

def ensure_ssh_key():
    if not os.path.exists(SSH_KEY_FILE):
        click.echo(
            click.style(
                "SSH key not found. Generating SSH key...",
                fg="yellow"))
        os.system("ssh-keygen -t rsa -b 2048 -f ~/.ssh/id_rsa -N ''")
        click.echo(click.style("SSH key generated.", fg="green"))

@cli.command(name="configure-aws", help="Configure AWS credentials.")
@click.option('--aws_access_key_id', required=True, help="AWS Access Key ID")
@click.option('--aws_secret_access_key', required=True, help="AWS Secret Access Key")
@click.option('--region', required=True, help="AWS Region")
def configure_aws(aws_access_key_id, aws_secret_access_key, region):
    save_aws_credentials(aws_access_key_id, aws_secret_access_key, region)
    click.echo("AWS credentials configured successfully.")

@cli.command(name="configure-instance", help="Configure an instance for DevOps bot access.")
@click.option('--user_id', required=True, help="User ID for the instance")
@click.option('--private_ip', required=True, help="Private IP address of the instance")
def configure_instance(user_id, private_ip):
    add_host_entry(user_id, private_ip)
    click.echo(f"Instance {user_id} configured successfully.")

@cli.command(name="check-nodes", help="Check if the DevOps bot can connect to the node.")
@click.argument('identifier')
@click.option('--username', required=True, help="SSH username for the instance")
def check_nodes(identifier, username):
    try:
        private_ip, _ = get_host_entry(identifier)
        success, message = ssh_connect_test(private_ip, username)
        if success:
            click.echo(f"Connection to {identifier} ({private_ip}) is successful.")
        else:
            click.echo(f"Failed to connect to {identifier} ({private_ip}): {message}")
    except ValueError as ve:
        click.echo(str(ve))

@cli.command(name="screenplay", help="Create EC2 instances, S3 buckets, and/or execute tasks on remote instances listed in /etc/hosts.")
@click.argument('screenplay', type=click.Path(exists=True), required=False)
@click.option('--identifier', required=False, help="Instance identifier")
@click.option('--username', required=False, help="SSH username for the instance")
@click.option('--command', required=False, help="Command to execute on the instance")
@click.pass_context  # Pass the Click context object
def screenplay(ctx, screenplay, identifier, username, command):
    table_data = []

    if screenplay and (screenplay.endswith('.yaml') or screenplay.endswith('.yml')):
        with open(screenplay, 'r') as yaml_file:
            data = yaml.safe_load(yaml_file)
        
         # Handle conditions
        if 'conditions' in data:
            for condition_name, condition in data['conditions'].items():
                result = eval_condition(condition)
                data['conditions'][condition_name]['result'] = result
 
        if 'tasks' in data:
            for task in data['tasks']:
                if 'loop' in task:
                    for item in task['loop']:
                        execute_task(task, item)
                else:
                    execute_task(task)

        # Resolve variables
        variables = load_variables()  # Assuming this is defined elsewhere in your code
        data = resolve_variables(data, variables)  # Assuming this is defined elsewhere in your code
        
         # Handle AWS Network Configuration
        if 'resources' in data:
            if 'vpc' in data['resources']:
                vpc_id = create_vpc(data['resources']['vpc'])
                table_data.append([click.style("+", fg="yellow"), "VPC", data['resources']['vpc']['name']])
            
            if 'subnets' in data['resources']:
                for subnet in data['resources']['subnets']:
                    create_subnet(vpc_id, subnet)
                    table_data.append([click.style("+", fg="yellow"), "Subnet", subnet['name']])
            
            if 'security_groups' in data['resources']:
                for sg in data['resources']['security_groups']:
                    create_security_group(vpc_id, sg)
                    table_data.append([click.style("+", fg="yellow"), "Security Group", sg['name']])
            
            if 'internet_gateway' in data['resources']:
                igw_id = create_internet_gateway(vpc_id, data['resources']['internet_gateway'])
                table_data.append([click.style("+", fg="yellow"), "Internet Gateway", data['resources']['internet_gateway']['name']])
            
            if 'route_tables' in data['resources']:
                for rt in data['resources']['route_tables']:
                    create_route_table(vpc_id, igw_id, rt)
                    table_data.append([click.style("+", fg="yellow"), "Route Table", rt['name']])

        # EC2 creation section
        if 'resources' in data and 'ec2_instances' in data['resources']:
            for idx, resource in enumerate(data['resources']['ec2_instances']):
                table_data.append([click.style("+", fg="green"), "EC2 Instance", f"Instance {idx+1}"])
                table_data.extend([
                    [click.style("+", fg="green"), "Instance Type", resource['instance_type']],
                    [click.style("+", fg="green"), "AMI ID", resource['ami_id']],
                    [click.style("+", fg="green"), "Key Name", resource['key_name']],
                    [click.style("+", fg="green"), "Security Group", resource['security_group']]
                ])

                optional_params = [
                    ('Tags', 'tags'),
                    ('Subnet ID', 'subnet_id'),
                    ('IAM Role', 'iam_instance_profile'),
                    ('Block Device Mappings', 'block_device_mappings'),
                    ('Monitoring', 'monitoring'),
                    ('Instance Initiated Shutdown Behavior', 'instance_initiated_shutdown_behavior'),
                    ('Private IP Address', 'private_ip_address'),
                    ('Elastic IP Allocation ID', 'elastic_ip_allocation_id'),
                    ('Count', 'count'),
                    ('User Data', 'user_data')
                ]
                for label, key in optional_params:
                    if key in resource:
                        table_data.append([click.style("+", fg="green"), label, resource[key]])

        # S3 Bucket creation section
        if 'resources' in data and 's3_buckets' in data['resources']:
            for idx, bucket in enumerate(data['resources']['s3_buckets']):
                table_data.append([click.style("+", fg="yellow"), "S3 Bucket", f"Bucket {idx+1}"])
                table_data.extend([
                    [click.style("+", fg="yellow"), "Bucket Name", bucket['bucket_name']],  # Required
                    [click.style("+", fg="yellow"), "Region", bucket.get('region', 'Not specified')],  # Optional
                    [click.style("+", fg="yellow"), "Public Access Block", bucket.get('public_access_block', True)],  # Optional
                    [click.style("+", fg="yellow"), "Versioning", bucket.get('versioning', False)],  # Optional
                    [click.style("+", fg="yellow"), "Lifecycle Rules", bucket.get('lifecycle_rules', 'None')],  # Optional
                    [click.style("+", fg="yellow"), "Logging", bucket.get('logging', 'None')],  # Optional
                    [click.style("+", fg="yellow"), "Encryption", bucket.get('encryption', 'None')],  # Optional
                ])

            # Displaying the entire table for review
            click.echo("\nFinal Review of All Actions:")
            click.echo(tabulate(table_data, headers=["", "Category", "Value"], tablefmt="grid"))

            if click.confirm(click.style("Do you want to proceed with executing these actions?", fg="green"), default=True):
                for bucket in data['resources']['s3_buckets']:
                    # Invoke the create_s3_bucket command using ctx.invoke
                    ctx.invoke(create_s3_bucket,
                               bucket['bucket_name'],
                               region=bucket.get('region'),
                               public_access_block=bucket.get('public_access_block', True),
                               versioning=bucket.get('versioning', False),
                               lifecycle_rules=json.dumps(bucket.get('lifecycle_rules', [])),
                               logging=json.dumps(bucket.get('logging', {})),
                               encryption=json.dumps(bucket.get('encryption', {}))
                               )

        # Remote server section
        if 'remote-server' in data:
            for server in data['remote-server']:
                table_data.append([click.style("+", fg="blue"), "Remote Server", server.get('identifiers', 'N/A')])
                table_data.append([click.style("+", fg="blue"), "Username", server.get('username', 'root')])

        # Task execution section
        if 'tasks' in data:
            for task in data['tasks']:
                task_identifier = task.get('identifiers', 'ALL')
                task_user = task.get('username', 'root')
                table_data.append([click.style("+", fg="cyan"), "Task", task['action']])
                table_data.append([click.style("+", fg="cyan"), "Command", task.get('command', 'N/A')])

        # Displaying the entire table for review
        click.echo("\nFinal Review of All Actions:")
        click.echo(tabulate(table_data, headers=["", "Category", "Value"], tablefmt="grid"))

        # Confirm the execution
        if click.confirm(click.style("Do you want to proceed with executing these actions?", fg="green"), default=True):
            # EC2 instance creation
            if 'resources' in data and 'ec2_instances' in data['resources']:
                try:
                    instances = []
                    credentials = load_aws_credentials()  # Assuming this is defined elsewhere in your code
                    for resource in data['resources']['ec2_instances']:
                        ec2_params = {
                            'InstanceType': resource['instance_type'],
                            'ImageId': resource['ami_id'],
                            'KeyName': resource['key_name'],
                            'SecurityGroupIds': [resource['security_group']],
                            'MinCount': resource.get('count', 1),
                            'MaxCount': resource.get('count', 1),
                            'TagSpecifications': [{
                                'ResourceType': 'instance',
                                'Tags': [{'Key': k, 'Value': v} for k, v in resource.get('tags', {}).items()]
                            }]
                        }

                        if resource.get('subnet_id'):
                            ec2_params['SubnetId'] = resource['subnet_id']
                        if resource.get('iam_instance_profile'):
                            ec2_params['IamInstanceProfile'] = {'Name': resource['iam_instance_profile']}
                        if resource.get('block_device_mappings'):
                            ec2_params['BlockDeviceMappings'] = resource['block_device_mappings']
                        if resource.get('monitoring') is not None:
                            ec2_params['Monitoring'] = {'Enabled': resource['monitoring']}
                        if resource.get('instance_initiated_shutdown_behavior'):
                            ec2_params['InstanceInitiatedShutdownBehavior'] = resource['instance_initiated_shutdown_behavior']}
                        if resource.get('private_ip_address'):
                            ec2_params['PrivateIpAddress'] = resource['private_ip_address']
                        if resource.get('user_data'):
                            ec2_params['UserData'] = resource['user_data']
                        ec2 = boto3.client('ec2', **credentials)
                        response = ec2.run_instances(**ec2_params)

                        instance_ids = [instance['InstanceId'] for instance in response['Instances']]
                        instances.extend(instance_ids)

                    click.echo(f"Instances created with IDs: {', '.join(instances)}")
                    click.echo("Waiting for instances to be in running state...")
                    reservations = fetch_instance_details(instance_ids, credentials)  # Assuming this is defined elsewhere in your code
                    click.echo("Instances are now running.")

                    if check_bucket_exists(VERSION_BUCKET_NAME):  # Assuming this is defined elsewhere in your code
                        version_id = str(uuid.uuid4())
                        comment = click.prompt("Enter a comment for this version")
                        save_version_info_to_bucket(version_id, comment, reservations)  # Assuming this is defined elsewhere in your code
                    else:
                        if click.confirm("Do you want to save the version information in a bucket?", default=False):
                            version_id = str(uuid.uuid4())
                            comment = click.prompt("Enter a comment for this version")
                            create_version_bucket()  # Assuming this is defined elsewhere in your code
                            save_version_info_to_bucket(version_id, comment, reservations)
                        else:
                            version_id = str(uuid.uuid4())
                            comment = click.prompt("Enter a comment for this version")
                            save_version_info_locally(version_id, comment, reservations)  # Assuming this is defined elsewhere in your code

                except ClientError as e:
                    click.echo(click.style(f"Failed to create and configure instances: {e}", fg="red"))

            # S3 bucket creation
            if 'resources' in data and 's3_buckets' in data['resources']:
                try:
                    for bucket in data['resources']['s3_buckets']:
                        create_s3_bucket(
                            bucket_name=bucket['bucket_name'],
                            region=bucket.get('region'),  # Pass the region if provided, otherwise None
                            public_access_block=bucket.get('public_access_block', True),
                            versioning=bucket.get('versioning', False),
                            lifecycle_rules=bucket.get('lifecycle_rules', []),
                            logging=bucket.get('logging', None),
                            encryption=bucket.get('encryption', None)
                        )
                        click.echo(f"S3 Bucket '{bucket['bucket_name']}' created successfully.")
                except ClientError as e:
                    click.echo(click.style(f"Failed to create S3 bucket: {e}", fg="red"))

            # Remote server and task execution
                    # Remote server section
        if 'remote-server' in data:
            for server in data['remote-server']:
                task_identifier = server.get('identifiers', 'N/A')
                table_data.append([click.style("+", fg="blue"), "Remote Server", task_identifier])
                task_user = server.get('username', None)
                table_data.append([click.style("+", fg="blue"), "Username", task_user if task_user else "N/A"])

        # Task execution section
        if 'tasks' in data:
            for task in data['tasks']:
                task_name = task.get('name', 'Unnamed Task')
                action = task['action']
                task_identifier = task.get('identifiers', 'ALL')
                task_command = task.get('command', None)
                package = task.get('package', None)
                service = task.get('service', None)

                target_identifiers = [task_identifier]
                if task_identifier.lower() == 'all':
                    target_identifiers = [server.get('identifiers') for server in data['remote-server']]

                for identifier in target_identifiers:
                    task_user = username

                    # Find the user for the given identifier if not provided via CLI
                    if not task_user:
                        for server in data['remote-server']:
                            if server.get('identifiers') == identifier:
                                task_user = server.get('username')
                                break

                    if not task_user:
                        click.echo(click.style(f"User not found for identifier '{identifier}'.", fg="red"))
                        continue

                    try:
                        private_ip, _ = get_host_entry(identifier)

                        if action == 'RUN' and task_command:
                            success, message = execute_command_on_server(private_ip, task_user, task_command)
                        elif action == 'COPY':
                            success, message = execute_command_on_server(private_ip, task_user, f"cp {task['src']} {task['dest']}")
                        elif action == 'DOWNLOAD':
                            success, message = execute_command_on_server(private_ip, task_user, f"wget {task['url']} -O {task['dest']}")
                        elif action == 'CREATE':
                            success, message = execute_command_on_server(private_ip, task_user, f"mkdir -p {task['path']}")
                        elif action == 'MOVE':
                            success, message = execute_command_on_server(private_ip, task_user, f"mv {task['src']} {task['dest']}")
                        elif action == 'DELETE':
                            success, message = execute_command_on_server(private_ip, task_user, f"rm -rf {task['path']}")
                        elif action == 'LINK':
                            success, message = execute_command_on_server(private_ip, task_user, f"xdg-open {task['url']}")
                        elif action == 'ATTACH':
                            success, message = execute_command_on_server(private_ip, task_user, f"aws ec2 attach-volume --volume-id {task['volume_id']} --instance-id {task['instance_id']}")
                        elif action == 'DETACH':
                            success, message = execute_command_on_server(private_ip, task_user, f"aws ec2 detach-volume --volume-id {task['volume_id']} --instance-id {task['instance_id']}")
                        elif action == 'INSTALL' and package:
                            success, message = execute_command_on_server(private_ip, task_user, f"apt-get install -y {package}")
                        elif action == 'START_SERVICE' and service:
                            success, message = execute_command_on_server(private_ip, task_user, f"systemctl start {service}")
                        elif action == 'STOP_SERVICE' and service:
                            success, message = execute_command_on_server(private_ip, task_user, f"systemctl stop {service}")
                        elif action == 'CHECK_SERVICE' and service:
                            success, message = execute_command_on_server(private_ip, task_user, f"systemctl status {service}")
                        else:
                            click.echo(f"Unknown action: {action}")
                            success = False
                            message = ""

                        if success:
                            click.echo(f"Task {task_name} on {identifier} ({private_ip}) was successful:\n{message}")
                        else:
                            click.echo(f"Failed to execute task {task_name} on {identifier} ({private_ip}): {message}")
                    except ValueError as ve:
                        click.echo(str(ve))

            # (Assuming you will implement these sections or they are implemented elsewhere in your code)

        # Direct command execution
        try:
            private_ip, _ = get_host_entry(identifier)  # Assuming this is defined elsewhere in your code
            click.echo(f"Attempting to execute command on {identifier} with IP {private_ip}")
            success, message = execute_command_on_server(private_ip, username, command)  # Assuming this is defined elsewhere in your code
            if success:
                click.echo(f"Command execution on {identifier} ({private_ip}) was successful:\n{message}")
            else:
                click.echo(f"Failed to execute command on {identifier} ({private_ip}): {message}")
        except ValueError as ve:
            click.echo(str(ve))

    else:
        click.echo("You must provide either a YAML screenplay file or the identifier, username, and command directly.")

def create_s3_bucket(bucket_name, region=None, public_access_block=True, versioning=False, lifecycle_rules=None, logging=None, encryption=None):
    try:
        credentials = load_aws_credentials()
        s3 = boto3.client('s3', region_name=region, aws_access_key_id=credentials['aws_access_key_id'], aws_secret_access_key=credentials['aws_secret_access_key'])

        print(f"Creating S3 bucket '{bucket_name}' in region '{region or 'us-east-1'}'")
        create_bucket_params = {'Bucket': bucket_name}

        # Only add the region configuration if a region is specified and it is not us-east-1
        if region and region != 'us-east-1':
            create_bucket_params['CreateBucketConfiguration'] = {'LocationConstraint': region}

        s3.create_bucket(**create_bucket_params)

        # Additional settings and confirmations
        if public_access_block:
            s3.put_public_access_block(
                Bucket=bucket_name,
                PublicAccessBlockConfiguration={
                    'BlockPublicAcls': True,
                    'IgnorePublicAcls': True,
                    'BlockPublicPolicy': True,
                    'RestrictPublicBuckets': True
                }
            )

        if versioning:
            s3.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration={'Status': 'Enabled'}
            )

        if lifecycle_rules:
            s3.put_bucket_lifecycle_configuration(
                Bucket=bucket_name,
                LifecycleConfiguration={'Rules': lifecycle_rules}
            )

        if logging:
            s3.put_bucket_logging(
                Bucket=bucket_name,
                BucketLoggingStatus={'LoggingEnabled': {'TargetBucket': logging['target_bucket'], 'TargetPrefix': logging['target_prefix']}}
            )

        if encryption:
            s3.put_bucket_encryption(
                Bucket=bucket_name,
                ServerSideEncryptionConfiguration={'Rules': [{'ApplyServerSideEncryptionByDefault': {'SSEAlgorithm': encryption['sse_algorithm']}}]}
            )

        click.echo(f"S3 Bucket '{bucket_name}' created successfully.")

    except ClientError as e:
        click.echo(click.style(f"An error occurred: {e}", fg="red"))
    except NoCredentialsError as e:
        click.echo(click.style(f"AWS credentials error: {e}", fg="red"))
    except Exception as e:
        click.echo(click.style(f"An unexpected error occurred: {e}", fg="red"))

def install_package_on_server(ip, username, package):
    command = f"DEBIAN_FRONTEND=noninteractive apt-get install -y {package}"
    return execute_command_on_server(ip, username, command)

# Example Functions

# Helper functions for evaluating conditions, loops, and executing tasks
def eval_condition(condition):
    # Implement the logic to evaluate the condition
    pass

def execute_task(task, loop_item=None):
    # Implement the logic to execute tasks, handling loops and conditions
    pass

def create_vpc(vpc_data):
    ec2 = boto3.client('ec2')
    response = ec2.create_vpc(
        CidrBlock=vpc_data['cidr_block'],
        AmazonProvidedIpv6CidrBlock=False,
        DryRun=False,
        InstanceTenancy='default'
    )
    vpc_id = response['Vpc']['VpcId']
    ec2.create_tags(Resources=[vpc_id], Tags=vpc_data.get('tags', []))
    return vpc_id

def create_subnet(vpc_id, subnet_data):
    ec2 = boto3.client('ec2')
    response = ec2.create_subnet(
        VpcId=vpc_id,
        CidrBlock=subnet_data['cidr_block'],
        AvailabilityZone=subnet_data['availability_zone']
    )
    subnet_id = response['Subnet']['SubnetId']
    ec2.create_tags(Resources=[subnet_id], Tags=subnet_data.get('tags', []))
    return subnet_id

def create_security_group(vpc_id, sg_data):
    ec2 = boto3.client('ec2')
    response = ec2.create_security_group(
        VpcId=vpc_id,
        GroupName=sg_data['name'],
        Description=sg_data['description']
    )
    sg_id = response['GroupId']
    ec2.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                'IpProtocol': rule['protocol'],
                'FromPort': int(rule['port_range'].split('-')[0]),
                'ToPort': int(rule['port_range'].split('-')[1]),
                'IpRanges': [{'CidrIp': rule['cidr_blocks']}]
            } for rule in sg_data['inbound_rules']
        ]
    )
    ec2.create_tags(Resources=[sg_id], Tags=sg_data.get('tags', []))
    return sg_id

def create_internet_gateway(vpc_id, igw_data):
    ec2 = boto3.client('ec2')
    response = ec2.create_internet_gateway()
    igw_id = response['InternetGateway']['InternetGatewayId']
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ec2.create_tags(Resources=[igw_id], Tags=igw_data.get('tags', []))
    return igw_id

def create_route_table(vpc_id, igw_id, rt_data):
    ec2 = boto3.client('ec2')
    response = ec2.create_route_table(VpcId=vpc_id)
    route_table_id = response['RouteTable']['RouteTableId']
    ec2.create_route(
        RouteTableId=route_table_id,
        DestinationCidrBlock='0.0.0.0/0',
        GatewayId=igw_id
    )
    for assoc in rt_data.get('associations', []):
        ec2.associate_route_table(SubnetId=assoc['subnet_name'], RouteTableId=route_table_id)
    ec2.create_tags(Resources=[route_table_id], Tags=rt_data.get('tags', []))
    return route_table_id

def handle_commands(commands):
    for cmd in commands:
        identifiers = [id.strip() for id in cmd['identifiers'].split(',')]
        user = cmd['username']
        cmd_to_run = cmd['command']

        for identifier in identifiers:
            try:
                private_ip, _ = get_host_entry(identifier)
                success, message = execute_command_on_server(private_ip, user, cmd_to_run)
                if success:
                    click.echo(f"Command execution on {identifier} ({private_ip}) was successful:\n{message}")
                else:
                    click.echo(f"Failed to execute command on {identifier} ({private_ip}): {message}")
            except ValueError as ve:
                click.echo(str(ve))

def execute_command_on_server(hostname, username, command):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, username=username)

        stdin, stdout, stderr = client.exec_command(command)
        stdout.channel.recv_exit_status()

        output = stdout.read().decode()
        error = stderr.read().decode()

        client.close()

        if error:
            return False, error
        else:
            return True, output

    except Exception as e:
        return False, str(e)

def execute_and_print(identifier, username, command):
    try:
        private_ip, _ = get_host_entry(identifier)
        success, message = execute_command_on_server(private_ip, username, command)
        if success:
            click.echo(f"Command execution on {identifier} ({private_ip}) was successful:\n{message}")
        else:
            click.echo(f"Failed to execute command on {identifier} ({private_ip}): {message}")
    except ValueError as ve:
        click.echo(str(ve))

def get_all_environments():
    environments = set()
    with open('/etc/hosts', 'r') as f:
        for line in f:
            match = re.match(r'\[(.+)\]', line)
            if match:
                environments.add(match.group(1))
    return list(environments)

def get_hosts_from_environment(environment):
    hosts = []
    in_environment = False
    with open('/etc/hosts', 'r') as f:
        for line in f:
            if re.match(r'\[' + re.escape(environment) + r'\]', line):
                in_environment = True
            elif re.match(r'\[.+\]', line):
                in_environment = False
            elif in_environment and line.strip():
                parts = line.split()
                if len(parts) >= 2:
                    ip, name = parts[:2]
                    hosts.append({'name': name, 'ip': ip})
    return hosts

def get_host_entry(identifier):
    if identifier is None:
        raise ValueError("Identifier is not set. Please provide a valid identifier.")

    with open('/etc/hosts', 'r') as f:
        for line in f:
            if identifier in line:
                parts = line.split()
                if len(parts) >= 2:
                    return parts[0], {}

    raise ValueError(f"Unknown identifier: {identifier}. Please check that the identifier is correct and exists in /etc/hosts.")

def execute_commands(commands):
    for cmd in commands:
        identifiers = [id.strip() for id in cmd['identifiers'].split(',')]
        environments = [env.strip() for env in cmd.get('Environment', 'ALL').split(',')]
        user = cmd['username']
        cmd_to_run = cmd['command']

        if 'ALL' in environments:
            environments = get_all_environments()

        for env in environments:
            hosts = get_hosts_from_environment(env)
            for identifier in identifiers:
                if identifier == 'ALL':
                    for host in hosts:
                        execute_and_print(host['name'], user, cmd_to_run)
                else:
                    host = next((host for host in hosts if host['name'] == identifier), None)
                    if host:
                        execute_and_print(host['name'], user, cmd_to_run)

def set_cron_job(hostname, username, cron_expression, command):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(hostname, username=username)

        cron_command = f'(crontab -l 2>/dev/null; echo "{cron_expression} {command}") | crontab -'
        stdin, stdout, stderr = client.exec_command(cron_command)
        stdout.channel.recv_exit_status()

        output = stdout.read().decode()
        error = stderr.read().decode()

        client.close()

        if error:
            raise Exception(error)
        else:
            return True, output

    except Exception as e:
        return False, str(e)

def load_variables():
    if os.path.exists(VARIABLES_FILE):
        with open(VARIABLES_FILE, 'r') as file:
            return yaml.safe_load(file)
    else:
        return {}

def resolve_variables(data, variables):
    if isinstance(data, dict):
        return {k: resolve_variables(v, variables) for k, v in data.items()}
    elif isinstance(data, list):
        return [resolve_variables(item, variables) for item in data]
    elif isinstance(data, str):
        # Only replace variables that match the pattern ${ver.variable_name}
        for key, value in variables.items():
            placeholder = "${ver." + key + "}"
            if placeholder in data:
                if value['type'] == 'str':
                    data = data.replace(placeholder, value['value'])
                elif value['type'] == 'list':
                    # Convert the list to a string that can be used in the context (e.g., comma-separated)
                    data = data.replace(placeholder, ','.join(value['value']))
        return data
    else:
        return data

if __name__ == '__main__':
    cli()
