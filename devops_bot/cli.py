import os
import shutil
import json
import requests
import boto3
import click
import psutil
import uuid
import uuid
import time
import secrets
import threading
from getpass import getpass
from datetime import datetime
from tabulate import tabulate
from cryptography.fernet import Fernet
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from base64 import urlsafe_b64encode, urlsafe_b64decode  # Corrected import
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError


cli = click.Group()

# Click group definition
@click.group()
def cli():
    """DevOps Bot CLI."""
    pass

API_BASE_URL = "https://devopsbot-testserver.online"

JENKINS_KEY_FILE = 'jenkins_key.key'
JENKINS_CREDENTIALS_BUCKET = 'jenkins-credentials.dob'
JENKINS_CREDENTIALS_FILE = 'jenkins_credentials.enc'
BASE_DIR = os.path.expanduser("~/.etc/devops-bot")
VERSION_BUCKET_NAME = "devops-bot-version-bucket"
VERSION_DIR = os.path.join(BASE_DIR, "version")
KEY_FILE = os.path.join(BASE_DIR, "key.key")
MASTER_INFO_FILE = os.path.join(BASE_DIR, "master_info.json")
AWS_CREDENTIALS_FILE = os.path.join(BASE_DIR, "aws_credentials.json")
DEVOPS_BOT_TOKEN_FILE = os.path.join(BASE_DIR, "devops_bot_token")
DOB_SCREENPLAY_FILE = os.path.join(BASE_DIR, "dob_screenplay.yaml")
MASTER_INFO_FILE = os.path.expanduser("~/.devops_master_info")

# Initialize Flask app
app = Flask(__name__)


@cli.command(name="configure-aws", help="Configure AWS credentials.")
@click.option('--aws_access_key_id', required=True, help="AWS Access Key ID")
@click.option('--aws_secret_access_key', required=True, help="AWS Secret Access Key")
@click.option('--region', required=True, help="AWS Region")
def configure_aws(aws_access_key_id, aws_secret_access_key, region):
    save_aws_credentials(aws_access_key_id, aws_secret_access_key, region)
    click.echo("AWS credentials configured successfully.")           

# Ensure user folder
def ensure_user_folder():
    if not os.path.exists(BASE_DIR):
        os.makedirs(BASE_DIR, mode=0o700, exist_ok=True)

#ensure private folder
def ensure_private_folder():
    """Ensure the private folder for storing master info exists with restricted permissions."""
    private_folder = os.path.dirname(MASTER_INFO_FILE)
    if not os.path.exists(private_folder):
        os.makedirs(private_folder, mode=0o700, exist_ok=True)  # rwx------ permissions

# Ensure version folder
def ensure_version_folder():
    if not os.path.exists(VERSION_DIR):
        os.makedirs(VERSION_DIR, mode=0o700, exist_ok=True)


@click.group()
def vault():
    """Manage the vault for sensitive information."""
    pass

# Vault utility functions
def ensure_vault_folder():
    if not os.path.exists(VAULT_FOLDER):
        os.makedirs(VAULT_FOLDER, mode=0o700)

def get_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return urlsafe_b64encode(kdf.derive(password.encode()))

def save_config(config):
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config, f)

def load_config():
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    return None

def setup_vault(password):
    ensure_vault_folder()
    salt = os.urandom(16)
    key = get_key(password, salt)
    config = {
        "salt": urlsafe_b64encode(salt).decode('utf-8')
    }
    save_config(config)
    print("Vault has been set up.")

def generate_token():
    return secrets.token_urlsafe(32)

def save_token(token):
    with open(TOKEN_FILE, 'w') as f:
        f.write(token)
    os.chmod(TOKEN_FILE, 0o600)  # rw-------

def load_token():
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'r') as f:
            return f.read().strip()
    return None

def encrypt_file(filepath, key):
    fernet = Fernet(key)
    with open(filepath, "rb") as file:
        original = file.read()
    encrypted = fernet.encrypt(original)
    with open(filepath, "wb") as encrypted_file:
        encrypted_file.write(encrypted)

def decrypt_file(filepath, key):
    fernet = Fernet(key)
    with open(filepath, "rb") as encrypted_file:
        encrypted = encrypted_file.read()
    decrypted = fernet.decrypt(encrypted)
    with open(filepath, "wb") as decrypted_file:
        decrypted_file.write(decrypted)

def move_to_vault(file_path, key):
    ensure_vault_folder()
    if not os.path.exists(file_path):
        print(f"File {file_path} does not exist.")
        return
    destination = os.path.join(VAULT_FOLDER, os.path.basename(file_path))
    shutil.move(file_path, destination)
    encrypt_file(destination, key)
    print(f"Moved and encrypted {file_path} to the vault.")

def pull_from_vault(file_name, key):
    file_path = os.path.join(VAULT_FOLDER, file_name)
    if not os.path.exists(file_path):
        print(f"File {file_name} does not exist in the vault.")
        return
    decrypt_file(file_path, key)
    shutil.move(file_path, os.getcwd())
    print(f"Decrypted and moved {file_name} to the current directory.")

def show_files():
    ensure_vault_folder()
    files = [f for f in os.listdir(VAULT_FOLDER) if f != "config.json"]
    if files:
        print("Files in the vault:")
        for file in files:
            print(f" - {file}")
    else:
        print("The vault is empty.")



@vault.command(name="setup", help="Setup the vault for sensitive information.")
def setup_cmd():
    if os.path.exists(CONFIG_FILE):
        print("Vault is already set up. Please use 'vault-config' to configure the vault.")
        return

    password = getpass("Password: ")
    confirm_password = getpass("Repeat for confirmation: ")
    if password != confirm_password:
        print("Passwords do not match. Please try again.")
        return

    setup_vault(password)
    token = generate_token()
    save_token(token)
    click.echo(f"Vault has been set up. Please save this token securely: {token}")

@vault.command(name="config", help="Configure the vault with password and token.")
def config_cmd():
    if not os.path.exists(CONFIG_FILE):
        print("Vault is not set up. Please use 'vault-setup' to set up the vault first.")
        return

    password = getpass("Password: ")
    token = getpass("Token: ")
    saved_token = load_token()

    if token != saved_token:
        print("Invalid token.")
        return

    salt = urlsafe_b64decode(load_config()["salt"].encode('utf-8'))
    key = get_key(password, salt)
    click.echo("Vault configured successfully.")

@vault.command(name="move", help="Move a file to the vault and encrypt it.")
@click.argument('file_path')
def move_cmd(file_path):
    config = load_config()
    if not config:
        print("Vault is not set up.")
        return

    salt = urlsafe_b64decode(config["salt"].encode('utf-8'))
    password = getpass("Password: ")
    token = getpass("Token: ")
    saved_token = load_token()

    if token != saved_token:
        print("Invalid token.")
        return

    key = get_key(password, salt)
    move_to_vault(file_path, key)

@vault.command(name="pull", help="Pull a file from the vault and decrypt it.")
@click.argument('file_name')
def pull_cmd(file_name):
    config = load_config()
    if not config:
        print("Vault is not set up.")
        return

    salt = urlsafe_b64decode(config["salt"].encode('utf-8'))
    password = getpass("Password: ")
    token = getpass("Token: ")
    saved_token = load_token()

    if token != saved_token:
        print("Invalid token.")
        return

    key = get_key(password, salt)
    pull_from_vault(file_name, key)

@vault.command(name="show", help="Show files in the vault.")
def show_cmd():
    show_files()

@vault.command(name="encrypt", help="Encrypt a file.")
@click.argument('file_path')
def encrypt_cmd(file_path):
    config = load_config()
    if not config:
        print("Vault is not set up.")
        return

    salt = urlsafe_b64decode(config["salt"].encode('utf-8'))
    password = getpass("Password: ")
    key = get_key(password, salt)
    encrypt_file(file_path, key)
    print(f"File {file_path} has been encrypted.")

@vault.command(name="decrypt", help="Decrypt a file.")
@click.argument('file_path')
def decrypt_cmd(file_path):
    config = load_config()
    if not config:
        print("Vault is not set up.")
        return

    salt = urlsafe_b64decode(config["salt"].encode('utf-8'))
    password = getpass("Password: ")
    key = get_key(password, salt)
    decrypt_file(file_path, key)
    print(f"File {file_path} has been decrypted.")

#jenkins information

def generate_jenkins_key():
    key = Fernet.generate_key()
    with open(JENKINS_KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    click.echo("Jenkins encryption key generated and saved.")

def load_jenkins_key():
    return open(JENKINS_KEY_FILE, 'rb').read()

def encrypt_jenkins_data(data, key):
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data.encode())
    return encrypted

def decrypt_jenkins_data(encrypted_data, key):
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_data).decode()
    return decrypted

def save_jenkins_credentials_to_s3(url, job_name, username, api_token):
    ensure_user_folder()
    if not os.path.exists(JENKINS_KEY_FILE):
        generate_jenkins_key()
    key = load_jenkins_key()

    credentials = {
        'jenkins_url': url,
        'job_name': job_name,
        'username': username,
        'api_token': api_token
    }

    encrypted_credentials = encrypt_jenkins_data(json.dumps(credentials), key)

    try:
        credentials = load_aws_credentials()
        s3 = boto3.client('s3', **credentials)
        s3.create_bucket(Bucket=JENKINS_CREDENTIALS_BUCKET)
        s3.put_object(Bucket=JENKINS_CREDENTIALS_BUCKET, Key=JENKINS_CREDENTIALS_FILE, Body=encrypted_credentials)
        click.echo(f"Jenkins credentials saved to S3 bucket {JENKINS_CREDENTIALS_BUCKET}.")
    except (NoCredentialsError, PartialCredentialsError) as e:
        click.echo(f"Error with AWS credentials: {e}")
    except ClientError as e:
        click.echo(f"Error saving credentials to S3: {e}")


@cli.command(name="configure-jenkins", help="Configure Jenkins credentials and save them to S3.")
@click.option('--jenkins_url', required=True, help="Jenkins URL")
@click.option('--job_name', required=True, help="Jenkins Job Name")
@click.option('--username', required=True, help="Jenkins Username")
@click.option('--api_token', required=True, hide_input=True, help="Jenkins API Token")
def configure_jenkins(jenkins_url, job_name, username, api_token):
    save_jenkins_credentials_to_s3(jenkins_url, job_name, username, api_token)


def ensure_private_folder():
    """Ensure the private folder for storing master info exists with restricted permissions."""
    private_folder = os.path.dirname(MASTER_INFO_FILE)
    if not os.path.exists(private_folder):
        os.makedirs(private_folder, mode=0o700, exist_ok=True)  # rwx------ permissions


# Ensure user folder
def ensure_user_folder():
    if not os.path.exists(BASE_DIR):
        os.makedirs(BASE_DIR, mode=0o700, exist_ok=True)

# Ensure version folder
def ensure_version_folder():
    if not os.path.exists(VERSION_DIR):
        os.makedirs(VERSION_DIR, mode=0o700, exist_ok=True)

# Generate encryption key
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as key_file:
        key_file.write(key)
    click.echo("Encryption key generated and saved.")

# Load encryption key
def load_key():
    return open(KEY_FILE, 'rb').read()

# Encrypt data
def encrypt_data(data, key):
    fernet = Fernet(key)
    encrypted = fernet.encrypt(data.encode())
    return encrypted

# Decrypt data
def decrypt_data(encrypted_data, key):
    fernet = Fernet(key)
    decrypted = fernet.decrypt(encrypted_data).decode()
    return decrypted

# Save AWS credentials encrypted
def save_aws_credentials(access_key, secret_key, region):
    ensure_user_folder()
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

def check_bucket_exists(bucket_name):
    try:
        credentials = load_aws_credentials()
        s3 = boto3.client('s3', **credentials)
        s3.head_bucket(Bucket=bucket_name)
        return True
    except ClientError:
        return False

# Load AWS credentials and decrypt them
def load_aws_credentials():
    credentials = None
    try:
        if os.path.exists(AWS_CREDENTIALS_FILE):
            key = load_key()
            with open(AWS_CREDENTIALS_FILE, 'rb') as cred_file:
                encrypted_credentials = cred_file.read()
            decrypted_credentials = decrypt_data(encrypted_credentials, key)
            credentials = json.loads(decrypted_credentials)
    except FileNotFoundError:
        pass
    return credentials


# Save master info
def save_master_info(instance_id, public_ip, security_group, key_pair):
    ensure_user_folder()
    master_info = {
        'instance_id': instance_id,
        'public_ip': public_ip,
        'security_group': security_group,
        'key_pair': key_pair
    }
    with open(MASTER_INFO_FILE, 'w') as f:
        json.dump(master_info, f)
    os.chmod(MASTER_INFO_FILE, 0o600)

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
    try:
        with open(MASTER_INFO_FILE, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return None

def load_aws_credentials():
    try:
        with open(AWS_CREDENTIALS_FILE, 'r') as cred_file:
            return json.load(cred_file)
    except FileNotFoundError:
        return None

def save_token(token):
    ensure_user_folder()
    with open(DEVOPS_BOT_TOKEN_FILE, 'w') as token_file:
        token_file.write(token)
    os.chmod(DEVOPS_BOT_TOKEN_FILE, 0o600)

def load_token():
    try:
        with open(DEVOPS_BOT_TOKEN_FILE, 'r') as token_file:
            return token_file.read().strip()
    except FileNotFoundError:
        return None

def save_aws_credentials(access_key, secret_key, region):
    ensure_user_folder()
    credentials = {
        'aws_access_key_id': access_key,
        'aws_secret_access_key': secret_key,
        'region_name': region
    }
    with open(AWS_CREDENTIALS_FILE, 'w') as cred_file:
        json.dump(credentials, cred_file)
    os.chmod(AWS_CREDENTIALS_FILE, 0o600)



@cli.command(help="Greet the user.")
def greet():
    click.echo("Hello from DevOps Bot!")

@cli.command(help="Show version information.")
def version():
    click.echo("devops-bot, version 0.1")


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

# Delete instance
@cli.command(name="delete-ec2", help="Delete EC2 instances using instance IDs or a version ID.")
@click.argument('ids', nargs=-1)
@click.option('--version-id', help="Version ID to delete instances from")
def delete_ec2(ids, version_id):
    instance_ids = list(ids)

    if version_id:
        version_info = load_version_info(version_id)
        if not version_info:
            click.echo("No version information found.")
            return
        instance_ids.extend(instance['InstanceId'] for instance in version_info['content'])

    if not instance_ids:
        click.echo("No instance IDs provided.")
        return

    table_data = [
        [click.style("-", fg="red"), "Instance ID", instance_id] for instance_id in instance_ids
    ]
    click.echo(click.style("\nStaging area: Deleting EC2 instance(s) with IDs:", fg="red"))
    click.echo(tabulate(table_data, headers=["", "Attribute", "Value"], tablefmt="grid"))

    if click.confirm(click.style("Do you want to proceed with deleting the instance(s)?", fg="red"), default=False):
        comment = click.prompt(click.style("Enter a comment for this version", fg="red"))
        version_id = str(uuid.uuid4())  # Generate a unique version ID

        try:
            terminated_instances = delete_ec2_instances(instance_ids)
            if terminated_instances is None:
                raise Exception("Instance deletion failed. Aborting operation.")

            click.echo(click.style("Instances deleted successfully.", fg="green"))
            for idx, instance in enumerate(terminated_instances):
                click.echo(click.style(f"Instance {idx+1}: ID = {instance['InstanceId']} - {instance['CurrentState']['Name']}", fg="green"))

            version_content = [{'InstanceId': instance['InstanceId'], 'CurrentState': instance['CurrentState']} for instance in terminated_instances]

            if check_bucket_exists(VERSION_BUCKET_NAME):
                save_version_info_to_bucket(version_id, comment, version_content)
            else:
                if click.confirm("Do you want to save the version information in a bucket?", default=False):
                    create_version_bucket()
                    save_version_info_to_bucket(version_id, comment, version_content)
                else:
                    save_version_info_locally(version_id, comment, version_content)
        except Exception as e:
            click.echo(click.style(f"Failed to delete instances: {e}", fg="red"))
    else:
        click.echo(click.style("Instance deletion aborted.", fg="yellow"))

# Utility function for deleting EC2 instances
def delete_ec2_instances(instance_ids):
    credentials = load_aws_credentials()
    if not credentials:
        click.echo("No AWS credentials found. Please configure them first.")
        return None

    ec2 = boto3.client('ec2', **credentials)
    try:
        response = ec2.terminate_instances(InstanceIds=instance_ids)
        return response['TerminatingInstances']
    except ClientError as e:
        click.echo(click.style(f"Failed to delete instances: {e}", fg="red"))
        return None

# Assuming utility functions for encryption, AWS credential loading, version saving/loading are present

def save_version_info_locally(version_id, comment, content):
    ensure_version_folder()
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
        s3.put_object(Bucket=VERSION_BUCKET_NAME, Key=f"{version_id}.enc", Body=encrypted_version_info)
        click.echo(f"Version information saved in S3 bucket with ID {version_id}.")
    except ClientError as e:
        click.echo(click.style(f"Failed to save version information to bucket: {e}", fg="red"))

def create_ec2_instances(instance_type, ami_id, key_name, security_group, count, tags, user_data=None):
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



def list_ec2_instances_to_file():
    credentials = load_aws_credentials()
    ec2 = boto3.client('ec2', **credentials)
    try:
        response = ec2.describe_instances()
        instances = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                instance_type = instance['InstanceType']
                key_name = instance.get('KeyName', '-')
                security_groups = ', '.join([sg['GroupId'] for sg in instance.get('SecurityGroups', [])])
                state = instance['State']['Name']
                state_symbol = {
                    'running': click.style('+', fg='green'),
                    'stopped': click.style('+', fg='red'),
                    'terminated': click.style('+', fg='yellow')
                }.get(state, state)
                launch_time = instance['LaunchTime'].strftime('%Y-%m-%d %H:%M:%S')
                tags = ', '.join([f"{tag['Key']}={tag['Value']}" for tag in instance.get('Tags', [])])
                public_ip = instance.get('PublicIpAddress', 'N/A')
                instances.append({
                    "State": state_symbol,
                    "Instance ID": instance_id,
                    "Instance Type": instance_type,
                    "Key Name": key_name,
                    "Security Groups": security_groups,
                    "Launch Time": launch_time,
                    "Tags": tags,
                    "Public IP": public_ip
                })

        with open('ec2_instances.json', 'w') as file:
            json.dump(instances, file)
        click.echo("EC2 instances information updated.")
    except ClientError as e:
        click.echo(click.style(f"Failed to list instances: {e}", fg="red"))


@cli.command(name="create-ec2", help="Create EC2 instances with specified options.")
@click.option('--instance-type', required=True, help="EC2 instance type")
@click.option('--ami-id', required=True, help="AMI ID")
@click.option('--key-name', required=True, help="Key pair name")
@click.option('--security-group', required=True, help="Security group ID")
@click.option('--count', default=1, help="Number of instances to create")
@click.option('--tags', multiple=True, type=(str, str), help="Tags for the instance in key=value format", required=False)
def create_ec2(instance_type, ami_id, key_name, security_group, count, tags):
    tags_dict = dict(tags)
    table_data = [
        [click.style("+", fg="green"), "Instance Type", instance_type],
        [click.style("+", fg="green"), "AMI ID", ami_id],
        [click.style("+", fg="green"), "Key Name", key_name],
        [click.style("+", fg="green"), "Security Group", security_group],
        [click.style("+", fg="green"), "Count", count],
        [click.style("+", fg="green"), "Tags", tags_dict]
    ]
    click.echo(click.style("\nStaging area: Creating EC2 instance(s) with the following configuration:\n", fg="green"))
    click.echo(tabulate(table_data, headers=["", "Attribute", "Value"], tablefmt="grid"))

    if click.confirm(click.style("Do you want to proceed with creating the instance(s)?", fg="green"), default=True):
        version_id = str(uuid.uuid4())  # Generate a unique version ID
        comment = click.prompt(click.style("Enter a comment for this version", fg="green"))

        try:
            instances = create_ec2_instances(instance_type, ami_id, key_name, security_group, count, tags_dict)
            if instances is None:
                raise Exception("Instance creation failed. Aborting operation.")

            click.echo(click.style("Instances created successfully.", fg="green"))
            for idx, instance in enumerate(instances):
                click.echo(click.style(f"Instance {idx+1}: ID = {instance['InstanceId']}", fg="green"))

            version_content = [{'InstanceId': instance['InstanceId'], 'InstanceType': instance['InstanceType'], 'ImageId': instance['ImageId'], 'KeyName': instance['KeyName'], 'SecurityGroups': instance['SecurityGroups'], 'Tags': instance.get('Tags', [])} for instance in instances]

            if check_bucket_exists(VERSION_BUCKET_NAME):
                save_version_info_to_bucket(version_id, comment, version_content)
            else:
                if click.confirm("Do you want to save the version information in a bucket?", default=False):
                    create_version_bucket()
                    save_version_info_to_bucket(version_id, comment, version_content)
                else:
                    save_version_info_locally(version_id, comment, version_content)
        except Exception as e:
            click.echo(click.style(f"Failed to create instances: {e}", fg="red"))
    else:
        click.echo(click.style("Instance creation aborted.", fg="yellow"))

def load_version_info(version_id):
    key = load_key()
    if os.path.exists(os.path.join(VERSION_DIR, f"{version_id}.enc")):
        with open(os.path.join(VERSION_DIR, f"{version_id}.enc"), 'rb') as version_file:
            encrypted_version_info = version_file.read()
        decrypted_version_info = decrypt_data(encrypted_version_info, key)
        return json.loads(decrypted_version_info)
    else:
        try:
            credentials = load_aws_credentials()
            s3 = boto3.client('s3', **credentials)
            response = s3.get_object(Bucket=VERSION_BUCKET_NAME, Key=f"{version_id}.enc")
            encrypted_version_info = response['Body'].read()
            decrypted_version_info = decrypt_data(encrypted_version_info, key)
            return json.loads(decrypted_version_info)
        except ClientError as e:
            click.echo(click.style(f"No version information found for ID {version_id}.", fg="red"))
            return None

@cli.command(name="recreate-ec2", help="Recreate EC2 instances using a version ID.")
@click.option('--version-id', required=True, help="Version ID to recreate instances from")
def recreate_ec2(version_id):
    version_info = load_version_info(version_id)
    if not version_info:
        click.echo("No version information found.")
        return

    instances_to_recreate = version_info['content']

    click.echo(click.style(f"\nStaging area: Recreating EC2 instance(s):", fg="green"))
    table_data = []
    for idx, instance in enumerate(instances_to_recreate):
        table_data.append([click.style("+", fg="green"), "Instance Type", instance.get('InstanceType', 'Unknown')])
        table_data.append([click.style("+", fg="green"), "AMI ID", instance.get('ImageId', 'Unknown')])
        table_data.append([click.style("+", fg="green"), "Key Name", instance.get('KeyName', 'Unknown')])
        security_groups = instance.get('SecurityGroups', [])
        security_group_ids = [sg['GroupId'] for sg in security_groups] if security_groups else None
        table_data.append([click.style("+", fg="green"), "Security Group", security_group_ids if security_group_ids else 'None'])
        table_data.append([click.style("+", fg="green"), "Tags", instance.get('Tags', [])])
    click.echo(tabulate(table_data, headers=["", "Attribute", "Value"], tablefmt="grid"))

    if click.confirm(click.style("Do you want to proceed with recreating the instance(s)?", fg="green"), default=True):
        new_version_id = str(uuid.uuid4())
        comment = click.prompt(click.style("Enter a new comment for this version", fg="green"))

        try:
            recreated_instances = []
            for instance in instances_to_recreate:
                created_instances = create_ec2_instances(
                    instance_type=instance.get('InstanceType', 'Unknown'),
                    ami_id=instance.get('ImageId', 'Unknown'),
                    key_name=instance.get('KeyName', 'Unknown'),
                    security_group=security_group_ids[0] if security_group_ids else None,
                    count=1,
                    tags={tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                )
                if created_instances is None:
                    raise Exception("Instance recreation failed. Aborting operation.")
                recreated_instances.extend(created_instances)

            click.echo(click.style("Instances recreated successfully.", fg="green"))
            for idx, instance in enumerate(recreated_instances):
                click.echo(click.style(f"Instance {idx+1}: ID = {instance['InstanceId']}", fg="green"))

            if check_bucket_exists(VERSION_BUCKET_NAME):
                save_version_info_to_bucket(new_version_id, comment, recreated_instances)
            else:
                if click.confirm("Do you want to save the version information in a bucket?", default=False):
                    create_version_bucket()
                    save_version_info_to_bucket(new_version_id, comment, recreated_instances)
                else:
                    save_version_info_locally(new_version_id, comment, recreated_instances)
        except Exception as e:
            click.echo(click.style(f"Failed to recreate instances: {e}", fg="red"))
    else:
        click.echo(click.style("Instance recreation aborted.", fg="yellow"))


def list_versions():
    versions = []
    key = load_key()
    # Check local versions
    for file_name in os.listdir(VERSION_DIR):
        if file_name.endswith(".enc"):
            version_id = file_name.split(".")[0]
            version_info = load_version_info(version_id)
            if version_info:
                timestamp = datetime.fromtimestamp(os.path.getmtime(os.path.join(VERSION_DIR, f"{version_id}.enc"))).strftime('%Y-%m-%d %H:%M:%S')
                instance_count = len(version_info['content'])
                versions.append((version_id, version_info.get('comment', ''), timestamp, instance_count))
    # Check S3 versions
    credentials = load_aws_credentials()
    s3 = boto3.client('s3', **credentials)
    try:
        response = s3.list_objects_v2(Bucket=VERSION_BUCKET_NAME)
        for obj in response.get('Contents', []):
            version_id = obj['Key'].split(".")[0]
            version_info = load_version_info(version_id)
            if version_info:
                timestamp = obj['LastModified'].strftime('%Y-%m-%d %H:%M:%S')
                instance_count = len(version_info['content'])
                versions.append((version_id, version_info.get('comment', ''), timestamp, instance_count))
    except ClientError as e:
        click.echo(click.style(f"Error listing versions in S3: {e}", fg="red"))
    return versions

@cli.command(name="view-version", help="View version information.")
@click.option('-o', '--output', type=click.Choice(['table', 'wide']), default='table', help="Output format")
def view_version(output):
    versions = list_versions()
    if output == 'table':
        table = [[version_id, comment, timestamp, count] for version_id, comment, timestamp, count in versions]
        headers = ["Version ID", "Comment", "Date", "Time", "Count"]
        click.echo(tabulate(table, headers, tablefmt="grid"))
    elif output == 'wide':
        for version_id, comment, timestamp, count in versions:
            version_info = load_version_info(version_id)
            click.echo(click.style(f"Version ID: {version_id}", fg="green"))
            click.echo(click.style(f"Comment: {comment}", fg="green"))
            click.echo(click.style(f"Timestamp: {timestamp}", fg="green"))
            click.echo(click.style(f"Count: {count}", fg="green"))
            click.echo(click.style(json.dumps(version_info['content'], indent=2), fg="green"))
            click.echo("-" * 80)

# List EC2 instances command

# List EC2 instances command
@cli.command(name="list-ec2", help="List EC2 instances in a table format.")
@click.option('--instance-ids', multiple=True, help="Filter by instance IDs")
def list_ec2_instances(instance_ids):
    credentials = load_aws_credentials()
    ec2 = boto3.client('ec2', **credentials)
    try:
        if instance_ids:
            response = ec2.describe_instances(InstanceIds=instance_ids)
        else:
            response = ec2.describe_instances()

        instances = []
        for reservation in response['Reservations']:
            for instance in reservation['Instances']:
                instance_id = instance['InstanceId']
                instance_type = instance['InstanceType']
                key_name = instance.get('KeyName', '-')
                security_groups = ', '.join([sg['GroupId'] for sg in instance.get('SecurityGroups', [])])
                state = instance['State']['Name']
                public_ip = instance.get('PublicIpAddress', 'N/A')
                state_symbol = {
                    'running': click.style('+', fg='green'),
                    'stopped': click.style('-', fg='red'),
                    'terminated': click.style('x', fg='yellow')
                }.get(state, state)
                launch_time = instance['LaunchTime'].strftime('%Y-%m-%d %H:%M:%S')
                tags = ', '.join([f"{tag['Key']}={tag['Value']}" for tag in instance.get('Tags', [])])
                instances.append([
                    state_symbol, instance_id, instance_type, key_name, security_groups,
                    launch_time, tags, public_ip
                ])

        headers = ["State", "Instance ID", "Instance Type", "Key Name", "Security Groups", "Launch Time", "Tags", "Public IP"]
        click.echo(tabulate(instances, headers, tablefmt="grid"))
    except ClientError as e:
        click.echo(click.style(f"Failed to list instances: {e}", fg="red"))


# List S3 buckets command
@cli.command(name="list-s3", help="List S3 buckets in a table format.")
def list_s3_buckets():
    credentials = load_aws_credentials()
    s3 = boto3.client('s3', **credentials)
    try:
        response = s3.list_buckets()
        buckets = []
        for bucket in response['Buckets']:
            bucket_name = bucket['Name']
            creation_date = bucket['CreationDate'].strftime('%Y-%m-%d %H:%M:%S')
            try:
                encryption = s3.get_bucket_encryption(Bucket=bucket_name)
                enc_rules = encryption['ServerSideEncryptionConfiguration']['Rules']
                encryption_status = 'Enabled'
            except ClientError:
                encryption_status = 'None'

            try:
                object_count = s3.list_objects_v2(Bucket=bucket_name)['KeyCount']
            except ClientError:
                object_count = 'Unknown'

            buckets.append([
                bucket_name, creation_date, encryption_status, object_count
            ])

        headers = ["Bucket Name", "Creation Date", "Encryption", "Number of Objects"]
        click.echo(tabulate(buckets, headers, tablefmt="grid"))
    except ClientError as e:
        click.echo(click.style(f"Failed to list buckets: {e}", fg="red"))

# List objects in a specific S3 bucket command
@cli.command(name="list-objects", help="List objects in a specific S3 bucket in a table format.")
@click.argument('bucket_name')
def list_s3_objects(bucket_name):
    credentials = load_aws_credentials()
    s3 = boto3.client('s3', **credentials)
    try:
        response = s3.list_objects_v2(Bucket=bucket_name)
        if 'Contents' not in response:
            click.echo(click.style(f"No objects found in bucket {bucket_name}.", fg="yellow"))
            return

        objects = []
        for obj in response['Contents']:
            key = obj['Key']
            size = obj['Size']
            last_modified = obj['LastModified'].strftime('%Y-%m-%d %H:%M:%S')
            storage_class = obj['StorageClass']
            objects.append([
                key, size, last_modified, storage_class
            ])

        headers = ["Object Key", "Size (Bytes)", "Last Modified", "Storage Class"]
        click.echo(tabulate(objects, headers, tablefmt="grid"))
    except ClientError as e:
        click.echo(click.style(f"Failed to list objects in bucket {bucket_name}: {e}", fg="red"))

@cli.command(name="delete-object", help="Delete an object from an S3 bucket.")
@click.argument('bucket_name')
@click.argument('object_key')
def delete_object(bucket_name, object_key):
    click.echo(click.style("Warning: This action is irreversible and you will not be able to recreate the object. No version information will be saved.", fg="red"))
    if click.confirm(click.style("Do you want to proceed with deleting the object?", fg="red"), default=False):
        comment = click.prompt(click.style("Enter a comment for this deletion", fg="red"))
        try:
            credentials = load_aws_credentials()
            s3 = boto3.client('s3', **credentials)
            s3.delete_object(Bucket=bucket_name, Key=object_key)
            click.echo(click.style(f"Object '{object_key}' deleted successfully from bucket '{bucket_name}'.", fg="green"))
        except ClientError as e:
            click.echo(click.style(f"Failed to delete object: {e}", fg="red"))
    else:
        click.echo(click.style("Object deletion aborted.", fg="yellow"))

@cli.command(name="delete-bucket", help="Delete an S3 bucket.")
@click.argument('bucket_name')
def delete_bucket(bucket_name):
    click.echo(click.style("Warning: This action is irreversible and you will not be able to recreate the bucket or its contents. No version information will be saved.", fg="red"))
    if click.confirm(click.style("Do you want to proceed with deleting the bucket?", fg="red"), default=False):
        try:
            credentials = load_aws_credentials()
            s3 = boto3.client('s3', **credentials)
            # Empty the bucket before deleting
            response = s3.list_objects_v2(Bucket=bucket_name)
            if 'Contents' in response:
                for obj in response['Contents']:
                    s3.delete_object(Bucket=bucket_name, Key=obj['Key'])
            s3.delete_bucket(Bucket=bucket_name)
            click.echo(click.style(f"Bucket '{bucket_name}' and all its contents deleted successfully.", fg="green"))
        except ClientError as e:
            click.echo(click.style(f"Failed to delete bucket: {e}", fg="red"))
    else:
        click.echo(click.style("Bucket deletion aborted.", fg="yellow"))


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
    raise Exception(f"Instances {instance_ids} did not reach running state within the allotted time.")


# Serialize instance information
def serialize_instance_info(instance):
    for key, value in instance.items():
        if isinstance(value, datetime):
            instance[key] = value.isoformat()
        elif isinstance(value, list):
            instance[key] = [serialize_instance_info(item) if isinstance(item, dict) else item for item in value]
        elif isinstance(value, dict):
            instance[key] = serialize_instance_info(value)
    return instance

def create_version_bucket():
    credentials = load_aws_credentials()
    if not credentials:
        click.echo("No AWS credentials found. Please configure them first.")
        return None

    s3 = boto3.client('s3', **credentials)
    try:
        if click.confirm("Do you want to create a new bucket for version information?", default=True):
            s3.create_bucket(Bucket=VERSION_BUCKET_NAME)
            click.echo(f"S3 bucket '{VERSION_BUCKET_NAME}' created successfully.")
    except ClientError as e:
        click.echo(click.style(f"Failed to create S3 bucket: {e}", fg="red"))



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
        response = ec2.stop_instances(InstanceIds=instance_ids_list)
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
        response = ec2.start_instances(InstanceIds=instance_ids_list)
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

@cli.command(name="download-s3", help="Download a file from S3.")
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

def load_jenkins_credentials_from_s3():
    key = load_jenkins_key()
    try:
        credentials = load_aws_credentials()
        s3 = boto3.client('s3', **credentials)
        response = s3.get_object(Bucket=JENKINS_CREDENTIALS_BUCKET, Key=JENKINS_CREDENTIALS_FILE)
        encrypted_credentials = response['Body'].read()
        decrypted_credentials = decrypt_jenkins_data(encrypted_credentials, key)
        return json.loads(decrypted_credentials)
    except (NoCredentialsError, PartialCredentialsError) as e:
        click.echo(f"Error with AWS credentials: {e}")
    except ClientError as e:
        click.echo(f"Error loading credentials from S3: {e}")
        return None

def create_jenkins_job(job_name, jenkinsfile_path):
    jenkins_credentials = load_jenkins_credentials_from_s3()
    if not jenkins_credentials:
        click.echo("Failed to load Jenkins credentials.")
        return

    jenkins_url = jenkins_credentials['jenkins_url']
    username = jenkins_credentials['username']
    api_token = jenkins_credentials['api_token']

    with open(jenkinsfile_path, 'r') as file:
        jenkinsfile_content = file.read()

    job_config_xml = f"""<?xml version='1.1' encoding='UTF-8'?>
<flow-definition plugin="workflow-job@2.40">
  <description></description>
  <keepDependencies>false</keepDependencies>
  <properties/>
  <definition class="org.jenkinsci.plugins.workflow.cps.CpsFlowDefinition" plugin="workflow-cps@2.92">
    <script>{jenkinsfile_content}</script>
    <sandbox>true</sandbox>
  </definition>
  <triggers/>
  <disabled>false</disabled>
</flow-definition>"""

    job_url = f"{jenkins_url}/createItem?name={job_name}"
    headers = {'Content-Type': 'application/xml'}
    response = requests.post(job_url, data=job_config_xml, headers=headers, auth=(username, api_token))

    if response.status_code == 200:
        return f"Job '{job_name}' created successfully."
    elif response.status_code == 400:
        return f"Job '{job_name}' already exists. Updating the job."
    else:
        return f"Failed to create job '{job_name}'. Status code: {response.status_code}\n{response.text}"

def trigger_jenkins_job(job_name):
    credentials = load_jenkins_credentials_from_s3()
    if not credentials:
        click.echo("Failed to load Jenkins credentials.")
        return

    jenkins_url = credentials['jenkins_url']
    username = credentials['username']
    api_token = credentials['api_token']

    job_url = f"{jenkins_url}/job/{job_name}/build"
    response = requests.post(job_url, auth=(username, api_token))

    if response.status_code == 201:
        return f"Job '{job_name}' triggered successfully."
    else:
        return f"Failed to trigger job '{job_name}'. Status code: {response.status_code}\n{response.text}"

@cli.command(name="create-jenkins-job", help="Create a Jenkins job with a specified Jenkinsfile.")
@click.argument('job_name')
@click.argument('jenkinsfile_path', type=click.Path(exists=True))
def create_jenkins_job_command(job_name, jenkinsfile_path):
    result = create_jenkins_job(job_name, jenkinsfile_path)
    click.echo(result)

@cli.command(name="trigger-jenkins-job", help="Trigger a Jenkins job.")
@click.argument('job_name')
def trigger_jenkins_job_command(job_name):
    result = trigger_jenkins_job(job_name)
    click.echo(result)







cli.add_command(vault)



if __name__ == '__main__':
    cli.add_command(setup_master)
    cli.add_command(greet)
    cli.add_command(version)
    cli.add_command(mkdir)
    cli.add_command(solve)
    cli.add_command(login)
    cli.add_command(create)
    cli.add_command(create_aws_instance)
    cli.add_command(list_instances)
    cli.add_command(stop_aws_instances)
    cli.add_command(start_aws_instances)
    cli.add_command(dob_screenplay)
    cli.add_command(download_s3)
    cli.add_command(upload_s3)
    cli.add_command(list_s3_buckets)
    cli.add_command(list_s3_objects)
    cli.add_command(create_s3_bucket)
    cli.add_command(delete_s3_bucket)
    cli.add_command(delete_s3_object)
    cli.add_command(copy_s3_object)
    cli.add_command(system_monitor)
    cli.add_command(start_master)
    cli.add_command(start_worker)
    cli.add_command(list_workers)
    cli.add_command(stop_worker)
    cli.add_command(assign_task)
    cli.add_command(create_worker)
    cli.add_command(delete_worker)
    cli.add_command(configure_aws)
    cli.add_command(system_monitor)
    cli.add_command(configure_jenkins)
    cli.add_command(jenkins_job)
    cli.add_command(create_jenkins_job_command)

    cli()
    app.run(debug=True)
