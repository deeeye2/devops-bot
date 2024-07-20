import click
import os
import json
import requests
import time
import boto3

API_BASE_URL = "https://devopsbot-testserver.online"

def save_token(token):
    with open(os.path.expanduser("~/.devops_bot_token"), "w") as token_file:
        token_file.write(token)

def load_token():
    try:
        with open(os.path.expanduser("~/.devops_bot_token"), "r") as token_file:
            return token_file.read().strip()
    except FileNotFoundError:
        return None

def save_aws_credentials(access_key, secret_key):
    credentials = {
        'aws_access_key_id': access_key,
        'aws_secret_access_key': secret_key
    }
    with open(os.path.expanduser("~/.aws_credentials"), "w") as cred_file:
        json.dump(credentials, cred_file)

def load_aws_credentials():
    try:
        with open(os.path.expanduser("~/.aws_credentials"), "r") as cred_file:
            return json.load(cred_file)
    except FileNotFoundError:
        return None

@click.group()
def cli():
    """DevOps Bot CLI."""
    pass

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

@cli.command(help="Create an AWS instance.")
@click.option('--params', required=True, help='Parameters for the AWS instance (e.g., "image_id=ami-0abcdef1234567890 instance_type=t2.micro")')
def create_aws_instance(params):
    aws_credentials = load_aws_credentials()
    if not aws_credentials:
        click.echo("No AWS credentials found. Please configure them first using 'devops-bot configure-aws'.")
        return

    params_dict = dict(param.split('=') for param in params.split())
    try:
        ec2 = boto3.client('ec2', **aws_credentials)
        response = ec2.run_instances(
            ImageId=params_dict.get('image_id'),
            InstanceType=params_dict.get('instance_type'),
            MinCount=1,
            MaxCount=1
        )
        instance_id = response['Instances'][0]['InstanceId']
        click.echo(f"Instance created successfully: {instance_id}")
    except NoCredentialsError:
        click.echo("AWS credentials not found.")
    except PartialCredentialsError:
        click.echo("Incomplete AWS credentials.")
    except Exception as e:
        click.echo(f"Error creating instance: {e}")


if __name__ == '__main__':
    cli()




