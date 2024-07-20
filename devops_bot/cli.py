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

def save_aws_credentials(access_key, secret_key, region):
    credentials = {
        'aws_access_key_id': access_key,
        'aws_secret_access_key': secret_key,
        'region_name': region
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


# Section Added: Create Multiple AWS Instances
@cli.command(help="Create multiple AWS instances.")
@click.option('--params', required=True, help='Parameters for the AWS instance (e.g., "image_id=ami-0abcdef1234567890 instance_type=t2.micro")')
@click.option('--count', default=1, help="Number of instances to create")
def create_multiple_aws_instances(params, count):
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
            MinCount=count,
            MaxCount=count
        )
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

@cli.command(help="Delete AWS instances.")
@click.option('--instance_ids', required=True, help='Space-separated IDs of the AWS instances to delete')
def delete_aws_instances(instance_ids):
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
    except NoRegionError:
        click.echo("You must specify a region.")
    except NoCredentialsError:
        click.echo("AWS credentials not found.")
    except PartialCredentialsError:
        click.echo("Incomplete AWS credentials.")
    except Exception as e:
        click.echo(f"Error deleting instances: {e}")

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

if __name__ == '__main__':
    cli()




