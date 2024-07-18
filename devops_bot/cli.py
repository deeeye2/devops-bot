import click
import os
import json
import requests
import yaml

API_BASE_URL = "http://192.168.56.41:8000/api"

def save_token(token):
    with open(os.path.expanduser("~/.devops_bot_token"), "w") as token_file:
        token_file.write(token)

def load_token():
    try:
        with open(os.path.expanduser("~/.devops_bot_token"), "r") as token_file:
            return token_file.read().strip()
    except FileNotFoundError:
        return None

@click.group()
def cli():
    """DevOps Bot CLI."""
    pass

@cli.command()
def greet():
    """Greet the user."""
    click.echo("Hello from DevOps Bot!")

@cli.command()
def version():
    """Show version information."""
    click.echo("devops-bot, version 0.1")

@cli.command()
@click.argument('path')
def mkdir(path):
    """Create a directory at the specified path."""
    try:
        os.makedirs(path, exist_ok=True)
        click.echo(f"Directory '{path}' created successfully.")
    except Exception as e:
        click.echo(f"Failed to create directory '{path}': {e}")

@cli.command()
@click.argument('issue')
def solve(issue):
    """Solve an issue using the knowledge base."""
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

@cli.command()
@click.argument('username')
@click.argument('password')
def login(username, password):
    """Login to the DevOps Bot."""
    response = requests.post(f"{API_BASE_URL}/login", json={"username": username, "password": password})
    if response.status_code == 200:
        token = response.json().get('token')
        if token:
            save_token(token)
            click.echo("Login successful!")
        else:
            click.echo("Failed to retrieve token.")
    else:
        click.echo("Invalid username or password")

@cli.command()
@click.argument('resource_type')
@click.argument('data', type=click.File('rb'))
def generate(resource_type, data):
    """Generate configuration files."""
    token = load_token()
    if not token:
        click.echo("No token found. Please log in first.")
        return

    headers = {'Authorization': token}
    response = requests.post(f"{API_BASE_URL}/generate/{resource_type}", headers=headers, json={"data": data.read()})

    if response.status_code == 200:
        click.echo(response.json().get('message'))
        click.echo(response.json().get('data'))
    else:
        click.echo("Failed to generate file.")
        click.echo(response.json().get('message'))

@cli.command()
@click.argument('type', type=click.Choice(['k8s', 'dockerfile', 'ansible', 'terraform']))
@click.argument('manifest_type', required=False)
@click.option('--params', type=str, help="Parameters for the manifest.")
def create(type, manifest_type, params):
    """Create various DevOps manifests.

    TYPE: The type of resource to create. Choices are: k8s, dockerfile, ansible, terraform.
    
    MANIFEST_TYPE: For k8s, specify the kind of Kubernetes resource (e.g., Deployment, Service).
    
    --params: Parameters for the manifest in the form 'key=value key2=value2 ...'.
    
    Examples:
    devops-bot create k8s Deployment --params "name=mydeployment image=nginx replicas=3 volume=myvol"
    devops-bot create dockerfile --params "base_image=node version=14 install_command=npm install start_command=node app.js"
    devops-bot create ansible --params "package=name=nginx state=present service=name=nginx state=started"
    devops-bot create terraform --params "resource_type=aws_instance resource_name=myinstance ami=ami-12345678 instance_type=t2.micro"
    """
    if type == 'k8s':
        create_k8s_manifest(manifest_type, params)
    elif type == 'dockerfile':
        create_dockerfile(params)
    elif type == 'ansible':
        create_ansible_playbook(params)
    elif type == 'terraform':
        create_terraform_config(params)
    else:
        click.echo("Invalid type specified.")

def create_k8s_manifest(manifest_type, params):
    if not manifest_type or not params:
        click.echo("For k8s, both manifest_type and params are required.")
        return
    
    params_dict = dict(param.split('=') for param in params.split())
    
    manifest = {}
    if manifest_type == 'Deployment':
        manifest = {
            'apiVersion': 'apps/v1',
            'kind': 'Deployment',
            'metadata': {'name': params_dict.get('name')},
            'spec': {
                'replicas': int(params_dict.get('replicas')),
                'selector': {'matchLabels': {'app': params_dict.get('name')}},
                'template': {
                    'metadata': {'labels': {'app': params_dict.get('name')}},
                    'spec': {
                        'containers': [{
                            'name': params_dict.get('name'),
                            'image': params_dict.get('image')
                        }]
                    }
                }
            }
        }
        if 'volume' in params_dict:
            manifest['spec']['template']['spec']['volumes'] = [{'name': params_dict.get('volume')}]
    # Add more conditions for other k8s resources
    click.echo(yaml.dump(manifest))

def create_dockerfile(params):
    if not params:
        click.echo("Parameters are required for dockerfile.")
        return
    
    params_dict = dict(param.split('=') for param in params.split())
    base_image = params_dict.get('base_image')
    version = params_dict.get('version')
    dockerfile_content = f"FROM {base_image}:{version}\n"
    
    if base_image in ["node", "python", "golang", "java"]:
        dockerfile_content += f"""
WORKDIR /usr/src/app
COPY . .
RUN {params_dict.get('install_command')}
CMD ["{params_dict.get('start_command')}"]
"""
    elif base_image == "nginx":
        dockerfile_content += f"""
COPY {params_dict.get('config_file')} /etc/nginx/nginx.conf
COPY {params_dict.get('document_root')} /usr/share/nginx/html
"""
    elif base_image == "alpine":
        dockerfile_content += f"""
RUN {params_dict.get('commands')}
"""
    
    click.echo(dockerfile_content)

def create_ansible_playbook(params):
    if not params:
        click.echo("Parameters are required for ansible playbook.")
        return
    
    params_dict = dict(param.split('=') for param in params.split())
    tasks = []
    
    for task_name, task_params in params_dict.items():
        task_params_dict = dict(param.split('=') for param in task_params.split(','))
        tasks.append({task_name: task_params_dict})
    
    playbook = {
        'hosts': 'all',
        'tasks': tasks
    }
    
    click.echo(yaml.dump(playbook))

def create_terraform_config(params):
    if not params:
        click.echo("Parameters are required for terraform configuration.")
        return
    
    params_dict = dict(param.split('=') for param in params.split())
    resource_type = params_dict.get('resource_type')
    resource_name = params_dict.get('resource_name')
    resource_params = {k: v for k, v in params_dict.items() if k not in ['resource_type', 'resource_name']}
    
    terraform_config = f"""
resource "{resource_type}" "{resource_name}" {{
    {json.dumps(resource_params, indent=4).replace('{', '').replace('}', '').replace('"', '')}
}}
"""
    click.echo(terraform_config)

if __name__ == '__main__':
    cli()

