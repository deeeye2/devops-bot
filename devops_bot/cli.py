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
@click.argument('username')
@click.argument('password')
def login(username, password):
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

@cli.command(help="Generate configuration files.")
@click.argument('resource_type')
@click.argument('data', type=click.File('rb'))
def generate(resource_type, data):
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

def generate_k8s(manifest_type, **kwargs):
    manifests = []
    for type in manifest_type:
        if type == 'Deployment':
            manifest = {
                "apiVersion": "apps/v1",
                "kind": "Deployment",
                "metadata": {"name": kwargs.get("name")},
                "spec": {
                    "replicas": int(kwargs.get("replicas")),
                    "selector": {"matchLabels": {"app": kwargs.get("name")}},
                    "template": {
                        "metadata": {"labels": {"app": kwargs.get("name")}},
                        "spec": {"containers": [{"name": kwargs.get("name"), "image": kwargs.get("image")}]}
                    }
                }
            }
            if kwargs.get("volume"):
                manifest["spec"]["template"]["spec"]["volumes"] = [{"name": kwargs.get("volume")}]
            manifests.append(manifest)
        
        elif type == 'Service':
            manifest = {
                "apiVersion": "v1",
                "kind": "Service",
                "metadata": {"name": kwargs.get("name")},
                "spec": {
                    "type": kwargs.get("service_type"),
                    "ports": [{"port": int(kwargs.get("port"))}],
                    "selector": {"app": kwargs.get("name")}
                }
            }
            manifests.append(manifest)
        
        elif type == 'ConfigMap':
            manifest = {
                "apiVersion": "v1",
                "kind": "ConfigMap",
                "metadata": {"name": kwargs.get("name")},
                "data": {kwargs.get("name"): kwargs.get("data")}
            }
            manifests.append(manifest)
        
        elif type == 'Secret':
            manifest = {
                "apiVersion": "v1",
                "kind": "Secret",
                "metadata": {"name": kwargs.get("name")},
                "data": {kwargs.get("name"): kwargs.get("data")}
            }
            manifests.append(manifest)
        
        elif type == 'PersistentVolume':
            manifest = {
                "apiVersion": "v1",
                "kind": "PersistentVolume",
                "metadata": {"name": kwargs.get("name")},
                "spec": {
                    "capacity": {"storage": kwargs.get("capacity")},
                    "accessModes": [kwargs.get("access_modes")],
                    "storageClassName": kwargs.get("storage_class")}
                }
            manifests.append(manifest)
        
        elif type == 'PersistentVolumeClaim':
            manifest = {
                "apiVersion": "v1",
                "kind": "PersistentVolumeClaim",
                "metadata": {"name": kwargs.get("name")},
                "spec": {
                    "storageClassName": kwargs.get("storage_class"),
                    "accessModes": [kwargs.get("access_modes")],
                    "resources": {"requests": {"storage": kwargs.get("resources")}}
                }
            }
            manifests.append(manifest)
        
        elif type == 'Ingress':
            manifest = {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "Ingress",
                "metadata": {"name": kwargs.get("name")},
                "spec": {
                    "rules": [{
                        "host": kwargs.get("host"),
                        "http": {
                            "paths": [{
                                "path": '/',
                                "pathType": 'Prefix',
                                "backend": {
                                    "service": {
                                        "name": kwargs.get("service_name"),
                                        "port": {"number": int(kwargs.get("service_port"))}
                                    }
                                }
                            }]
                        }
                    }]
                }
            }
            manifests.append(manifest)
        
        elif type == 'Role':
            manifest = {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "Role",
                "metadata": {"name": kwargs.get("name")},
                "rules": json.loads(kwargs.get("rules"))
            }
            manifests.append(manifest)
        
        elif type == 'RoleBinding':
            manifest = {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "RoleBinding",
                "metadata": {"name": kwargs.get("name")},
                "roleRef": {
                    "apiGroup": "rbac.authorization.k8s.io",
                    "kind": "Role",
                    "name": kwargs.get("role_name")
                },
                "subjects": json.loads(kwargs.get("subjects"))
            }
            manifests.append(manifest)
        
        elif type == 'ClusterRole':
            manifest = {
                "apiVersion": "rbac.authorization.k8s.io/v1",
                "kind": "ClusterRole",
                "metadata": {"name": kwargs.get("name")},
                "rules": json.loads(kwargs.get("rules"))
            }

