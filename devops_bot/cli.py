import click
import os
import json

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

if __name__ == '__main__':
    cli()
