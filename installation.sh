#!/bin/bash

# Update and install required packages
echo "Updating system and installing required packages..."
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip git

# Create the devops_bot directory
mkdir -p ~/devops_bot

# Navigate to the devops_bot directory
cd ~/devops_bot

# Create a virtual environment
python3 -m venv env

# Activate the virtual environment
source env/bin/activate

# Create the setup.py file
cat > setup.py <<EOL
from setuptools import setup, find_packages

setup(
    name='devops-bot',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'Click',
        'Flask',
        'gunicorn'
    ],
    entry_points='''
        [console_scripts]
        devops-bot=devops_bot.cli:cli
    ''',
)
EOL

# Create the devops_bot directory
mkdir -p devops_bot

# Create the __init__.py file
cat > devops_bot/__init__.py <<EOL
EOL

# Create the cli.py file
cat > devops_bot/cli.py <<EOL
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
EOL

# Create the knowledge_base.json file
cat > devops_bot/knowledge_base.json <<EOL
{
  "issues": [
    {
      "problem": "disk space",
      "solution": "Check disk usage with 'df -h' and clear unnecessary files. Use 'du -sh *' to find large directories."
    },
    {
      "problem": "service not starting",
      "solution": "Check service status with 'systemctl status <service>' and inspect logs in /var/log. Ensure all dependencies are installed."
    },
    {
      "problem": "high CPU usage",
      "solution": "Identify the process causing high CPU usage with 'top' or 'htop'. Investigate further by checking application logs."
    },
    {
      "problem": "memory leak",
      "solution": "Use 'free -m' to check memory usage, and 'ps aux --sort=-%mem | head' to identify processes with high memory usage. Restart the problematic services."
    },
    {
      "problem": "network issues",
      "solution": "Use 'ping', 'traceroute', and 'netstat' to diagnose network issues. Check firewall rules and network configurations."
    }
  ]
}
EOL

# Install the devops-bot package
pip install .

# Create the systemd service file
cat > /etc/systemd/system/devops_bot.service <<EOL
[Unit]
Description=DevOps Bot Service
After=network.target

[Service]
User=root
Group=root
WorkingDirectory=/root/devops_bot
Environment="PATH=/root/devops_bot/env/bin"
ExecStart=/root/devops_bot/env/bin/gunicorn --config /root/devops_bot/gunicorn_config.py wsgi:app

[Install]
WantedBy=multi-user.target
EOL

# Create the gunicorn_config.py file
cat > ~/devops_bot/gunicorn_config.py <<EOL
bind = "0.0.0.0:5000"
workers = 3
EOL

# Create the wsgi.py file
cat > ~/devops_bot/wsgi.py <<EOL
from flask import Flask

app = Flask(__name__)

@app.route('/devops-bot/uptime')
def uptime():
    return "The system is up and running!"

if __name__ == "__main__":
    app.run()
EOL

# Prompt user to enable and start the service
read -p "Do you want to enable the DevOps Bot service to start on boot? (y/n) " enable_service
if [ "$enable_service" == "y" ]; then
    sudo systemctl daemon-reload
    sudo systemctl enable devops_bot.service
fi

read -p "Do you want to start the DevOps Bot service now? (y/n) " start_service
if [ "$start_service" == "y" ]; then
    sudo systemctl start devops_bot.service
    sudo systemctl status devops_bot.service
fi

echo "DevOps Bot setup completed successfully."
