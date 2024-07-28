#!/bin/bash

if [ "$1" == "exclude" ]; then
    echo "Excluding devops_bot/cli.py from tracking..."
    echo "devops_bot/cli.py" >> .gitignore
    git rm --cached devops_bot/cli.py
    git add .gitignore
    git commit -m "Exclude cli.py from tracking"
    git push origin master
    echo "devops_bot/cli.py has been excluded from tracking and added to .gitignore."
elif [ "$1" == "include" ]; then
    echo "Including devops_bot/cli.py in tracking..."
    sed -i '' '/devops_bot\/cli.py/d' .gitignore
    git add .gitignore
    git add devops_bot/cli.py
    git commit -m "Include cli.py in tracking"
    git push origin master
    echo "devops_bot/cli.py has been included in tracking and removed from .gitignore."
else
    echo "Usage: $0 {exclude|include}"
fi

