from setuptools import setup, find_packages

setup(
    name='devops-bot',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'Click==8.0.4',
        'Flask==2.0.3',
        'gunicorn==21.2.0',
        'requests>=2.25.0',
        'cryptography>=3.4.7',
        'PyYAML==6.0.1',
        'Flask-SQLAlchemy==2.5.1',
        'Werkzeug>=2.0.3',
        'Flask-Mail==0.9.1',
        'python-dotenv>=0.20.0',  # Loosened version constraint
        'PyJWT==2.4.0',
        'tabulate==0.8.9',
        'argcomplete==3.1.2',
        'psutil==5.9.0',
        'tqdm==4.64.1',
        'boto3>=1.20.0',
        'blinker>=1.5',  # Loosened version constraint
        'botocore>=1.26.10',  # Loosened version constraint
        'certifi>=2024.7.4',  # Loosened version constraint
        'cffi>=1.15.1',  # Loosened version constraint
        'charset-normalizer>=2.0.0',  # Loosened version constraint
        'idna<3,>=2.5',  # Loosened version constraint
        'itsdangerous>=2.0.1',  # Loosened version constraint
        'Jinja2>=3.0.3',  # Loosened version constraint
        'jmespath>=0.10.0',  # Loosened version constraint
        'MarkupSafe>=2.0.1',  # Loosened version constraint
        's3transfer>=0.5.2',  # Loosened version constraint
        'six>=1.16.0',
        'typing-extensions==4.1.1',
        'python-dateutil==2.9.0',
    ],
    entry_points='''
        [console_scripts]
        dob=devops_bot.cli:cli
    ''',
)
