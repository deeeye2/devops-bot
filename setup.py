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
