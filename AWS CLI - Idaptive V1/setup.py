import setuptools

setuptools.setup(
    name="idaptive-aws-cli-utilities",
    version="1.3.1",
    description="Obtain AWS credentials using Idaptive SSO",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Apache License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[
        "requests",
        "boto3",
        "colorama",
        "coloredlogs",
        "defusedxml",
        "importlib-metadata >= 1.0 ; python_version < '3.8'",
    ],
    entry_points={
        "console_scripts": ["idaptive-aws-cli-login=idaptive.aws_cli.cli:main"],
    },
)
