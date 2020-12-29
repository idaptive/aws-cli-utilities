import setuptools

setuptools.setup(
    name="idaptive-aws-cli-utilities",
    version="1.0.1",
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
    ],
    entry_points={
        "console_scripts": ["idaptive-aws-cli-login=idaptive.aws_cli.cli:main"],
    },
)
