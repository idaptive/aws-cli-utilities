# Idaptive AWS CLI (Python version)

The official Idaptive documentation is available here: https://developer.idaptive.com/v1.2/docs/aws-cli

This repository contains a number of additional features and usability
improvements which have [not been accepted by Idaptive](https://github.com/idaptive/aws-cli-utilities/pull/2)
but are covered in the output of the `--help` command-line argument.

Many options can be set using environmental variables to avoid needing to
specify them on the command-line for every call.

## Installation

[pipx](https://pipxproject.github.io/pipx/) is highly recommended for Python
tools you are installing globally since each tool gets a clean install in its
own virtualenv and can be updated automatically when new versions of Python or
this program are released.

```bash
pipx install 'https://github.com/acdha/aws-cli-utilities/releases/download/v1.0.1/idaptive-aws-cli-utilities-1.0.1.tar.gz'
```

Alternatively you can use pip in the Python environment of your choosing:

```bash
python3 -m pip install 'https://github.com/acdha/aws-cli-utilities/releases/download/v1.0.1/idaptive-aws-cli-utilities-1.0.1.tar.gz'
```

## Running the CLI

A basic login session starts like this:

```bash
$ idaptive-aws-cli-login
…
```

There are many options available to configure how the CLI tool works – consult
`--help` for more details. Of particular interest, the
`--use-app-name-for-profile` option will create an AWS CLI profile using the
name of the application instead of the role, which can be helpful if you work
with multiple accounts, and the `--renew-all-sessions` option will renew every
session in your credentials file without requiring you to reselect the
applications and roles you commonly use.

A number of options can be set using shell environmental variables to avoid
needing frequent re-entry on the command-line:

```shell
--cert:                         IDAPTIVE_CUSTOM_CA
--region:                       AWS_DEFAULT_REGION
--tenant:                       IDAPTIVE_TENANT
--use-app-name-for-profile:     IDAPTIVE_USE_APP_NAME_FOR_PROFILE
--username:                     IDAPTIVE_USERNAME
```

```bash
$ idaptive-aws-cli-login --help
usage: idaptive-aws-cli-login [-h] [--username USERNAME] [--tenant TENANT] [--region REGION] [--cert CERT] [--debug]
                              [--use-app-name-for-profile] [--renew-all-sessions] [--log-file LOG_FILE] [--verbose]

Use Idaptive SSO to populate a local AWS profile with short-term credentials
…
```
