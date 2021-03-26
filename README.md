# aws-cli-utilities

AWS CLI tools for CyberArk

This repository contains two separate codebases: a portable Python CLI which
will obtain short-term AWS credentials after you authenticate to Idaptive and a
PowerShell version which will only run on Microsoft Windows. Please consult the
README files in the directory for the tool which suits your needs.

## Python Installation

See [the Python CLI documentation](./AWS%20CLI%20-%20Idaptive%20V1/README.md) for more details:

```bash
$ pipx install idaptive-aws-cli-utilities --pip-args='--extra-index-url https://git.loc.gov/api/v4/projects/1594/packages/pypi/simple'
…
```

## Docker Usage

As a convenience a Docker image is available which has the Idaptive Python CLI
packaged with the AWS CLI. This can be used to run the CLI or even an entire AWS
CLI session inside the container. This will likely require setting some environmental
variables:

-   `IDAPTIVE_USERNAME`
-   `AWS_DEFAULT_REGION`

In the simplest case, this can be used to start a shell:

```bash
cadams@Ganymede ~/Projects/idaptive-aws-cli-utilities (add-docker-wrapper)> docker run -it --rm -e IDAPTIVE_USERNAME idaptive-aws-cli
Password :
Select the aws app to login. Type 'quit' or 'q' to exit
…
--------------------------------------------------------------------------------
Your profile is created. It will expire at 2020-12-23 05:38:37+00:00
Use --profile sandbox-development for the commands
Example -
aws s3 ls --profile sandbox-development
--------------------------------------------------------------------------------
--------------------------------------------------------------------------------
…
Launching AWS CLI using profile sandbox-development as arn:aws:sts::587057701939:assumed-role/AWSLoCDevOps/cadams@loc.gov
aws-user@ab95027d9a40:~$ aws sts get-caller-identity
{
    "UserId": "AROAYRL25UQZ24ENCOSXH:cadams@loc.gov",
    "Account": "587057701939",
    "Arn": "arn:aws:sts::587057701939:assumed-role/AWSLoCDevOps/cadams@loc.gov"
}
aws-user@ab95027d9a40:~$
```

This can be used to work with external credential files, perhaps for use with
tools such as Terraform or to renew multiple sessions:

```bash
$ docker run -it --rm -e AWS_PROFILE -e IDAPTIVE_USERNAME -v "$HOME/.aws:/home/aws-user/.aws" idaptive-aws-cli sts get-caller-identity
{
    "UserId": "AROAZFZYV77ZAFOJDGKZ4:cadams@loc.gov",
    "Account": "630942203890",
    "Arn": "arn:aws:sts::630942203890:assumed-role/AWSLoCAdministrator/cadams@loc.gov"
}
```

```bash
$ docker run -it --rm -e AWS_PROFILE -e IDAPTIVE_USERNAME -v "$HOME/.aws:/home/aws-user/.aws" idaptive-aws-cli
Launching AWS CLI using profile bard-development as arn:aws:sts::630942203890:assumed-role/AWSLoCAdministrator/cadams@loc.gov
aws-user@3fa80fe16814:~$ idaptive-aws-cli-login --renew-all-sessions
Password :
Display Name : aws-bard-development
…
```
