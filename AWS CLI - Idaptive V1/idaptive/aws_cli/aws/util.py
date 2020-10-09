import configparser
import os


def get_default_aws_credentials_filename():
    return os.path.expanduser(os.path.join("~", ".aws", "credentials"))


def load_aws_credentials(path=None):
    """
    Returns a RawConfigParser instance with the AWS CLI credentials loaded
    """

    if not path:
        path = get_default_aws_credentials_filename()

    config = configparser.RawConfigParser()
    config.read(path)
    return config, path
