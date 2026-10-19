# Copyright 2019 CyberArk, LLC.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import boto3
from botocore.exceptions import ClientError
from os.path import expanduser
import configparser
import sys
import logging

def _sts_client_for_region(region):
    """Return a boto3 STS client pinned to *region*.

    Passing region_name lets botocore resolve the correct regional STS
    endpoint automatically for any AWS partition — including aws-eusc
    (e.g. eusc-de-east-1 → sts.eusc-de-east-1.amazonaws.eu) — without
    requiring any hardcoded endpoint URLs.  This mirrors what AWS CLI v2
    does when --region is supplied.
    """
    logging.info('Creating STS client for region: %s', region)
    return boto3.client('sts', region_name=region)


def write_cred(cred, count, display_name, region, role, profile_name=None):
    home = expanduser("~")
    print('home = ' + home)
    cred_file = home + "/.aws/credentials"
    config = configparser.RawConfigParser()
    config.read(cred_file)
    print("Display Name : " + display_name)
    if not profile_name:
        profile_name = role.split('/')[-1] + '_profile'
    section = profile_name 
    if not config.has_section(section):
        config.add_section(section)
    config.set(section, 'output', 'json')
    config.set(section, 'region', region)
    config.set(section, 'aws_access_key_id', cred['Credentials']['AccessKeyId'])
    config.set(section, 'aws_secret_access_key', cred['Credentials']['SecretAccessKey'])
    config.set(section, 'aws_session_token', cred['Credentials']['SessionToken'])
    with open(cred_file, 'w+') as credentials:
        config.write(credentials)
    print('\n\n')
    print('-' * 80)
    print('Your profile is created. It will expire at ' + str(cred['Credentials']['Expiration']))
    print('Use --profile ' + section + ' for the commands')
    print('Example - ')
    print('aws s3 ls --profile ' + section)
    print('-' * 80)

    

def assume_role_with_saml(role, principle, saml, count, display_name, region, duration=3600, profile_name=None):
    # Pass region_name so botocore resolves the correct regional STS endpoint
    # automatically — works for commercial, GovCloud, China, and aws-eusc
    # (eusc-de-east-1 → sts.eusc-de-east-1.amazonaws.eu) without any
    # hardcoded endpoint URLs.
    stsclient = _sts_client_for_region(region)
    try:
        cred = stsclient.assume_role_with_saml(RoleArn=role, PrincipalArn=principle, SAMLAssertion=saml, DurationSeconds=duration)
    except ClientError as e:
        print("Access Denied. Please check.. " + str(e))
        logging.info(str(e))
        return False
    write_cred(cred, count, display_name, region, role, profile_name)
    return True
    