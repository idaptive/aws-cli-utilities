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
import base64
import re
import xml.etree.ElementTree as ET

EUSC_DEFAULT_REGION = 'eusc-de-east-1'
_EUSC_ACS_REGION_RE = re.compile(r'https?://([a-z0-9-]+)\.signin\.amazonaws-eusc\.eu\b', re.IGNORECASE)


def _extract_eusc_region_from_saml(encoded_saml):
    if not encoded_saml:
        return None
    try:
        decoded_saml = base64.b64decode(encoded_saml)
        root = ET.fromstring(decoded_saml)
        candidates = [root.get('Destination') or '']
        for elem in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData'):
            if elem.get('Recipient'):
                candidates.append(elem.get('Recipient'))
        for url in candidates:
            match = _EUSC_ACS_REGION_RE.search(url)
            if match:
                return match.group(1).lower()
            if 'amazonaws-eusc.eu' in url.lower() or 'amazonaws.eu' in url.lower():
                return EUSC_DEFAULT_REGION
    except Exception:
        pass
    return None


def _resolve_eusc_parameters(role, principle, region, saml=None):
    saml_eusc_region = _extract_eusc_region_from_saml(saml)
    is_eusc = (
        ':aws-eusc:' in (role or '')
        or ':aws-eusc:' in (principle or '')
        or (region or '').lower().startswith('eusc-')
        or saml_eusc_region is not None
    )
    if not is_eusc:
        return role, principle, region, None

    if role and role.startswith('arn:aws:iam::'):
        role = 'arn:aws-eusc:iam::' + role[len('arn:aws:iam::'):]
    if principle and principle.startswith('arn:aws:iam::'):
        principle = 'arn:aws-eusc:iam::' + principle[len('arn:aws:iam::'):]

    if region and region.lower().startswith('eusc-'):
        effective_region = region.lower()
    else:
        effective_region = saml_eusc_region or EUSC_DEFAULT_REGION

    endpoint_url = 'https://sts.{}.amazonaws.eu'.format(effective_region)
    return role, principle, effective_region, endpoint_url


def _sts_client_for_region(region, endpoint_url=None):
    """Return a boto3 STS client pinned to *region* (and explicit *endpoint_url* when needed).

    For AWS European Sovereign Cloud (aws-eusc), explicitly targeting
    https://sts.<region>.amazonaws.eu (e.g. https://sts.eusc-de-east-1.amazonaws.eu)
    ensures AssumeRoleWithSAML reaches the EUSC STS endpoint even on older
    botocore releases that predate the aws-eusc partition definition.
    """
    if endpoint_url:
        logging.info('Creating STS client for region: %s (endpoint_url=%s)', region, endpoint_url)
        return boto3.client('sts', region_name=region, endpoint_url=endpoint_url)
    logging.info('Creating STS client for region: %s', region)
    return boto3.client('sts', region_name=region)


def write_cred(cred, count, display_name, region, role):
    home = expanduser("~")
    print('home = ' + home)
    cred_file = home + "/.aws/credentials"
    config = configparser.RawConfigParser()
    config.read(cred_file)
    print("Display Name : " + display_name)
    rolesplit = role.split('/')
    profile_name = rolesplit[1] + '_profile'
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

    

def assume_role_with_saml(role, principle, saml, count, display_name, region, duration=3600):
    role, principle, effective_region, endpoint_url = _resolve_eusc_parameters(role, principle, region, saml)
    stsclient = _sts_client_for_region(effective_region, endpoint_url=endpoint_url)
    try:
        cred = stsclient.assume_role_with_saml(RoleArn=role, PrincipalArn=principle, SAMLAssertion=saml, DurationSeconds=duration)
    except ClientError as e:
        print("Access Denied. Please check.. " + str(e))
        logging.info(str(e))
        return False
    write_cred(cred, count, display_name, effective_region, role)
    return True
