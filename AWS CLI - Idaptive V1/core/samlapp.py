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

from core import restclient, auth
from core.htmlresponse import HtmlResponse
import base64
import xml.etree.ElementTree as ET
import sys
from core.awsinputs import AwsInputs
from core.util import printline
import logging
from _operator import contains
import urllib
from urllib import parse as urlparse
import json
from core.authresponse import AuthResponse
from colorama import Fore, Style


def handle_app_click(session, appkey, version, environment, proxy, user_agent=None):
    method = "/uprest/handleAppClick?appkey=" + appkey
    body = {}
    headers = {}
    session_token = "Bearer "+session.session_token
    headers['Authorization'] = session_token
    if user_agent:
        headers['User-Agent'] = user_agent
    response = restclient.call_rest_post(session.endpoint, method, body, headers, environment.get_certpath(), proxy, environment.get_debug())
    logging.info("Call App Response URL : " + response.url)
    if ('elevate' in response.url):
        url = response.url
        parsed_url = urlparse.urlparse(url)
        elav = urlparse.parse_qs(parsed_url.query)['elevate'][0]
        chal = urlparse.parse_qs(parsed_url.query)['challengeId'][0]
        ele_session = auth.elevate(session, appkey, headers, response, version, environment, proxy)
        ele_token = "Bearer "+ele_session.session_token
        headers['Authorization'] = ele_token
        headers['X-CFY-CHALLENGEID'] = chal
        body['ChallengeStateId'] = chal
        json_body = json.dumps(body)
        response = restclient.call_rest_post(session.endpoint, method, json_body, headers, environment.get_certpath(), proxy, environment.get_debug())
        logging.info("Call App Response URL - After Elevate : " + response.url)
    return response

def call_app(session, appkey, version, environment, proxy, user_agent=None):
    response = handle_app_click(session, appkey, version, environment, proxy, user_agent)
    html_response = HtmlResponse(response.text)
    logging.info("------------------- App Response ----------------")
    logging.info(html_response)
    encoded_saml = html_response.get_saml()
    if (encoded_saml == ''):
        error_title, error_text = html_response.get_error()
        logging.info('Did not receive SAML response. Response URL: %s, server error: %s %s',
        getattr(response, 'url', ''), error_title, error_text)
        print(Fore.RED + 'Did not receive SAML response from app (' + str(appkey) + ').')
        if error_title or error_text:
            print('  Identity returned: ' + ' - '.join(part for part in (error_title, error_text) if part))
        if getattr(response, 'url', '') and 'handleAppClick' not in response.url:
            print('  Redirected to: ' + str(response.url))
        if not (error_title or error_text):
            print('  Please check aws-cli.log ("Received Response") for the server reply.')
        print(Style.RESET_ALL)
        return ''
    return encoded_saml

# ---------------------------------------------------------------------------
# SAML Role attribute URIs per AWS partition.
# Commercial and aws-eusc SAML federation use https://aws.amazon.com/SAML/Attributes/Role.
# ---------------------------------------------------------------------------
_AWS_ROLE_SAML_ATTR_URIS = {
    'https://aws.amazon.com/SAML/Attributes/Role',            # commercial (aws) & EU Sovereign Cloud (aws-eusc)
    'https://aws.amazon.com.eusc.gov/SAML/Attributes/Role',   # fallback EUSC attribute URI
}


def _extract_saml_acs_url(root):
    destination = root.get('Destination')
    if destination:
        return destination.strip()
    for elem in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData'):
        recipient = elem.get('Recipient')
        if recipient:
            return recipient.strip()
    return ''


def _is_eusc_acs_url(acs_url):
    acs_lower = (acs_url or '').lower()
    return (
        'amazonaws-eusc.eu' in acs_lower
        or 'amazonaws.eu' in acs_lower
        or 'eusc-' in acs_lower
    )


def _normalize_eusc_arn(arn):
    if arn and arn.startswith('arn:aws:iam::'):
        return 'arn:aws-eusc:iam::' + arn[len('arn:aws:iam::'):]
    return arn


def extract_roles(encoded_saml):
    decoded_saml = base64.b64decode(encoded_saml)
    logging.info(decoded_saml)
    root = ET.fromstring(decoded_saml)
    acs_url = _extract_saml_acs_url(root)
    is_eusc_acs = _is_eusc_acs_url(acs_url)

    awsroles = []
    for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if (saml2attribute.get('Name') in _AWS_ROLE_SAML_ATTR_URIS):
            for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                if saml2attributevalue.text:
                    awsroles.append(saml2attributevalue.text.strip())

    allroles = []
    saml_provider = []
    eusc_via_universal_idp = False
    for awsrole in awsroles:
        chunks = [c.strip() for c in awsrole.split(',') if c.strip()]
        if len(chunks) < 2:
            continue
        if ':saml-provider/' in chunks[0]:
            provider_arn, role_arn = chunks[0], chunks[1]
        else:
            role_arn, provider_arn = chunks[0], chunks[1]

        if is_eusc_acs or ':aws-eusc:' in role_arn or ':aws-eusc:' in provider_arn:
            role_arn = _normalize_eusc_arn(role_arn)
            provider_arn = _normalize_eusc_arn(provider_arn)

        # Warn only when an aws-eusc role is federated through a non-EUSC
        # (commercial Universal IDP) SAML destination.
        if (':aws-eusc:' in role_arn or ':aws-eusc:' in provider_arn) and not is_eusc_acs:
            eusc_via_universal_idp = True
        allroles.append(role_arn)
        saml_provider.append(provider_arn)

    return allroles, saml_provider, eusc_via_universal_idp


def choose_role(encoded_saml, appkey):
    logging.info("Decoding SAML ....")
    allroles, saml_provider, eusc_via_universal_idp = extract_roles(encoded_saml)

    if len(allroles) == 0:
        print(Fore.RED + "No AWS roles found in SAML assertion for app: " + str(appkey) + Style.RESET_ALL)
        return 'q', None

    if eusc_via_universal_idp:
        print(Fore.YELLOW)
        print("WARNING: One or more roles belong to the AWS European Sovereign Cloud (aws-eusc).")
        print("  eusc accounts do NOT federate through 'AWS Universal IDP'.")
        print("  Please select the dedicated per-account eusc Idira app for this account.")
        print("  Logging in via Universal IDP will always fail with InvalidIdentityToken.")
        print(Style.RESET_ALL)
    
    printline()
    print(Fore.GREEN)
    print("Select a role to login. Choose one role at a time. This")
    print("selection might be displayed multiple times to facilitate")
    print("multiple profile creations. ")
    print("Type 'q' to exit.")
    print(Style.RESET_ALL)
    print('Please choose the role you would like to assume -')
    if (len(allroles) > 1):
        i = 1
        for role in allroles:
            print('[',i,']: ', role)
            i = i+1
        try:
            inputstring = ""
            while (inputstring == ""):
                inputstring = input('Please select : ')
            selection = int (inputstring)
        except ValueError:
            return 'q', None
        if (selection > len(allroles)):
            print('You have selected a wrong role..')
            sys.exit(0)
    else:
        print('1: ' + allroles[0])
        print("Selecting above role. ")
        selection = 1
        
    role = allroles[selection-1]
    principle = saml_provider[selection-1]
    
    print('You Chose : ', role)
    print('Your SAML Provider : ', principle)
        
    awsinputs = AwsInputs(role, principle, encoded_saml)
    if (len(allroles) == 1):
        return 'one_role_quit', awsinputs
    return 'go', awsinputs