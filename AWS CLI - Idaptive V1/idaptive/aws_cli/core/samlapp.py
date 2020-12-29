# Copyright 2019 IDaptive, LLC.
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


import base64
import json
import logging
import sys
from urllib import parse as urlparse

import defusedxml.ElementTree as ET
from colorama import Fore, Style

from . import auth, restclient
from .awsinputs import AwsInputs
from .htmlresponse import HtmlResponse
from .util import printline, safe_input


def handle_app_click(session, appkey, version, environment, proxy):
    method = "/uprest/handleAppClick?appkey=" + appkey
    body = {}
    headers = {}
    session_token = "Bearer " + session.session_token
    headers["Authorization"] = session_token
    response = restclient.call_rest_post(
        session.endpoint,
        method,
        body,
        headers,
        environment.get_certpath(),
        proxy,
        environment.get_debug(),
    )

    logging.debug("Call App Response URL: %s", response.url)

    if "elevate" in response.url:
        url = response.url
        parsed_url = urlparse.urlparse(url)
        chal = urlparse.parse_qs(parsed_url.query)["challengeId"][0]
        ele_session = auth.elevate(
            session, appkey, headers, response, version, environment, proxy
        )
        ele_token = "Bearer " + ele_session.session_token
        headers["Authorization"] = ele_token
        headers["X-CFY-CHALLENGEID"] = chal
        body["ChallengeStateId"] = chal
        json_body = json.dumps(body)
        response = restclient.call_rest_post(
            session.endpoint,
            method,
            json_body,
            headers,
            environment.get_certpath(),
            proxy,
            environment.get_debug(),
        )
        logging.debug("Call App Response URL - After Elevate: %s", response.url)
    return response


def call_app(session, appkey, version, environment, proxy):
    response = handle_app_click(session, appkey, version, environment, proxy)
    html_response = HtmlResponse(response.text)
    logging.debug("------------------- App Response ----------------")
    logging.debug(html_response)
    encoded_saml = html_response.get_saml()
    if encoded_saml == "":
        logging.error(
            "Did not receive SAML response. Please check if you have chosen Saml App"
        )
        raise RuntimeError(
            "Did not receive SAML response. Please check if you have chosen Saml App"
        )
    return encoded_saml


def extract_roles_from_encoded_saml(encoded_saml):
    logging.debug("Decoding SAML ....")
    decoded_saml = base64.b64decode(encoded_saml)
    logging.debug(decoded_saml)
    root = ET.fromstring(decoded_saml)
    awsroles = []
    for saml2attribute in root.iter("{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"):
        if saml2attribute.get("Name") == "https://aws.amazon.com/SAML/Attributes/Role":
            for saml2attributevalue in saml2attribute.iter(
                "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"
            ):
                awsroles.append(saml2attributevalue.text)

    awsroles.sort()

    allroles = []
    saml_providers = []
    for awsrole in awsroles:
        chunks = awsrole.split(",")
        allroles.append(chunks[0])
        saml_providers.append(chunks[1])

    return saml_providers, allroles


def choose_role(encoded_saml, appkey):
    saml_providers, all_roles = extract_roles_from_encoded_saml(encoded_saml)

    printline()
    print(Fore.GREEN)
    print("Select a role to login. Choose one role at a time. This")
    print("selection might be displayed multiple times to facilitate")
    print("multiple profile creations. ")
    print("Type 'q' to exit.")
    print(Style.RESET_ALL)
    print("Please choose the role you would like to assume -")
    if len(all_roles) > 1:
        i = 1
        for role in all_roles:
            print("[", i, "]: ", role)
            i = i + 1
        try:
            inputstring = ""
            while inputstring == "":
                inputstring = safe_input("Please select : ")
            selection = int(inputstring)
        except ValueError:
            return "q", None
        if selection > len(all_roles):
            print("You have selected a wrong role..", file=sys.stderr)
            sys.exit(0)
    else:
        print("1: " + all_roles[0])
        print("Selecting above role. ")
        selection = 1

    role = all_roles[selection - 1]

    principle = saml_providers[selection - 1]
    print("You Chose : ", role)
    print("Your SAML Provider : ", principle)

    awsinputs = AwsInputs(role, principle, encoded_saml)
    if len(all_roles) == 1:
        return "one_role_quit", awsinputs
    return "go", awsinputs
