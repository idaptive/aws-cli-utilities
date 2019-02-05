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

from core.restclient import call_rest_post
from core.authrequest import AuthRequest
from core.authresponse import AuthResponse
from core.adv_authrequest import AdvAuthRequest
from getpass import getpass
from core.authsession import AuthSession
import logging
import sys
import time
from threading import Thread
from kbread import kbinput
from queue import Queue
import platform
from core import authresponse
import urllib
from urllib import parse as urlparse
import json
from colorama import Fore, Back, Style


result = []
done = False

def start_authentication(username, version, proxy, environment):
    endpoint = environment.get_endpoint()
    certpath = environment.get_certpath()
    debug = environment.get_debug()
    method = "/Security/StartAuthentication"
    message = AuthRequest('', username, version)
    json_body = message.get_start_auth_json()
    headers = {}
    logging.info("Starting Authentication .. ")
    response = call_rest_post(endpoint, method, json_body, headers, certpath, proxy, debug)
    authresponse = AuthResponse(response, endpoint)
    success_result = authresponse.get_success_result()
    if (success_result == False):
        print("Invalid User")
        sys.exit(0)
    if (success_result == True):
        try:
            tenant_url = authresponse.get_tenant_url()
        except KeyError as e:
            logging.error(format(e))
            logging.info('Seems we have tenant URL already ')
            return authresponse
        
    endpoint = "https://"+tenant_url
    logging.info("Redirecting to " + endpoint)
    logging.info("Authenticating on the tenant..")
    response = call_rest_post(endpoint, method, json_body, headers, certpath, proxy, environment.get_debug())
    tenant_resp = AuthResponse(response, endpoint)
    return tenant_resp
    
def advance_authentication(tenant_response, endpoint, username, version, proxy, environment):
    certpath = environment.get_certpath()
    method = "/Security/AdvanceAuthentication"
    headers = {}
    challenges = tenant_response.get_challenges()
    challenge_count = 0
    for challenge in challenges:
        logging.info("Starting Challenge " + str(challenge_count))
        challenge_count = challenge_count + 1
        total_mechanism = len(challenge['Mechanisms'])
        logging.info("There are " + str(total_mechanism) + " mechanisms")
        
        if (total_mechanism > 1):
            again = True
            while(again):
                for key, value in challenge.items():
                    count = 1
                    for mechanism in value:
                        print(str(count) + " : " + mechanism['PromptSelectMech'])
                        count = count + 1
                    choice = input("Please choose the mechanism : ")
                try:
                    if (int(choice) >= count or int(choice) <= 0):
                        continue
                except ValueError:
                    continue
                mechanism = value[int(choice)-1]
                again = False
        else:
            mechanism = challenge['Mechanisms'][0]
        logging.info("Mechanism is " + str(mechanism))
        session = advance_auth_for_mech(mechanism, tenant_response, username, endpoint, method, proxy, environment)
    return session

def get_user_choice():
    print("Select from following :")
    print("1. Use OTP")
    print("2. Use URL")
    return input("Enter (1) or (2) to select: ")

def handle_unix(mechanism, tenant_response, username, endpoint, method, environment, proxy, request, json_req):
    certpath = environment.get_certpath()
    mechanism_id = mechanism['MechanismId']
    session_id = tenant_response.get_sessionid()
    tenant_id = tenant_response.get_tenantid()
    headers = {}
    choice = '2'
    if (mechanism['Name'] == 'SMS'):
        choice = get_user_choice()
    if (mechanism['Name'] == 'OATH'):
        choice = '1'
    if (choice == '1'):
        passwd = getpass(mechanism['PromptSelectMech'] + " : ")
        request = AdvAuthRequest(tenant_id, session_id, mechanism_id, passwd)
        json_req = request.get_adv_auth_json_passwd()
        authresp = call_rest_post(endpoint, method, json_req, headers, certpath, proxy, environment.get_debug())
        authresponse = AuthResponse(authresp, endpoint)
        success_result = authresponse.get_success_result()
        summary = authresponse.get_summary()
        if (success_result == False):
            print(Fore.RED + 'Wrong Credentials.. Exiting..')
            print(Style.RESET_ALL)
            sys.exit(0)
    else:
        print("Waiting for completing authentication mechanism.. ")
        json_req = request.get_adv_auth_json_poll()
        while (True):
            authresp = call_rest_post(endpoint, method, json_req, headers, certpath, proxy, environment.get_debug())
            resp = AuthResponse(authresp, endpoint)
            success_result = resp.get_success_result()
            summary = resp.get_summary()
            logging.info("Success : " + str(success_result) + " Summary : " + summary)
            if (success_result == True and summary != "OobPending"):
                break
            if (success_result != True):
                break
    result.append(authresp)
    result.append(success_result)
    result.append(summary)
        

def handle_text(mechanism, tenant_response, username, endpoint, method, proxy, environment):
    certpath = environment.get_certpath()
    mechanism_id = mechanism['MechanismId']
    session_id = tenant_response.get_sessionid()
    tenant_id = tenant_response.get_tenantid()
    passwd = getpass(mechanism['PromptSelectMech'] + " : ")
    request = AdvAuthRequest(tenant_id, session_id, mechanism_id, passwd)
    json_req = request.get_adv_auth_json_passwd()
    headers = {}
    authresp = call_rest_post(endpoint, method, json_req, headers, certpath, proxy, environment.get_debug())
    authresponse = AuthResponse(authresp, endpoint)
    success_result = authresponse.get_success_result()
    logging.info("Is it Successful : " + str(success_result))
    summary = authresponse.get_summary()
    logging.info(summary)
    if (success_result == False):
        print("Wrong Credentials.. Exiting..")
        sys.exit()
    global result
    result.append(authresp)
    result.append(success_result)
    result.append(summary)

            
def handle_text_oob(mechanism, tenant_response, username, endpoint, method, proxy, environment):
    certpath = environment.get_certpath()
    mechanism_id = mechanism['MechanismId']
    session_id = tenant_response.get_sessionid()
    tenant_id = tenant_response.get_tenantid()
    logging.info("Starting StartTextOob...")
    request = AdvAuthRequest(tenant_id, session_id, mechanism_id, "")
    json_req = request.get_adv_auth_json_startoob()
    headers = {}
    authresp = call_rest_post(endpoint, method, json_req, headers, certpath, proxy, environment.get_debug())
    logging.info("The response is StartOob req" + authresp.text)
    handle_unix(mechanism, tenant_response, username, endpoint, method, environment, proxy, request, json_req)

def advance_auth_for_mech(mechanism, tenant_response, username, endpoint, method, proxy, environment):
    certpath = environment.get_certpath()
    mechanism_id = mechanism['MechanismId']
    session_id = tenant_response.get_sessionid()
    tenant_id = tenant_response.get_tenantid()
    logging.info("The AnswerType is : " + mechanism['AnswerType'])
    if (mechanism['AnswerType'] == "Text" or mechanism['AnswerType'] == "StartTextOob"):
        if (mechanism['AnswerType'] == 'Text'):
            handle_text(mechanism, tenant_response, username, endpoint, method, proxy, environment)
        if (mechanism['AnswerType'] == "StartTextOob"):
            handle_text_oob(mechanism, tenant_response, username, endpoint, method, proxy, environment)
        authresp = result[0]
        success_result = result[1]
        summary = result[2]
        del result[:]
        if (success_result == False):
            logging.info("Authentication is not successful..")
            print("Authentication is not successful..")
            sys.exit()
    elif (mechanism['AnswerType'] == "StartOob"):
        logging.info("StartOob..")
        request = AdvAuthRequest(tenant_id, session_id, mechanism_id, "")
        json_req = request.get_adv_auth_json_startoob()
        headers = {}
        authresp = call_rest_post(endpoint, method, json_req, headers, certpath, proxy, environment.get_debug())
        print(mechanism['PromptSelectMech'] + " Waiting ......")
        json_req = request.get_adv_auth_json_poll()
        while (True):
            sys.stdout.write(".")
            authresp = call_rest_post(endpoint, method, json_req, headers, certpath, proxy, environment.get_debug())
            resp = AuthResponse(authresp, endpoint)
            success_result = resp.get_success_result()
            summary = resp.get_summary()
            if (success_result == True and summary != "OobPending"):
                break
            if (success_result != True):
                break
            time.sleep(2)
        print()
        logging.info("Is it Successful : " + str(success_result))
        logging.info(summary)
    if (success_result == True and summary == "LoginSuccess"):
        session_token = authresp.cookies['.ASPXAUTH']
        logging.info(session_token)
        session = AuthSession(endpoint, username, session_id, session_token)
        return session
    
def elevate(session, appkey, headers, response, version, environment, proxy):
    url = response.url
    parsed_url = urlparse.urlparse(url)
    elav = urlparse.parse_qs(parsed_url.query)['elevate'][0]
    chal = urlparse.parse_qs(parsed_url.query)['challengeId'][0]
    method = "/security/startchallenge"
    message={}
    message['Version']="1.0"
    message['elevate']=elav
    message['ChallengeStateId']=chal
    json_body=json.dumps(message)
    chal_resp = call_rest_post(session.endpoint, method, json_body, headers, environment.get_certpath(), proxy, environment.get_debug())
    auth_resp = AuthResponse(chal_resp, session.endpoint)
    return advance_authentication(auth_resp, session.endpoint, "", "1.0", proxy, environment)
        
def interactive_login(user, version, proxy, environment):
    response = start_authentication(user, version, proxy, environment)
    session = advance_authentication(response, response.tenant_url, user, version, proxy, environment)
    return session
