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

import requests
import logging
import sys, traceback, trace
from colorama import Fore, Back, Style
    
def call_rest_post(endpoint, method, body, headers, certpath, proxy, debug):
    endpoint = endpoint+method
    if 'x-centrify-native-client' not in headers:
        headers['x-centrify-native-client'] = "true"
    if 'content-type' not in headers:
        headers['content-type'] = "application/json"
    if 'cache-control' not in headers:
        headers['cache-control'] = "no-cache"

    logging.info("Calling " + endpoint + " with headers : " + str(headers))
    if (debug):
        logging.info("Request : " + str(body))
    
    try :
        response = requests.post(endpoint, headers=headers, verify=certpath, proxies=proxy, data=body)
    except Exception as e :
        logging.exception('Error in calling ' + endpoint + ' - ')
        print(Fore.RED + 'Error in calling ' + endpoint + ' - Please refer logs. ')
        print(Style.RESET_ALL)
        sys.exit(0)
    
    logging.info("Received Response : " + response.text)
    return response

#Following method is not used currently. It will be used if redirects are needed.
def call_rest_post_redirect(endpoint, method, body, headers, certpath, proxy, allow_redirects=True):
    if 'x-centrify-native-client' not in headers:
        headers['x-centrify-native-client'] = "true"
    if 'content-type' not in headers:
        headers['content-type'] = "application/json"
    if 'cache-control' not in headers:
        headers['cache-control'] = "no-cache"
    endpoint = endpoint+method
    logging.info("Calling " + endpoint)
    logging.info("Method : " + method + " Request Body : " + str(body) + " Headers : " + str(headers) + " Proxy : " + str(proxy))
    logging.info("Calling " + endpoint + " with headers : " + str(headers) + " and data : " + str(body))
    response = requests.post(endpoint, headers=headers, verify=certpath, proxies=proxy, data=body)
    logging.info("Received Response : " + response.text)
    return response
    