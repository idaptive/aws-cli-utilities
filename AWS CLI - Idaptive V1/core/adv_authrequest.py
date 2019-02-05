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

import json
import logging

class AdvAuthRequest(object):
    '''
    Request object for advanced authentication
    '''
    def __init__(self, tenant_id, session_id, mechanism_id, password):
        self.tenant_id = tenant_id
        self.session_id = session_id
        self.mechanism_id = mechanism_id
        self.password = password
        logging.info('--------- Creating Adv Authentiation Request ----------')
        logging.info("Tenant " + tenant_id + " Session " + session_id + " Mechanism " + mechanism_id)
        
    def get_adv_auth_json_passwd(self):
        message = {}
        message['TenantId'] = self.tenant_id
        message['SessionId'] = self.session_id
        message['MechanismId'] = self.mechanism_id
        message['Action'] = "Answer"
        message['Answer'] = self.password
        json_body=json.dumps(message)
        logging.info('---------- Advance Authentication Passwd Request JSON body ------------')
        return json_body
    
    def get_adv_auth_json_startoob(self):
        message = {}
        message['TenantId'] = self.tenant_id
        message['SessionId'] = self.session_id
        message['MechanismId'] = self.mechanism_id
        message['Action'] = "StartOOB"
        json_body=json.dumps(message)
        logging.info('---------- Advance Authentication StartOOB Request JSON body ------------')
        return json_body
    
    def get_adv_auth_json_poll(self):
        message = {}
        message['TenantId'] = self.tenant_id
        message['SessionId'] = self.session_id
        message['MechanismId'] = self.mechanism_id
        message['Action'] = "Poll"
        json_body=json.dumps(message)
        logging.info('---------- Advance Authentication StartOOB Request JSON body ------------')
        return json_body
