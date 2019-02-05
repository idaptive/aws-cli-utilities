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

class AuthResponse(object):
    '''
    Authentication Response received
    '''
    def __init__(self, response, tenant_url):
        self.response = response
        self.tenant_url = tenant_url
        json_resp = json.loads(self.response.text)
        logging.info('------ Json Response from the REST call ---------')
        logging.info(json_resp)
        logging.info('--------------------------------------------------')
        
                
    def get_success_result(self):
        json_resp = json.loads(self.response.text)
        success_result = json_resp['success']
        return success_result

    def get_tenant_url(self):
        json_resp = json.loads(self.response.text)
        tenant_url = json_resp['Result']['PodFqdn']
        return tenant_url   
    
    def get_mechanism(self):
        json_resp = json.loads(self.response.text)
        challenges = json_resp['Result']['Challenges']
        mechanisms = challenges[0]
        a_mechanism = mechanisms['Mechanisms']
        return a_mechanism
    
    def get_challenges(self):
        json_resp = json.loads(self.response.text)
        return json_resp['Result']['Challenges']

    def get_tenantid(self):
        json_resp = json.loads(self.response.text)
        tenant_id = json_resp['Result']['TenantId']
        return tenant_id
    
    def get_sessionid(self):
        json_resp = json.loads(self.response.text)
        session_id = json_resp['Result']['SessionId']
        return session_id
    
    def get_mechanismid(self):
        json_resp = json.loads(self.response.text)
        challenges = json_resp['Result']['Challenges']
        mechanisms = challenges[0]
        a_mechanism = mechanisms['Mechanisms']
        mechanismid = a_mechanism[0]['MechanismId']
        return mechanismid

    def get_summary(self):
        json_resp = json.loads(self.response.text)
        return json_resp['Result']['Summary']
    
    def get_message(self):
        json_resp = json.loads(self.response.text)
        return json_resp['Result']['Message']
        