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

class AuthRequest(object):
    '''
    Message body required for Authentication requests
    '''
    def __init__(self, tenantid, username, version, password=''):
        self.tenantid = tenantid
        self.username = username
        self.version = version
        
    def get_start_auth_json(self):
        message={}
        if (self.tenantid):
            message['TenantId']=self.tenantid
        message['User']=self.username
        message['Version']=self.version
        json_body=json.dumps(message)
        logging.info('--------- Body of Start Authentication Request --------------')
        logging.info(json_body)
        return json_body
    
