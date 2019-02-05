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

import logging

class Environment(object):

    def __init__(self, name, endpoint, certpath, debug):
        self.name = name
        self.endpoint = endpoint
        self.certpath = certpath
        self.debug = debug
        self.applications = []
        
        
    def log(self):
        logging.info('--------- Environment -----------')
        logging.info(self.name)
        logging.info(self.endpoint)
        logging.info(self.certpath)
        for application in self.applications:
            application.log_application()
        
    def get_name(self):
        return self.name
    
    def get_endpoint(self):
        return self.endpoint
    
    def get_certpath(self):
        return self.certpath
    
    def get_debug(self):
        return self.debug
    
    def get_apps_properties(self):
        return self.apps_properties
    
    def get_applications(self):
        return self.applications
    
    def set_applications(self, applications):
        self.applications = applications