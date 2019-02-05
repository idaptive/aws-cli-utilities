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

class Proxy(object):

    def __init__(self, isproxy, proxy_http, proxy_https, proxy_user, proxy_password):
        self.isproxy = isproxy
        self.proxy_http = proxy_http
        self.proxy_https = proxy_https
        self.proxy_user = proxy_user
        self.proxy_password = proxy_password
        
        
    def log(self):
        logging.info('------  Proxy -------')
        logging.info(self.isproxy)
        logging.info(self.proxy_http)
        logging.info(self.proxy_https)
        logging.info(self.proxy_user)
        logging.info('********')
        
    def is_proxy(self):
        return self.isproxy
    
    def get_http(self):
        return self.proxy_http
    
    def get_https(self):
        return self.proxy_https
    
    def get_user(self):
        return self.proxy_user
    
    def get_password(self):
        return self.proxy_password