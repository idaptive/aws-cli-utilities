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

from html.parser import HTMLParser

class SamlHtmlParser(HTMLParser):
    '''
    Parser for HTML response received from handleAppClick method
    '''
    def __init__(self):
        super().__init__()
        self.reset()
        self.saml = ''
        
    def handle_startendtag(self, tag, attrs):
        if (tag == 'input'):
            for attr in attrs:
                if (attr[0] == 'name' and attr[1] == 'TARGET'):
                    break
                if (attr[0] == 'value'):
                    saml = attr[1]
                    self.saml = saml
        
    def get_saml(self):
        return self.saml
    
    def clean(self):
        self.saml = ''