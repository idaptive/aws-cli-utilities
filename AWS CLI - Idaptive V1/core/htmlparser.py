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

from html.parser import HTMLParser

class SamlHtmlParser(HTMLParser):
    '''
    Parser for HTML response received from handleAppClick method
    '''
    _ERROR_CLASSES = ('error-title', 'error-text')

    def __init__(self):
        super().__init__()
        self.reset()
        self.saml = ''
        self.errors = {}
        self._capturing = None

    def handle_starttag(self, tag, attrs):
        self._extract_saml_input(tag, attrs)
        classes = (dict(attrs).get('class') or '').split()
        for error_class in self._ERROR_CLASSES:
            if error_class in classes:
                self._capturing = error_class
                self.errors.setdefault(error_class, '')

    def handle_endtag(self, tag):
        if tag.lower() in ('span', 'div'):
            self._capturing = None

    def handle_data(self, data):
        if self._capturing:
            self.errors[self._capturing] += data

    def handle_startendtag(self, tag, attrs):
        self._extract_saml_input(tag, attrs)

    def _extract_saml_input(self, tag, attrs):
        if tag.lower() != 'input':
            return
        attr_map = {k.lower(): v for k, v in attrs if k}
        input_name = (attr_map.get('name') or '').strip()
        if input_name.lower() == 'samlresponse' and attr_map.get('value'):
            self.saml = attr_map['value']
        
    def get_saml(self):
        return self.saml

    def get_error(self):
        title = ' '.join(self.errors.get('error-title', '').split())
        text = ' '.join(self.errors.get('error-text', '').split())
        return title, text

    def clean(self):
        self.saml = ''
        self.errors = {}
        self._capturing = None