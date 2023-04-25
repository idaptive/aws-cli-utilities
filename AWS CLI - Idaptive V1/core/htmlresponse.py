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


import logging

from core.htmlparser import SamlHtmlParser


class HtmlResponse(object):
    """
    Html Response from handle app click which consists of SAML
    """

    def __init__(self, html_response):
        self.html_response = html_response
        self.saml = ""

    def get_saml(self):
        htmlparser = SamlHtmlParser()
        htmlparser.feed(self.html_response)
        saml = htmlparser.get_saml()
        htmlparser.clean()
        logging.debug("------------ SAML ---------------")
        logging.debug(saml)
        return saml
