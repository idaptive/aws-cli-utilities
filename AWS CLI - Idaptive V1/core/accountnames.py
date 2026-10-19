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

"""Look up AWS account names for the role menu.

The SAML assertion contains role ARNs only. The AWS sign-in page that the
browser shows after SAML login lists each account as
"Account: <alias> (<account id>)". This module posts the assertion to that
page and reads the names.

This is the same page and the same markup that saml2aws reads
(div.saml-account-name). The lookup is best effort: any failure returns an
empty map, and the menu then shows ARNs only, as before.
"""

import logging
import re
import xml.etree.ElementTree as ET
from html.parser import HTMLParser

import requests

_SAML_PROTOCOL_NS = '{urn:oasis:names:tc:SAML:2.0:protocol}'
_SAML_ASSERTION_NS = '{urn:oasis:names:tc:SAML:2.0:assertion}'
_ACCOUNT_RE = re.compile(r'^Account:\s*(?:(?P<alias>.*?)\s*\()?(?P<id>\d{12})\)?\s*$')
_TIMEOUT_SECONDS = 15


class _AccountNameParser(HTMLParser):
    """Collect the text of every <div class="saml-account-name">."""

    def __init__(self):
        super().__init__()
        self.names = []
        self._depth = 0
        self._text = []

    def handle_starttag(self, tag, attrs):
        if self._depth:
            if tag == 'div':
                self._depth += 1
            return
        if tag == 'div' and 'saml-account-name' in (dict(attrs).get('class') or '').split():
            self._depth = 1
            self._text = []

    def handle_endtag(self, tag):
        if self._depth and tag == 'div':
            self._depth -= 1
            if self._depth == 0:
                self.names.append(''.join(self._text).strip())

    def handle_data(self, data):
        if self._depth:
            self._text.append(data)


def parse_account_names(html):
    """Return {account_id: alias} from the AWS sign-in role-picker page.

    An account with no alias ("Account: 123456789012") is left out.
    """
    parser = _AccountNameParser()
    parser.feed(html)
    names = {}
    for text in parser.names:
        match = _ACCOUNT_RE.match(text)
        if match and match.group('alias'):
            names[match.group('id')] = match.group('alias')
    return names


def get_destination(decoded_saml):
    """Return the URL the SAML response is addressed to, or None."""
    root = ET.fromstring(decoded_saml)
    destination = root.get('Destination')
    if destination:
        return destination
    for element in root.iter(_SAML_ASSERTION_NS + 'SubjectConfirmationData'):
        if element.get('Recipient'):
            return element.get('Recipient')
    return None


def get_account_names(encoded_saml, decoded_saml, certpath=True, proxy=None):
    """Post the assertion to its AWS sign-in page and return {account_id: alias}.

    Return an empty map on any failure, so the caller can fall back to ARNs.
    """
    try:
        destination = get_destination(decoded_saml)
        if not destination or not destination.startswith('https://'):
            logging.info('No usable SAML destination; account names not looked up.')
            return {}
        response = requests.post(
            destination,
            data={'SAMLResponse': encoded_saml},
            verify=certpath,
            proxies=proxy or None,
            timeout=_TIMEOUT_SECONDS,
        )
        # Do not log the response body: the page echoes the SAML assertion.
        logging.info('Account name lookup: HTTP %s from %s', response.status_code, destination)
        if response.status_code != 200:
            return {}
        return parse_account_names(response.text)
    except Exception as error:  # best effort only
        logging.info('Account name lookup failed: %s', type(error).__name__)
        return {}
