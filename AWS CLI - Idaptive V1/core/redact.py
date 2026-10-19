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

"""Remove secrets from values before they are written to the log file.

The log must never hold the password or OTP ("Answer"), the session token
("Auth", the .ASPXAUTH cookie, the Authorization header), or the SAML
assertion. Any of these lets the reader log in as the user.
"""

import json

REDACTED = '***'

# JSON keys whose values are secrets, compared case-insensitively.
# Answer: the password or OTP in AdvanceAuthentication requests.
# Auth: the session token in a LoginSuccess response.
SECRET_KEYS = {'answer', 'auth', 'samlresponse'}
# Any key that contains one of these is also a secret, e.g. "AccessToken".
SECRET_KEY_PARTS = ('token', 'password', 'secret')

SECRET_HEADERS = {'authorization', 'cookie', 'set-cookie'}


def is_secret_key(key):
    key = str(key).lower()
    return key in SECRET_KEYS or any(part in key for part in SECRET_KEY_PARTS)


def redact_json(value):
    """Return a copy of a decoded JSON value with secret values replaced."""
    if isinstance(value, dict):
        return {key: REDACTED if is_secret_key(key) else redact_json(item)
                for key, item in value.items()}
    if isinstance(value, list):
        return [redact_json(item) for item in value]
    return value


def redact_body(body):
    """Return a request or response body that is safe to log.

    A JSON body is logged with secret values replaced. Any other body (for
    example the handleAppClick HTML, which holds the SAML assertion) is
    logged as its length only.
    """
    if isinstance(body, (dict, list)):
        return json.dumps(redact_json(body))
    if isinstance(body, bytes):
        body = body.decode('utf-8', 'replace')
    if not body:
        return repr(body)
    try:
        return json.dumps(redact_json(json.loads(body)))
    except (TypeError, ValueError):
        return '<non-JSON body, {} characters, not logged>'.format(len(body))


def redact_headers(headers):
    """Return a copy of a headers dict with credential headers replaced."""
    return {key: REDACTED if str(key).lower() in SECRET_HEADERS else value
            for key, value in (headers or {}).items()}
