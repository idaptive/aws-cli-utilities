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

from . import restclient


def get_applications(user, session, environment, proxy):
    method = "/uprest/getupdata"
    body = {}
    headers = {}
    headers["X-CENTRIFY-NATIVE-CLIENT"] = "true"
    headers["Content-type"] = "application/json"
    session_token = "Bearer " + session.session_token
    headers["Authorization"] = session_token
    response = restclient.call_rest_post(
        session.endpoint,
        method,
        body,
        headers,
        environment.get_certpath(),
        proxy,
        environment.get_debug(),
    )
    logging.debug(response.text)
    return response.json()
