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

import requests


def call_rest_post(endpoint, method, body, headers, certpath, proxy, debug):
    endpoint = endpoint + method
    if "x-centrify-native-client" not in headers:
        headers["x-centrify-native-client"] = "true"
    if "content-type" not in headers:
        headers["content-type"] = "application/json"
    if "cache-control" not in headers:
        headers["cache-control"] = "no-cache"

    logging.info("Calling %s with headers: %s", endpoint, headers)
    logging.debug("Request: %s", body)

    try:
        response = requests.post(
            endpoint, headers=headers, verify=certpath, proxies=proxy, data=body
        )
    except Exception:
        logging.exception("Error in calling %s ", endpoint)
        raise

    logging.debug("Received Response: %s", response.text)
    return response


# Following method is not used currently. It will be used if redirects are needed.
def call_rest_post_redirect(
    endpoint, method, body, headers, certpath, proxy, allow_redirects=True
):
    if "x-centrify-native-client" not in headers:
        headers["x-centrify-native-client"] = "true"
    if "content-type" not in headers:
        headers["content-type"] = "application/json"
    if "cache-control" not in headers:
        headers["cache-control"] = "no-cache"
    endpoint = endpoint + method
    logging.info("Calling " + endpoint)
    logging.debug(
        "Method : "
        + method
        + " Request Body : "
        + str(body)
        + " Headers : "
        + str(headers)
        + " Proxy : "
        + str(proxy)
    )
    logging.debug(
        "Calling "
        + endpoint
        + " with headers : "
        + str(headers)
        + " and data : "
        + str(body)
    )
    response = requests.post(
        endpoint, headers=headers, verify=certpath, proxies=proxy, data=body
    )
    logging.debug("Received Response %s", response)
    return response
