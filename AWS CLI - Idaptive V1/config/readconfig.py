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

import base64
import configparser
import logging
from getpass import getpass

from config import apps, environment, proxy


def set_logging():
    logging.basicConfig(filename="config.log", level=logging.INFO)
    logging.info("Starting App..")


def read_proxy():
    file_reader = configparser.ConfigParser()
    config_file = "proxy.properties"
    file_reader.read(config_file)
    isproxy = file_reader["Proxy"]["proxy"]
    http_proxy = file_reader["Proxy"]["http_proxy"]
    https_proxy = file_reader["Proxy"]["https_proxy"]
    proxy_user = file_reader["Proxy"]["proxy_user"]
    proxy_password = file_reader["Proxy"]["proxy_password"]
    proxy_object = proxy.Proxy(
        isproxy, http_proxy, https_proxy, proxy_user, proxy_password
    )
    return proxy_object


def log_config(proxy):
    proxy.log()


def read_config():
    proxy = read_proxy()
    log_config(proxy)
    return proxy
