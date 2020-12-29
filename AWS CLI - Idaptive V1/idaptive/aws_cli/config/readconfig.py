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


import configparser

from . import proxy


def read_proxy(config_file):
    file_reader = configparser.ConfigParser()
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


def read_config(config_file):
    proxy = read_proxy(config_file)
    log_config(proxy)
    return proxy
