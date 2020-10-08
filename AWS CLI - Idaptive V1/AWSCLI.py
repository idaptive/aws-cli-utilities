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

import argparse
import logging
import re
import sys
import traceback

from aws import assumerolesaml
from config import environment, readconfig

# Version 8.1
from core import auth, samlapp, uprest


def get_environment(args):
    tenant = args.tenant
    if ("." not in tenant):
        tenant = tenant + ".idaptive.app"
    name = tenant.split(".")[0]
    tenant = "https://" + tenant
    cert = "cacerts_" + name + ".pem"
    debug = args.debug
    env = environment.Environment(name, tenant, cert, debug)
    return env


def login_instance(proxy, environment):
    user = input("Please enter your username : ")
    version = "1.0"
    session = auth.interactive_login(user, version, proxy, environment)
    return session, user


def set_logging():
    logging.basicConfig(
        handlers=[logging.FileHandler("aws-cli.log", "w", "utf-8")],
        level=logging.INFO,
        format="%(asctime)s %(filename)s %(funcName)s %(lineno)d %(message)s",
    )
    logging.info("Starting App..")
    print("Logfile - aws-cli.log")


def select_app(awsapps):
    print("Select the aws app to login. Type 'quit' or 'q' to exit")
    count = 1
    for app in awsapps:
        print(str(count) + " : " + app["DisplayName"] + " | " + app["AppKey"])
        count = count + 1
    if len(awsapps) == 1:
        return "1"
    return input("Enter Number : ")


def client_main():
    parser = argparse.ArgumentParser(
        prog="AWSCLI",
        description="Enter your Identity Provider Credentials and choose AWS Role to create AWS Profile. Use this AWS Profile to run AWS commands.",
    )

    parser.add_argument(
        "-tenant",
        "-t",
        help="Enter tenant url or name e.g. cloud.idaptive.com or cloud",
        default="cloud",
    )
    parser.add_argument(
        "-region",
        "-r",
        help="Enter AWS region. Default is us-west-2",
        default="us-west-2",
    )
    parser.add_argument(
        "-debug", "-d", help="This will make debug on", action="store_true"
    )
    parser.add_argument(
        "-version", "-v", action="version", version="Idaptive AWS CLI V1"
    )
    args = parser.parse_args()

    set_logging()

    try:
        proxy_obj = readconfig.read_config()
    except:
        logging.info(
            "proxy.properties file not found. Please make sure the files are at home dir of the script."
        )
        print(
            "proxy.properties file not found. Please make sure the files are at home dir of the script."
        )
        sys.exit()
    proxy = {}
    if proxy_obj.is_proxy() == "yes":
        proxy = {
            "http": proxy_obj.get_http(),
            "https": proxy_obj.get_https(),
            "username": proxy_obj.get_user(),
            "password": proxy_obj.get_password(),
        }
    environment = get_environment(args)
    session, user = login_instance(proxy, environment)

    region = args.region

    response = uprest.get_applications(user, session, environment, proxy)
    result = response["Result"]
    logging.info("Result " + str(result))
    apps = result["Apps"]
    logging.info("Apps : " + str(apps))
    length = len(apps)
    awsapps = []
    for j in range(0, length):
        try:
            appinfo = {}
            if (
                "AWS" in apps[j]["TemplateName"] or "Amazon" in apps[j]["TemplateName"]
            ) and apps[j]["WebAppType"] != "UsernamePassword":
                appinfo = apps[j]
                logging.info(appinfo)
                awsapps.append(appinfo)
        except KeyError:
            continue

    logging.info("AWSapps : " + str(awsapps))

    if len(awsapps) == 0:
        print("No AWS Applications to select for the user " + user)
        return

    pattern = re.compile("[^0-9.]")
    count = 1
    profilecount = [0] * len(awsapps)
    while True:
        number = select_app(awsapps)
        if number == "":
            continue
        if re.match(pattern, number):
            print("Exiting..")
            break
        if int(number) - 1 >= len(awsapps):
            continue

        appkey = awsapps[int(number) - 1]["AppKey"]
        display_name = awsapps[int(number) - 1]["DisplayName"]
        print("Calling app with key : " + appkey)
        encoded_saml = samlapp.call_app(session, appkey, "1.0", environment, proxy)
        while True:
            _quit, awsinputs = samlapp.choose_role(encoded_saml, appkey)
            if _quit == "q":
                break
            count = profilecount[int(number) - 1]
            assumed = assumerolesaml.assume_role_with_saml(
                awsinputs.role,
                awsinputs.provider,
                awsinputs.saml,
                count,
                display_name,
                region,
            )
            if assumed:
                profilecount[int(number) - 1] = count + 1
            if _quit == "one_role_quit":
                break

        if len(awsapps) == 1:
            break

    logging.info("Done")
    logging.shutdown()


try:
    client_main()
except SystemExit as se:
    print("Program Exited..")
    exc_type, exc_value, exc_traceback = sys.exc_info()
except:
    print("Program Exited due to some error..")
    logging.exception("Program Exited..")
    exc_type, exc_value, exc_traceback = sys.exc_info()
    traceback.print_exception(exc_type, exc_value, exc_traceback)
finally:
    logging.shutdown()
