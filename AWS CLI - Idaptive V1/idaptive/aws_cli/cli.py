#!/usr/bin/env python
#
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
"""
A number of options can be specified as environmental variables to avoid needing
frequent re-entry on the command-line:

--cert:                         IDAPTIVE_CUSTOM_CA
--region:                       AWS_DEFAULT_REGION
--tenant:                       IDAPTIVE_TENANT
--use-app-name-for-profile:     IDAPTIVE_USE_APP_NAME_FOR_PROFILE
--username:                     IDAPTIVE_USERNAME
"""


import argparse
import logging
import os
import re
import sys
from getpass import getuser

import coloredlogs

from .aws import assumerolesaml
from .aws.util import load_aws_credentials
from .config import environment, readconfig
from .core import auth, samlapp, uprest
from .core.util import safe_input


def get_environment(args):
    tenant = args.tenant
    if "idaptive." not in tenant and "centrify.com" not in tenant:
        tenant = tenant + ".centrify.com"
    name = tenant.split(".")[0]
    tenant = "https://" + tenant
    env = environment.Environment(name, tenant, args.cert, args.debug, args.username)
    return env


def get_proxy_configuration(args):
    proxy = {}

    # We'll search for the proxy properties file in multiple locations and build
    # the combinded configuration.
    # TODO: use the standard HTTPS_PROXY environmental variables

    for filename in (
        os.path.expanduser("~/.config/idaptive-proxy.properties"),
        os.path.expanduser("~/.idaptive-proxy.properties"),
        "proxy.properties",
    ):
        if not os.path.exists(filename):
            continue

        proxy_obj = readconfig.read_config(filename)

        if proxy_obj.is_proxy() == "yes":
            proxy.update(
                {
                    "http": proxy_obj.get_http(),
                    "https": proxy_obj.get_https(),
                    "username": proxy_obj.get_user(),
                    "password": proxy_obj.get_password(),
                }
            )

    return proxy


def login_instance(proxy, environment):
    if not environment.username:
        user = safe_input("Please enter your username : ")
    else:
        user = environment.username

    version = "1.0"
    session = auth.idaptive_interactive_login(user, version, proxy, environment)
    return session, user


def select_app(awsapps):
    print("Select the aws app to login. Type 'quit' or 'q' to exit")
    count = 1
    for app in awsapps:
        print(str(count) + " : " + app["DisplayName"] + " | " + app["AppKey"])
        count = count + 1
    if len(awsapps) == 1:
        return "1"
    return safe_input("Enter Number : ")


class ArgparseSensibleFormatter(
    argparse.RawDescriptionHelpFormatter,
    argparse.ArgumentDefaultsHelpFormatter,
):
    pass


def configure_logging(verbosity, log_filename=None):
    if verbosity > 1:
        desired_level = logging.DEBUG
    elif verbosity > 0:
        desired_level = logging.INFO
    else:
        desired_level = logging.WARNING

    log_format = "%(asctime)s %(filename)s %(funcName)s %(lineno)d %(message)s"

    if sys.stderr.isatty():
        coloredlogs.install(level=desired_level, reconfigure=True, format=log_format)
    else:
        logging.basicConfig(
            handlers=[logging.StreamHandler(stream=sys.stderr)],
            level=desired_level,
            format=log_format,
        )

    if log_filename:
        logging.getLogger().addHandler(logging.FileHandler(log_filename, "w", "utf-8"))

    for handler in logging.getLogger().handlers:
        handler.setLevel(desired_level)


def main():
    parser = argparse.ArgumentParser(
        description="Use Idaptive SSO to populate a local AWS profile"
        " with short-term credentials",
        formatter_class=ArgparseSensibleFormatter,
        epilog=__doc__.strip(),
    )

    parser.add_argument(
        "--username",
        "-u",
        help="Change the username used to authenticate to Idaptive",
        default=os.environ.get("IDAPTIVE_USERNAME", getuser()),
    )
    parser.add_argument(
        "--tenant",
        "-t",
        help="Enter tenant url or name e.g. cloud.idaptive.com or cloud",
        default=os.environ.get("IDAPTIVE_TENANT", "cloud"),
    )
    parser.add_argument(
        "--region",
        "-r",
        help="Enter AWS region. Default is %(default)s",
        default=os.environ.get("AWS_DEFAULT_REGION", "us-west-2"),
    )
    parser.add_argument(
        "--cert",
        "-c",
        help="Use a custom certificate root instead of the standard browser root",
        default=os.environ.get("IDAPTIVE_CUSTOM_CA", None),
    )
    parser.add_argument(
        "--debug", "-d", help="This will make debug on", action="store_true"
    )
    parser.add_argument(
        "--use-app-name-for-profile",
        help="Use the application name for the profile's name",
        action="store_true",
        default=os.environ.get("IDAPTIVE_USE_APP_NAME_FOR_PROFILE", "") == "true",
    )
    parser.add_argument(
        "--renew-all-sessions",
        action="store_true",
        help="Renew sessions for all previously-used profiles",
    )
    parser.add_argument(
        "--log-file",
        type=argparse.FileType("w+"),
        help="Record log in this file along with the console",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        dest="verbosity",
        default=0,
        action="count",
        help="Display more progress information (use multiple times for more detail)",
    )

    args = parser.parse_args()

    configure_logging(args.verbosity, args.log_file)

    proxy = get_proxy_configuration(args)

    environment = get_environment(args)
    session, user = login_instance(proxy, environment)

    region = args.region

    response = uprest.get_applications(user, session, environment, proxy)
    result = response["Result"]
    apps = result["Apps"]

    awsapps = []
    for app in apps:
        if app.get("WebAppType") == "UsernamePassword":
            continue

        template_name = app.get("TemplateName", "")

        if "AWS" in template_name or "Amazon" in template_name:
            awsapps.append(app)

    awsapps.sort(key=lambda i: i["DisplayName"])

    logging.debug("AWSapps: %s", awsapps)

    if not awsapps:
        logging.error("No AWS Applications to select for the user %s", user)
        return

    if args.renew_all_sessions:
        # FIXME: refactor this into a separate method and continue cleaning up
        # the legacy data structures
        config, _ = load_aws_credentials()
        for section in config.sections():
            app_name = config.get(section, "idaptive_application_name", fallback=None)
            role = config.get(section, "idaptive_role", fallback=None)

            if not app_name or not role:
                continue

            logging.info("Renewing %s session as %s" % (app_name, role))

            try:
                app_saml = samlapp.call_app(
                    session, app_name, "1.0", environment, proxy
                )
                saml_providers, all_roles = samlapp.extract_roles_from_encoded_saml(
                    app_saml
                )

                provider = saml_providers[all_roles.index(role)]

                assumerolesaml.assume_role_with_saml(
                    role,
                    provider,
                    app_saml,
                    app_name,
                    region,
                    use_app_name_for_profile=args.use_app_name_for_profile,
                )
            except Exception:
                logging.exception(
                    "Unable to renew session for application %s as %s", app_name, role
                )
    else:
        pattern = re.compile("[^0-9.]")
        count = 1
        profilecount = [0] * len(awsapps)
        while True:
            number = select_app(awsapps)
            if number == "":
                continue
            if re.match(pattern, number):
                break
            if int(number) - 1 >= len(awsapps):
                continue

            appkey = awsapps[int(number) - 1]["AppKey"]
            display_name = awsapps[int(number) - 1]["DisplayName"]
            logging.info("Calling app with key: %s %s", appkey, display_name)
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
                    display_name,
                    region,
                    use_app_name_for_profile=args.use_app_name_for_profile,
                )
                if assumed:
                    profilecount[int(number) - 1] = count + 1
                if _quit == "one_role_quit":
                    break

            if len(awsapps) == 1:
                break


if __name__ == "__main__":
    main()
