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

#Version 8.1
from core import auth
from core import samlapp
from aws import assumerolesaml
import logging
from config import readconfig
from core import uprest
import re
import sys
import argparse
from config import environment
import traceback

def get_environment(args):
    tenant = args.tenant
    if ("." not in tenant):
        tenant = tenant + ".idaptive.app"
    name = tenant.split(".")[0]
    tenant = "https://" + tenant
    #cert = "cacerts_" + name + ".pem"  
    cert = True    # comment this line and uncomment above line to add certificate pinning. Please refer url https://identity-developer.cyberark.com/docs/making-cacertspem
    debug = args.debug
    env = environment.Environment(name, tenant, cert, debug)
    return env
    


def login_instance(proxy, environment):
    user = input('Please enter your username : ')
    version = "1.0"
    session = auth.interactive_login(user, version, proxy, environment)
    return session, user

def set_logging():
    logging.basicConfig(handlers=[logging.FileHandler('aws-cli.log', 'w', 'utf-8')], level=logging.INFO, format='%(asctime)s %(filename)s %(funcName)s %(lineno)d %(message)s')
    logging.info('Starting App..')
    print("Logfile - aws-cli.log")
    

def _get_app_key(app):
    return (app.get("AppKey") or app.get("_RowKey") or "").strip()


def _get_app_display_name(app):
    return (app.get("DisplayName") or app.get("Name") or "").strip()


def select_app(awsapps):
    print("Select the aws app to login. Type 'quit' or 'q' to exit")
    count = 1
    for app in awsapps:
        print(str(count) + " : " + _get_app_display_name(app) + " | " + _get_app_key(app))
        count = count+1
    if (len(awsapps) == 1):
        return "1"
    return input("Enter Number : ")

             
def _is_aws_or_eusc_app(app):
    if app.get("WebAppType") == 'UsernamePassword':
        return False
    template = (app.get("TemplateName") or "").strip()
    display_name = _get_app_display_name(app)
    name = (app.get("Name") or "").strip()
    app_url = (app.get("Url") or "").strip().lower()
    description = (app.get("Description") or "").strip().lower()

    keywords = ("aws", "amazon", "eusc", "sovereign")
    text_fields = (template.lower(), display_name.lower(), name.lower(), description)
    if any(k in field for field in text_fields for k in keywords):
        return True
    if any(domain in app_url for domain in ("amazonaws-eusc.eu", "amazonaws.eu", "signin.aws.amazon.com", "amazonaws.com")):
        return True
    return False


def _matches_requested_app(app, requested):
    if app.get("WebAppType") == 'UsernamePassword':
        return False
    target = requested.strip().lower()
    app_key = _get_app_key(app).lower()
    display_name = (app.get("DisplayName") or "").strip().lower()
    name = (app.get("Name") or "").strip().lower()
    return (
        target == app_key
        or target == display_name
        or target == name
        or target in display_name
        or target in name
    )


DEFAULT_BROWSER_USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
)


def client_main():
    parser = argparse.ArgumentParser(prog="AWSCLI", description="Enter your Identity Provider Credentials and choose AWS Role to create AWS Profile. Use this AWS Profile to run AWS commands.")

    parser.add_argument("-tenant", "-t", help="Enter tenant url or name e.g. cloud.idaptive.com or cloud", default="cloud")
    parser.add_argument("-region", "-r", help="Enter AWS region. Default is us-west-2 (auto-set to eusc-de-east-1 for aws-eusc)", default="us-west-2")
    parser.add_argument("-app", "--app", "-a", help="Select AWS/EUSC app by AppKey or DisplayName (tile name)", default=None)
    parser.add_argument("--list", "-list", "-l", help="List available AWS/EUSC apps and roles", action="store_true")
    parser.add_argument("-useragent", "--user-agent", dest="useragent", nargs="?", const=DEFAULT_BROWSER_USER_AGENT, default=None,
                        help="User-Agent sent when launching the app (handleAppClick). Without a value, a desktop Chrome User-Agent is used. Default is the CLI User-Agent.")
    parser.add_argument("-duration", help="Session duration in seconds for AssumeRoleWithSAML. Default is 3600, max is 43200.", type=int, default=3600)
    parser.add_argument("-debug", "-d", help="This will make debug on", action="store_true")
    parser.add_argument("-version", "-v", action='version', version='Idaptive AWS CLI V1')
    args = parser.parse_args()

    if not (0 <= args.duration):
        parser.error("-duration must be greater than 0 seconds (got {}).".format(args.duration))

    set_logging()
    
    try:
        proxy_obj = readconfig.read_config()
    except:
        logging.info("proxy.properties file not found. Please make sure the files are at home dir of the script.")
        print("proxy.properties file not found. Please make sure the files are at home dir of the script.")
        sys.exit()
    proxy = {}
    if proxy_obj.is_proxy() == 'yes':
        proxy={ 'http':proxy_obj.get_http(), 'https':proxy_obj.get_https(), 'username':proxy_obj.get_user(), 'password':proxy_obj.get_password() }
    environment = get_environment(args)
    session, user = login_instance(proxy, environment)
    
    region = args.region
    duration = args.duration
    
    response = uprest.get_applications(user, session, environment, proxy)
    result = response["Result"]
    logging.info("Result " + str(result))
    apps = result["Apps"]
    logging.info("Apps : " + str(apps))
    length = len(apps)
    awsapps = []
    if args.app:
        target = args.app.strip().lower()
        exact_matches = [
            app for app in apps
            if app.get("WebAppType") != 'UsernamePassword'
            and target in (
                _get_app_key(app).lower(),
                (app.get("DisplayName") or "").strip().lower(),
                (app.get("Name") or "").strip().lower(),
            )
        ]
        if exact_matches:
            awsapps = exact_matches
        else:
            awsapps = [app for app in apps if _matches_requested_app(app, args.app)]
    else:
        for j in range(0, length):
            try:
                if _is_aws_or_eusc_app(apps[j]):
                    appinfo = apps[j]
                    logging.info(appinfo)
                    awsapps.append(appinfo)
            except KeyError:
                continue

    logging.info("AWSapps : " + str(awsapps))
    
    if (len(awsapps) == 0):
        if args.app:
            print("No AWS/SAML Application found matching '" + args.app + "' for user " + user)
        else:
            print("No AWS Applications to select for the user " + user)
        return

    if args.list:
        for app in awsapps:
            appkey = _get_app_key(app)
            display_name = _get_app_display_name(app)
            print(display_name + " | " + appkey)
            encoded_saml = samlapp.call_app(session, appkey, "1.0", environment, proxy, args.useragent)
            if not encoded_saml:
                continue
            roles, providers, _ = samlapp.extract_roles(encoded_saml)
            for idx, role_arn in enumerate(roles):
                print("  Role: " + role_arn + " | Provider: " + providers[idx])
        logging.info("Done")
        logging.shutdown()
        return
    
    pattern = re.compile("[^0-9.]")
    count = 1
    profilecount = [0] * len(awsapps)
    while(True):
        number = select_app(awsapps)
        if (number == ""):
            continue
        if (re.match(pattern, number)):
            print("Exiting..")
            break
        if (int(number) - 1 >= len(awsapps)):
            continue
        
        appkey = _get_app_key(awsapps[int(number)-1])
        display_name = _get_app_display_name(awsapps[int(number)-1])
        print("Calling app with key : " + appkey)
        encoded_saml = samlapp.call_app(session, appkey, "1.0", environment, proxy, args.useragent)
        if not encoded_saml:
            if len(awsapps) == 1:
                break
            continue
        while(True):
            _quit, awsinputs = samlapp.choose_role(encoded_saml, appkey)
            if (_quit == 'q'):
                break;
            count = profilecount [int(number)-1]
            assumed = assumerolesaml.assume_role_with_saml(awsinputs.role, awsinputs.provider, awsinputs.saml, count, display_name, region, duration)
            if (assumed):
                profilecount [int(number)-1] = count + 1
            if (_quit == 'one_role_quit'):
                break

        if (len(awsapps) == 1):
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

