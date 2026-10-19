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
from core import accountnames
from aws import assumerolesaml
import base64
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
    

def select_app(awsapps):
    print("Select the aws app to login. Type 'quit' or 'q' to exit")
    count = 1
    for app in awsapps:
        print(str(count) + " : " + app['DisplayName'] + " | " + app['AppKey'])
        count = count+1
    if (len(awsapps) == 1):
        return "1"
    return input("Enter Number : ")

             
def client_main():
    parser = argparse.ArgumentParser(prog="AWSCLI", description="Enter your Identity Provider Credentials and choose AWS Role to create AWS Profile. Use this AWS Profile to run AWS commands.")

    parser.add_argument("-tenant", "-t", help="Enter tenant url or name e.g. cloud.idaptive.com or cloud", default="cloud")
    parser.add_argument("-region", "-r", help="Enter AWS region. Default is us-west-2", default="us-west-2")
    parser.add_argument("-duration", help="Session duration in seconds for AssumeRoleWithSAML. Default is 3600, max is 43200.", type=int, default=3600)
    parser.add_argument("-no-account-names", dest="no_account_names", help="Do not look up account names from the AWS sign-in page. The role menu then shows role ARNs only.", action="store_true")
    parser.add_argument("-app", help="App key of the AWS app to use. Skips the app menu.")
    parser.add_argument("-role", action="append", default=[], metavar="ROLE_ARN", help="Role ARN to assume. Repeat for more roles. Skips the role menu: one login creates a profile for each role.")
    parser.add_argument("-profile-name", dest="profile_name", default=samlapp.DEFAULT_PROFILE_NAME, help="Profile name template. Placeholders: {account} (account name, or ID if unknown), {account_id}, {role}. Default: %(default)s. Example: '{account}-{role}'.")
    parser.add_argument("-debug", "-d", help="This will make debug on", action="store_true")
    parser.add_argument("-version", "-v", action='version', version='Idaptive AWS CLI V1')
    args = parser.parse_args()

    if not (0 <= args.duration):
        parser.error("-duration must be greater than 0 seconds (got {}).".format(args.duration))
    try:
        samlapp.profile_name(args.profile_name, "arn:aws:iam::000000000000:role/check")
    except (KeyError, IndexError, ValueError) as e:
        parser.error("-profile-name has an unknown placeholder: {}".format(e))

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
    for j in range (0, length):
        try:
            appinfo = {}
            template = apps[j].get("TemplateName", "")
            # Match commercial AWS apps AND eusc per-account apps.
            # eusc accounts each have their own Idira app; their template names
            # typically contain "EUSC" or "Sovereign".  They must NOT be accessed
            # via the commercial "AWS Universal IDP" app — each requires its own
            # dedicated app so the SAML assertion carries the correct issuer and
            # arn:aws-eusc: ARNs that the eusc STS will accept.
            is_aws_app = (
                "AWS" in template
                or "Amazon" in template
                or "EUSC" in template
                or "Sovereign" in template
            )
            if is_aws_app and apps[j]["WebAppType"] != 'UsernamePassword':
                appinfo = apps[j]
                logging.info(appinfo)
                awsapps.append(appinfo)
        except KeyError:
            continue

    logging.info("AWSapps : " + str(awsapps))
    
    if (len(awsapps) == 0):
        print("No AWS Applications to select for the user " + user)
        return

    if args.app:
        awsapps = [app for app in awsapps if app['AppKey'] == args.app]
        if not awsapps:
            print("No AWS app with key " + args.app + " is available to the user " + user)
            sys.exit(1)

    if args.role:
        if len(awsapps) > 1:
            print("-role needs a single AWS app. Add -app with one of these keys:")
            for app in awsapps:
                print("  " + app['AppKey'] + " : " + app['DisplayName'])
            sys.exit(1)
        app = awsapps[0]
        encoded_saml = samlapp.call_app(session, app['AppKey'], "1.0", environment, proxy)
        account_names = {}
        if not args.no_account_names:
            account_names = accountnames.get_account_names(
                encoded_saml, base64.b64decode(encoded_saml), environment.get_certpath(), proxy)
        failed = []
        for count, awsinputs in enumerate(samlapp.find_roles(encoded_saml, args.role)):
            name = samlapp.profile_name(args.profile_name, awsinputs.role, account_names)
            if not assumerolesaml.assume_role_with_saml(awsinputs.role, awsinputs.provider, awsinputs.saml,
                                                        count, app['DisplayName'], region, duration, name):
                failed.append(awsinputs.role)
        if failed:
            print("Could not assume: " + ", ".join(failed))
            sys.exit(1)
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
        
        appkey = awsapps[int(number)-1]['AppKey']
        display_name = awsapps[int(number)-1]['DisplayName']
        print("Calling app with key : " + appkey)
        encoded_saml = samlapp.call_app(session, appkey, "1.0", environment, proxy)
        account_names = {}
        if not args.no_account_names:
            account_names = accountnames.get_account_names(
                encoded_saml, base64.b64decode(encoded_saml), environment.get_certpath(), proxy)
        while(True):
            _quit, awsinputs = samlapp.choose_role(encoded_saml, appkey, account_names)
            if (_quit == 'q'):
                break;
            count = profilecount [int(number)-1]
            name = samlapp.profile_name(args.profile_name, awsinputs.role, account_names)
            assumed = assumerolesaml.assume_role_with_saml(awsinputs.role, awsinputs.provider, awsinputs.saml, count, display_name, region, duration, name)
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

