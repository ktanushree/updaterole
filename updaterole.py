#!/usr/bin/env python
"""
Prisma SDWAN script to update user role
tkamath@paloaltonetworks.com
"""
import sys
import os
import argparse
import cloudgenix

SCRIPT_NAME = "Update User Role"
SCRIPT_VERSION = "v1.0"


# Import CloudGenix Python SDK
try:
    import cloudgenix
except ImportError as e:
    cloudgenix = None
    sys.stderr.write("ERROR: 'cloudgenix' python module required. (try 'pip install cloudgenix').\n {0}\n".format(e))
    sys.exit(1)

# Check for cloudgenix_settings.py config file in cwd.
sys.path.append(os.getcwd())
try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # if cloudgenix_settings.py file does not exist,
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

try:
    # Also, separately try and import USERNAME/PASSWORD from the config file.
    from cloudgenix_settings import CLOUDGENIX_USER, CLOUDGENIX_PASSWORD

except ImportError:
    # will get caught below
    CLOUDGENIX_USER = None
    CLOUDGENIX_PASSWORD = None


# Handle differences between python 2 and 3. Code can use text_type and binary_type instead of str/bytes/unicode etc.
if sys.version_info < (3,):
    text_type = unicode
    binary_type = str
else:
    text_type = str
    binary_type = bytes


def cleanexit(cgx_session):
    print("INFO: Logging Out")
    cgx_session.get.logout()
    sys.exit()

role_map = {
    "viewonly": {"name": "tenant_viewonly"},
    "nwadmin": {"name": "tenant_network_admin"},
    "secadmin": {"name": "tenant_security_admin"},
    "super": {"name": "tenant_super"},
    "iam": {"name": "tenant_iam_admin"}
}

def go():
    """
    Stub script entry point. Authenticates CloudGenix SDK, and gathers options from command line to run do_site()
    :return: No return
    """

    #############################################################################
    # Begin Script, parse arguments.
    ############################################################################

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default=None)

    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of prompting",
                             default=None)
    login_group.add_argument("--pass", "-P", help="Use this Password instead of prompting",
                             default=None)

    # Debug Settings
    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--sdkdebug", "-D", help="Enable SDK Debug output, levels 0-2", type=int,
                             default=0)

    # Config Settings
    config_group = parser.add_argument_group('Config', 'These options are to assign a new role to the user')
    config_group.add_argument("--useremail", "-UE", help="Enter User Email", default=None)
    config_group.add_argument("--userrole", "-UR", help="Allowed values: viewonly, nwadin, secadmin, iam, super",
                              default="super")

    ############################################################################
    # Parse arguments provided via CLI
    ############################################################################
    args = vars(parser.parse_args())
    sdk_debuglevel = args["sdkdebug"]
    useremail = args["useremail"]
    userrole = args["userrole"]

    if useremail is None:
        print("ERR: Invalid email. Please provide a valid email")
        sys.exit()

    if userrole not in ["viewonly", "nwadmin", "secadmin", "iam", "super"]:
        print("ERR: Invalid Role. Please choose from: viewonly, nwadin, secadmin, iam, super")
        sys.exit()

    ############################################################################
    # Instantiate API & Login
    ############################################################################
    cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=False)
    cgx_session.set_debug(sdk_debuglevel)
    print("{0} v{1} ({2})\n".format(SCRIPT_NAME, cgx_session.version, cgx_session.controller))

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # figure out user
    if args["email"]:
        user_email = args["email"]
    elif CLOUDGENIX_USER:
        user_email = CLOUDGENIX_USER
    else:
        user_email = None

    # figure out password
    if args["pass"]:
        user_password = args["pass"]
    elif CLOUDGENIX_PASSWORD:
        user_password = CLOUDGENIX_PASSWORD
    else:
        user_password = None

    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["pass"]:
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit()

    else:
        while cgx_session.tenant_id is None:
            cgx_session.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not cgx_session.tenant_id:
                user_email = None
                user_password = None

    ############################################################################
    # Update User Role
    ############################################################################
    print("INFO: Getting configured users..")
    resp = cgx_session.get.operators_t()
    if resp.cgx_status:
        operators = resp.cgx_content.get("items", None)
        userfound = False
        for op in operators:
            if op["email"] == useremail:
                userfound = True
                print("INFO: User found. Updating role to {}".format(userrole))
                rolval = role_map[userrole]
                op["roles"] = [rolval]

                resp = cgx_session.patch.operators_t(operator_id=op["id"], data=op)
                if resp.cgx_status:
                    print("Role updated!")
                else:
                    print("ERR: Could not update role for user {} to {}.".format(useremail, userrole))
                    cloudgenix.jd_detailed(resp)

        if not userfound:
            print("ERR: User with email {} does not exist".format(useremail))
            cloudgenix.jd_detailed(resp)

    else:
        print("ERR: Could not retrieve operators")
        cloudgenix.jd_detailed(resp)


    ############################################################################
    # Logout to clear session.
    ############################################################################
    cleanexit(cgx_session)


if __name__ == "__main__":
    go()
