# Update User Role
Prisma SDWAN script to update user role. Currently this script only supports base roles

#### Synopsis
This script accepts user email and new role that needs to be assigned to an already configured user on Prisma SDWAN.

#### Requirements
* Active CloudGenix Account
* Python >=3.6
* Python modules:
    * CloudGenix Python SDK >= 6.0.1b1 - <https://github.com/CloudGenix/sdk-python>

#### License
MIT

#### Installation:
 - **Github:** Download files to a local directory, manually run `updaterole.py` 

### Usage:
Update user role to super
```
./updaterole.py -UE user@domain.com -UR super 
```

Help Text:
```angular2
TanushreeMacBookPro:updaterole tanushreekamath$ ./updaterole.py -h
usage: updaterole.py [-h] [--controller CONTROLLER] [--email EMAIL] [--pass PASS] [--sdkdebug SDKDEBUG] [--useremail USEREMAIL] [--userrole USERROLE]

Update User Role.

optional arguments:
  -h, --help            show this help message and exit

API:
  These options change how this program connects to the API.

  --controller CONTROLLER, -C CONTROLLER
                        Controller URI, ex. C-Prod: https://api.elcapitan.cloudgenix.com

Login:
  These options allow skipping of interactive login

  --email EMAIL, -E EMAIL
                        Use this email as User Name instead of prompting
  --pass PASS, -P PASS  Use this Password instead of prompting

Debug:
  These options enable debugging output

  --sdkdebug SDKDEBUG, -D SDKDEBUG
                        Enable SDK Debug output, levels 0-2

Config:
  These options are to assign a new role to the user

  --useremail USEREMAIL, -UE USEREMAIL
                        Enter User Email
  --userrole USERROLE, -UR USERROLE
                        Allowed values: viewonly, nwadin, secadmin, iam, super
TanushreeMacBookPro:updaterole tanushreekamath$

```

#### Version
| Version | Build | Changes |
| ------- | ----- | ------- |
| **1.0.0** | **b1** | Initial Release. |


#### For more info
 * For more information on Prisma SDWAN Python SDK, go to https://developers.cloudgenix.com
 
