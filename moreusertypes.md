## Additional user types

Two additional user types have been added to dcos-oauth to authorize access to a cluster using either LDAP credentials or cluster defined local user credentials for authentication. These user types mirror the behavior of Oauth users already defined by dcos-oauth but use separate URLs to log in.

Environment variables control whether or not these additional user types are enabled for a cluster.

Environment variable | Values | Description
------------ | ------------ | -------------
OAUTH_ALLOW_LDAP_USERS | expects true or false, defaults to false | When true, LDAP users may be authorized to access the cluster
OAUTH_ALLOW_LOCAL_USERS | expects true or false, defaults to false | When true, local users may be authorized to access the cluster

### Managing list of authorized users
A RESTful interface is available on each DCOS master for managing the list of authorized LDAP and local users. In order to get responses to these requests the user making the request must already be authorized on the cluster.

#### LDAP users
Request Type | \<master\>/acs/api/v1/ldapusers | \<master\>/acs/api/v1/ldapusers/{uid:.*}
------------ | ------------ | -------------
POST | Add an LDAP user to the list. Include username in the body {"username":"\<username\>"} | Add URL specified LDAP user ('uid') to the list. A username in the body overrides 'uid' in the URL
PUT | N/A | N/A
GET | Show list of authorized LDAP users | Show whether or not LDAP user 'uid' is authorized
DELETE | N/A | Remove LDAP user 'uid' from the list

#### Local users
Request Type | \<master\>/acs/api/v1/localusers | \<master\>/acs/api/v1/localusers/{uid:.*}
------------ | ------------ | -------------
POST | Add a local user to the list. Include username and password in the body {"username":"\<username\>", "newpassword":"\<password\>"} | Add URL specified LDAP user ('uid') to the list. A username in the body overrides 'uid' in the URL. Include password in the body {"newpassword":"\<password\>"}. Password must have at least 12 characters
PUT | N/A | Change the password for local user 'uid'. Include old password and new password in the body {"oldpassword":"\<password\>", "newpassword":"\<password\>"}. New password must have at least 12 characters
GET | Show list of authorized local users | Show whether or not local user 'uid' is authorized
DELETE | N/A | Remove local user 'uid' from the list

### Logging in to the cluster

The following URLs are used to log in to the cluster and receive an authorization token. This will also set DCOS expected cookies in the browser.

User Type | URL
------------ | ------------
LDAP users | \<master\>/acs/api/v1/auth/ldaplogin
Local users | \<master\>/acs/api/v1/auth/locallogin

Basic Auth is used to prompt for username and password. Once provided, the user is authenticated using LDAP credentials or the bcrypt hash stored for the local user.

Once authenticated, a check is made to ensure that the user is authorized on the cluster.

By default, LDAP users are automatically added to the list of authorized LDAP users during login if they are in an LDAP group that has been granted access to the cluster. Another option is to specifically manage a "whitelist" of authorized LDAP users. In either case, LDAP authentication is accomplished using a .toml configuration file that provides LDAP access information and optional group control.

For local users, the specified user must be in the list of authorized local users or be a special "default local user" defined for the cluster.

Also for local users, too many recent failed login attempts will result in that user being unable to log in to the cluster for a specified lockout period. Currently 6 failed attempts in the previous 5 minutes will result in a 30 minute lockout.

### Additional Environment variables

Environment variable | Values | Description
------------ | ------------ | -------------
OAUTH_LDAP_CONFIG_FILE | expects full path and filename, defaults to '/etc/ethos/ldap.toml' | The .toml configuration file that provides LDAP access information
OAUTH_LDAP_WHITELIST_ONLY | expects true or false, defaults to false | When true, LDAP users must be in the authorized LDAP users list to gain access to the cluster
OAUTH_LDAP_GROUPS_ONLY | expects true or false, defaults to false | When true, LDAP users must be in an LDAP group that has an admin role for the cluster to gain access to the cluster even if the user is in the authorized LDAP users list
OAUTH_DEFAULT_LOCAL_USER | expects string matching regex \`^[a-zA-Z0-9._-]{2,}$\`, defaults to "" | The only authorized local user when no local users have been added to the list. When specified, the default DCOS behavior of automatically authorizing the first Oauth user to log in to the cluster is ignored
OAUTH_DEFAULT_LOCAL_USER_HASH | expects a bcrypt hash or a plain text password | The "password" initially associated with the default local user.  This is required when OAUTH_DEFAULT_LOCAL_USER is specified. For security when using a plain text password, the password should be considered temporary and should be changed using PUT decribed above as soon as the cluster is up
OAUTH_ADMIN_GROUPS_FILE | expects full path and filename, defaults to "" | The CSV file that provides a list of Oauth groups with an admin role for the cluster. When not specified Oauth group checking is ignored which means that only Oauth users that have been specifically added to the Oauth authorized users list can access the cluster
OAUTH_LDAP_CHECK_ON_OAUTH | expects true or false, defaults to false | When true, Oauth users must be in an LDAP group (looked up by email) that has an admin role for the cluster to gain access to the cluster

### LDAP .toml configuration file

The following is sample content of a .toml file to configure LDAP access. A properly constructed configuation file must be found on master servers at the location specified by OAUTH_LDAP_CONFIG_FILE (default: /etc/ethos/ldap.toml) to allow LDAP access.

```
[server]
# Ldap server host
host = "HOST.COMPANY.COM"
# Default port is 389 or 636 if use_ssl = true
port = 636
# Set to true if ldap server supports TLS
use_ssl = true
# set to true if you want to skip ssl cert validation
ssl_skip_verify = false

# Search user bind dn
bind_dn = "cn=%s,cn=users,DC=companynet,DC=global,DC=company,DC=com"
# Search user bind password
#bind_password = ''

# Email filter, for example "(mail=%s)"
email_filter = "(mail=%s)"
# Search filter, for example "(cn=%s)" or "(sAMAccountName=%s)"
search_filter = "(cn=%s)"
# An array of base dns to search through
search_base_dns = ["dc=companynet,dc=global,dc=company,dc=com"]

# Default role for users who are not members of groups below
#default_role = "Admin"
default_role = ""

# Specify names of the ldap attributes your ldap uses
[server.attributes]
name = "givenName"
surname = "sn"
username = "cn"
member_of = "memberOf"
email =  "mail"

# Map ldap groups to org roles
[[server.group_mappings]]
group_dn = "CN=ORG-DIRECT,OU=DIRECT_REPORTS,OU=Org_Based_DLs,OU=Exchange_Objects,DC=companynet,DC=global,DC=company,DC=com"
org_role = "Admin"

[[server.group_mappings]]
group_dn = "CN=ORG-OTHER,OU=DIRECT_REPORTS,OU=Org_Based_DLs,OU=Exchange_Objects,DC=companynet,DC=global,DC=company,DC=com"
org_role = "Admin"
```