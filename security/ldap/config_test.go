package ldap

import (
	"github.com/dcos/dcos-oauth/security"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestNewConfig(t *testing.T) {
	result, err := NewConfig([]byte(validConfigData))
	assert.NoError(t, err)
	expected := &Config{
		Server: &ServerConfig{
			Host:          "GLOBALAD.CORP.ADOBE.COM",
			Port:          636,
			UseSSL:        true,
			BindDN:        "cn=%s,cn=users,DC=adobenet,DC=global,DC=adobe,DC=com",
			BindPassword:  "",
			SkipVerifySSL: false,
			SearchFilter:  "(cn=%s)",
			SearchBaseDNs: []string{"dc=adobenet,dc=global,dc=adobe,dc=com"},
			Attr: AttributeMap{
				Name:     "givenName",
				Username: "cn",
				Surname:  "sn",
				MemberOf: "memberOf",
				Email:    "mail",
			},
			LdapGroups: []*GroupToOrganizationRole{
				&GroupToOrganizationRole{
					GroupDN: "CN=ORG-RUMARSH-DIRECT,OU=DIRECT_REPORTS,OU=Org_Based_DLs,OU=Exchange_Objects,DC=adobenet,DC=global,DC=adobe,DC=com",
					OrgRole: security.ROLE_ADMIN,
				},
			},
		},
	}
	assert.Equal(t, expected, result)
}

var validConfigData = `
[server]
# Ldap server host
host = "GLOBALAD.CORP.ADOBE.COM"
# Default port is 389 or 636 if use_ssl = true
port = 636
# Set to true if ldap server supports TLS
use_ssl = true
# set to true if you want to skip ssl cert validation
ssl_skip_verify = false

# Search user bind dn
bind_dn = "cn=%s,cn=users,DC=adobenet,DC=global,DC=adobe,DC=com"
# Search user bind password
#bind_password = ''

# Search filter, for example "(cn=%s)" or "(sAMAccountName=%s)"
search_filter = "(cn=%s)"
# An array of base dns to search through
search_base_dns = ["dc=adobenet,dc=global,dc=adobe,dc=com"]

# Specify names of the ldap attributes your ldap uses
[server.attributes]
name = "givenName"
surname = "sn"
username = "cn"
member_of = "memberOf"
email =  "mail"

# Map ldap groups to bert org roles
[[server.group_mappings]]
group_dn = "CN=ORG-RUMARSH-DIRECT,OU=DIRECT_REPORTS,OU=Org_Based_DLs,OU=Exchange_Objects,DC=adobenet,DC=global,DC=adobe,DC=com"
org_role = "Admin"
`
