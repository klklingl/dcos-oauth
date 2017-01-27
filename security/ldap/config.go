package ldap

import (
	"github.com/dcos/dcos-oauth/security"
	"github.com/BurntSushi/toml"
	"io/ioutil"
)

func NewConfig(data []byte) (conf *Config, err error) {
	_, err = toml.Decode(string(data), &conf)
	return
}

type Config struct {
	Server *ServerConfig `toml:"server"`
}

type ServerConfig struct {
	Host          string       `toml:"host"`
	Port          int          `toml:"port"`
	UseSSL        bool         `toml:"use_ssl"`
	SkipVerifySSL bool         `toml:"ssl_skip_verify"`
	BindDN        string       `toml:"bind_dn"`
	BindPassword  string       `toml:"bind_password"`
	Attr          AttributeMap `toml:"attributes"`
	EmailFilter   string       `toml:"email_filter"`
	SearchFilter  string       `toml:"search_filter"`
	SearchBaseDNs []string     `toml:"search_base_dns"`
	DefaultRole   string       `toml:"default_role"`

	LdapGroups []*GroupToOrganizationRole `toml:"group_mappings"`
}

type AttributeMap struct {
	Username string `toml:"username"`
	Name     string `toml:"name"`
	Surname  string `toml:"surname"`
	Email    string `toml:"email"`
	MemberOf string `toml:"member_of"`
}

type GroupToOrganizationRole struct {
	GroupDN string            `toml:"group_dn"`
	OrgRole security.RoleType `toml:"org_role"`
}

func ConfigFromFile(filename string) (*Config, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return NewConfig(data)
}
