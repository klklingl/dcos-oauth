package ldap

import (
	"github.com/dcos/dcos-oauth/security"
	"github.com/go-ldap/ldap"
)

type Provider struct {
	name              string
	server            *ServerConfig
	conn              *ldap.Conn
	requireSecondBind bool
}

func NewProvider(conf *Config) *Provider {
	return &Provider{server: conf.Server}
}

func (a *Provider) Name() string {
	return a.name
}

func (a *Provider) Initialize(name string) error {
	a.name = name
	return a.dial()
}

func (a *Provider) Close() {
	defer a.conn.Close()
}

func (a *Provider) GetUser(un string) (security.Principal, error) {
	user, err := a.searchForUser(un)
	if err != nil {
		return nil, err
	}
	return a.mapToOrgUser(user), nil
}

func (a *Provider) GetUserByEmail(email string) (security.Principal, error) {
	user, err := a.searchForUserByEmail(email)
	if err != nil {
		return nil, err
	}
	return a.mapToOrgUser(user), nil
}

func (a *Provider) ValidateUser(un, pwd string) (security.Principal, error) {
	if pwd == "" {
		return nil, security.ErrInvalidCredentials
	}
	user, err := a.validateUser(un, pwd)
	if err != nil {
		return nil, err
	}
	return a.mapToOrgUser(user), nil
}
