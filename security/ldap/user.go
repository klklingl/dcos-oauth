package ldap

import (
	"github.com/dcos/dcos-oauth/security"
	"strings"
)

type User struct {
	DN              string
	Username        string
	Email           string
	FirstName       string
	LastName        string
	Membership      []string
	providerType    string
	isAuthenticated bool
}

func (u *User) IsAuthenticated() bool {
	return u.isAuthenticated
}

func (u *User) AuthenticationType() string {
	return u.providerType
}

func (u *User) Name() string {
	return u.Username
}

func (u *User) Identity() security.Identity {
	return u
}

func (u *User) GetRoles() []security.RoleType {
	return []security.RoleType{
		security.ROLE_ADMIN,
	}
}

func (u *User) IsInRole(role string) bool {
	if len(u.Membership) == 0 {
		return false
	}
	for _, r := range u.Membership {
		if r != "" && strings.ToLower(r) == strings.ToLower(role) {
			return true
		}
	}
	return false
}
