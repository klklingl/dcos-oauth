// Package security defines what membership providers should look like
package security

import (
	"errors"
)

var (
	ErrInvalidCredentials = errors.New("Invalid username or password")
)

type Provider interface {
	Initialize(name string) error
	Close()
}

// MembershipProvider defines a membership management service
type MembershipProvider interface {
	Provider
	Name() string
	GetUser(un string) (Principal, error)
	GetUserByEmail(email string) (Principal, error)
	ValidateUser(un string, pw string) (Principal, error)
}

// RoleProvider defines a role management service
type RoleProvider interface {
	Provider
	GetRolesForUser(un string) ([]string, error)
	FindUsersInRole(rn string) ([]string, error)
	IsUserInRole(un, rn string) (bool, error)
}

// Principal combines a users identity with the authorized roles they have in a
// given security context.
type Principal interface {
	Identity() Identity
	GetRoles() []RoleType
	IsInRole(string) bool
}

// Identity represents a users authenticated identity.
type Identity interface {
	AuthenticationType() string
	IsAuthenticated() bool
	Name() string
}
