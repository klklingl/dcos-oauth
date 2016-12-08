package security

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestUserInRole(t *testing.T) {
	u := &User{
		Roles: []RoleType{
			ROLE_ADMIN,
		},
	}
	assert.True(t, u.IsInRole(string(ROLE_ADMIN)))
	assert.False(t, u.IsInRole(string(ROLE_VIEWER)))
}

func TestUserGetRoles(t *testing.T) {
	u := &User{
		Roles: []RoleType{
			ROLE_ADMIN,
			ROLE_VIEWER,
		},
	}
	roles := u.GetRoles()
	expected := []RoleType{
		ROLE_ADMIN,
		ROLE_VIEWER,
	}
	assert.Equal(t, expected, roles)
}

func TestUserIdentity(t *testing.T) {
	u := &User{}
	assert.Exactly(t, u.Identity(), u)
}

func TestGetUsername(t *testing.T) {
	u := &User{
		Username: "testbob",
	}
	assert.Equal(t, u.Name(), "testbob")
}

func TestUserAuthentication(t *testing.T) {
	u := &User{
		providerType: "testprov",
	}
	assert.Equal(t, u.AuthenticationType(), "testprov")
	assert.False(t, u.IsAuthenticated())
}
