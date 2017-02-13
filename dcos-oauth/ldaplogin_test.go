package main

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/context"

	"github.com/stretchr/testify/assert"
	"errors"
	"github.com/coreos/go-oidc/jose"
	"github.com/dcos/dcos-oauth/security"
	"github.com/dcos/dcos-oauth/security/ldap"
)

type testLdapProvider struct {
	initializeErr error
	validateUserErr	error
	isAuthenticated bool
	isInRole bool
	getUserErr error
	getUserByEmailErr error
}

func (t *testLdapProvider) Initialize(name string) error {
	return t.initializeErr
}

func (t *testLdapProvider) Close() {
}

func (t *testLdapProvider) Name() string {
	return "name"
}
func (t *testLdapProvider) GetUser(un string) (security.Principal, error) {
	return t, t.getUserErr
}

func (t *testLdapProvider) GetUserByEmail(email string) (security.Principal, error) {
	return t, t.getUserByEmailErr
}

func (t *testLdapProvider) ValidateUser(un string, pw string) (security.Principal, error) {
	r := t
	if t.validateUserErr != nil {
		r = nil
	}
	return r, t.validateUserErr
}

func (t *testLdapProvider) Identity() security.Identity {
	return t
}

func (t *testLdapProvider) GetRoles() []security.RoleType {
	return nil
}

func (t *testLdapProvider) IsInRole(string) bool {
	return t.isInRole
}

func (t *testLdapProvider) AuthenticationType() string {
	return ""
}

func (t *testLdapProvider) IsAuthenticated() bool {
	return t.isAuthenticated
}

func TestVerifyLdapUser(t *testing.T) {
	aAssert := assert.New(t)
	mockZk := &MockZk{}
	ctx := context.Background()
	ctx = context.WithValue(ctx, "zk", mockZk)
	ctx = context.WithValue(ctx, keyAllowLdapUsers, true)
	var testCase string

	mockZk.rExists.exists = false
	mockZk.rExists.err = errors.New("Exists Error")
	jwtValid, err := jose.ParseJWT("eyJhbGciOiJIUzI1NiIsImtpZCI6InNlY3JldCIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImxvY2FsYWRtaW4iLCJ1aWQiOiJsb2NhbGFkbWluIn0.IH4ZKekBL4J24bLih4YCrhm8ZMT0SLrqJ86o88AJBAk")
	aAssert.Nil(err, "Expecting valid json token to parse without error")

	testCase = "Expecting error when token is invalid"
	jwtInvalid := jwtValid
	jwtInvalid.Payload = []byte("Bad payload")
	aAssert.NotNil(verifyLdapUser(ctx, jwtInvalid), testCase)

	testCase = "Expecting error when Exist function returns an error"
	mockZk.rExists.err = errors.New("Exists Error")
	aAssert.EqualError(verifyLdapUser(ctx, jwtValid), "Exists Error", testCase)

	mockZk.rExists.err = nil

	testCase = "Expecting error when ldap user hasn't already been added"
	mockZk.rExists.exists = false
	aAssert.EqualError(verifyLdapUser(ctx, jwtValid), "No matching ldap user: "+tokenUsername, testCase)

	testCase = "Expecting success when ldap user has already been added"
	mockZk.rExists.exists = true
	aAssert.Nil(verifyLdapUser(ctx, jwtValid), testCase)
}

func TestHandleLdapLogin(t *testing.T) {
	aAssert := assert.New(t)
	mockZk := &MockZk{}
	ctx := context.Background()
	ctx = context.WithValue(ctx, "zk", mockZk)
	ctx = context.WithValue(ctx, "secret-key", "12345")
	unusedUrl := "URL not used in testing"
	provider := &testLdapProvider{}
	var respBody []byte
	var testCase string

	ldapConfig = &ldap.Config{
		Server: &ldap.ServerConfig{
			DefaultRole: "",
		},
	}
	r, _ := http.NewRequest("POST", unusedUrl, nil)
	w := httptest.NewRecorder()
	mockZk.rChildren.children = []string{}
	mockZk.rChildren.err = errors.New("Error")
	mockZk.rExists.exists = false
	mockZk.rExists.err = errors.New("Error")
	mockZk.rGet.bytes = nil
	mockZk.rGet.err = errors.New("Error")
	mockZk.rCreate.err = errors.New("Error")
	ctx = context.WithValue(ctx, keyAllowLdapUsers, false)
	ctx = context.WithValue(ctx, keyLdapWhitelistOnly, false)
	ctx = context.WithValue(ctx, keyLdapGroupsOnly, false)
	provider.initializeErr = errors.New("Error")
	provider.validateUserErr = errors.New("Error")
	provider.isAuthenticated = false
	provider.isInRole = false

	testCase = "Expecting StatusServiceUnavailable error when ldap users aren't allowed"
	ctx = context.WithValue(ctx, keyAllowLdapUsers, false)
	aAssert.Equal("Service Unavailable", handleLdapLogin(ctx, w, r).Title, testCase)

	ctx = context.WithValue(ctx, keyAllowLdapUsers, true)

	testCase = "Expecting StatusUnauthorized error when no BasicAuth header found"
	// Also proves, no error when local users are allowed
	aAssert.Equal("Unauthorized", handleLdapLogin(ctx, w, r).Title, testCase)

	testCase = "Expecting StatusUnauthorized error when username in BasicAuth header is empty"
	// Also proves, no error when BasicAuth header is found
	r.SetBasicAuth("", "anyPass")
	aAssert.Equal("Unauthorized", handleLdapLogin(ctx, w, r).Title, testCase)

	r.SetBasicAuth("anyUser", "anyPass")

	testCase = "Expecting StatusInternalServerError error when newLdapProvider function returns an error"
	newLdapProvider = func(ctx context.Context) (security.MembershipProvider, error) {
		return nil, errors.New("Error")
	}
	aAssert.Equal("Internal Server Error", handleLdapLogin(ctx, w, r).Title, testCase)

	testCase = "Expecting StatusInternalServerError error when Initialize function returns an error"
	provider.initializeErr = errors.New("Error")
	newLdapProvider = func(ctx context.Context) (security.MembershipProvider, error) {
		return provider, nil
	}
	aAssert.Equal("Internal Server Error", handleLdapLogin(ctx, w, r).Title, testCase)

	provider.initializeErr = nil

	testCase = "Expecting StatusUnauthorized error when ValidateUser function returns an error"
	// Also proves, no error when Initialize function doesn't return an error
	provider.validateUserErr = errors.New("Error")
	aAssert.Equal("Unauthorized", handleLdapLogin(ctx, w, r).Title, testCase)

	provider.validateUserErr = nil

	testCase = "Expecting StatusUnauthorized error when ldap user isn't authenticated"
	// Also proves, no error when ValidateUser function doesn't return an error
	provider.isAuthenticated = false
	aAssert.Equal("Unauthorized", handleLdapLogin(ctx, w, r).Title, testCase)

	provider.isAuthenticated = true

	testCase = "Expecting StatusInternalServerError error when Exists function returns an error"
	mockZk.rExists.err = errors.New("Error")
	aAssert.Equal("Internal Server Error", handleLdapLogin(ctx, w, r).Title, testCase)

	mockZk.rExists.err = nil

	testCase = "Expecting StatusUnauthorized error when ldap user isn't in ldap group with Admin role"
	// Also proves, no error when Exists function doesn't return an error
	provider.isInRole = false
	aAssert.Equal("Unauthorized", handleLdapLogin(ctx, w, r).Title, testCase)

	provider.isInRole = true

	testCase = "Expecting StatusUnauthorized error when ldap user not already added and using whitelist only"
	ctx = context.WithValue(ctx, keyLdapWhitelistOnly, true)
	mockZk.rExists.exists = false
	aAssert.Equal("Unauthorized", handleLdapLogin(ctx, w, r).Title, testCase)

	ctx = context.WithValue(ctx, keyLdapWhitelistOnly, false)
	mockZk.rExists.exists = true
	mockZk.rGet.err = nil

	testCase = "Expecting success when logging in as ldap user that was already added in whitelist"
	mockZk.rGet.bytes = []byte("whitelist")
	aAssert.Nil(handleLdapLogin(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Contains(string(respBody), "\"token\":\"", "Expecting response to contain a new token")

	testCase = "Expecting success when logging in as an already added ldap user that was/is in a group with admin role"
	mockZk.rGet.bytes = []byte("in group")
	aAssert.Nil(handleLdapLogin(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Contains(string(respBody), "\"token\":\"", "Expecting response to contain a new token")

	testCase = "Expecting success when logging in as an unadded ldap user that is in a group with Admin role"
	// Also proves, silently ignores error when Create function has an error
	mockZk.rExists.exists = false
	mockZk.rGet.bytes = nil
	mockZk.rCreate.err = errors.New("Error")
	aAssert.Nil(handleLdapLogin(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Contains(string(respBody), "\"token\":\"", "Expecting response to contain a new token")

	ldapConfig = nil
}

func TestLdapGroupsCheck(t *testing.T) {
	aAssert := assert.New(t)
	mockZk := &MockZk{}
	ctx := context.Background()
	ctx = context.WithValue(ctx, "zk", mockZk)
	provider := &testLdapProvider{}
	ldapConfig = &ldap.Config{
		Server: &ldap.ServerConfig{
			DefaultRole: "",
		},
	}
	var testCase string

	mockZk.rExists.exists = false
	mockZk.rExists.err = errors.New("Exists Error")
	mockZk.rGet.bytes = nil
	provider.initializeErr = errors.New("Error")
	provider.getUserByEmailErr = errors.New("GetUserByEmail Error")
	provider.getUserErr = errors.New("GetUser Error")
	provider.isInRole = false

	testCase = "Expecting error when Exists function returns an error"
	mockZk.rExists.err = errors.New("Exists Error")
	aAssert.EqualError(ldapGroupsCheck(ctx, "oauth@user"), "Exists Error", testCase)

	mockZk.rExists.err = nil

	testCase = "Expecting success when oauth user is on whitelist"
	// Also proves, no error when Exists function doesn't return an error
	mockZk.rExists.exists = true
	mockZk.rGet.bytes = []byte("whitelist")
	aAssert.Nil(ldapGroupsCheck(ctx, "oauth@user"), testCase)

	mockZk.rExists.exists = false
	mockZk.rGet.bytes = nil

	testCase = "Expecting error when newLdapProvider function returns an error"
	newLdapProvider = func(ctx context.Context) (security.MembershipProvider, error) {
		return nil, errors.New("Error")
	}
	aAssert.EqualError(ldapGroupsCheck(ctx, "ldap_user"), "Error", testCase)

	testCase = "Expecting error when Initialize function returns an error"
	provider.initializeErr = errors.New("Error")
	newLdapProvider = func(ctx context.Context) (security.MembershipProvider, error) {
		return provider, nil
	}
	aAssert.EqualError(ldapGroupsCheck(ctx, "ldap_user"), "Error", testCase)

	provider.initializeErr = nil

	testCase = "Expecting error when oauth user and GetUserByEmail function returns an error"
	// Also proves, no error when Initialize function doesn't return an error
	provider.getUserByEmailErr = errors.New("GetUserByEmail Error")
	aAssert.EqualError(ldapGroupsCheck(ctx, "oauth@user"), "GetUserByEmail Error", testCase)

	provider.getUserByEmailErr = nil

	testCase = "Expecting error when ldap user and GetUser function returns an error"
	provider.getUserErr = errors.New("GetUser Error")
	aAssert.EqualError(ldapGroupsCheck(ctx, "ldap_user"), "GetUser Error", testCase)

	provider.getUserErr = nil

	testCase = "Expecting error when non-whitelist oauth user isn't in an oauth group with admin role"
	// Also proves, no error when GetUserByEmail doesn't return an error
	provider.isInRole = false
	aAssert.EqualError(ldapGroupsCheck(ctx, "oauth@user"), "LDAP user oauth@user is not a member of an LDAP group with admin role for this cluster", testCase)

	testCase = "Expecting success when non-whitelist ldap user is in an ldap group with admin role"
	// Also proves, no error when GetUser doesn't return an error
	provider.isInRole = true
	aAssert.Nil(ldapGroupsCheck(ctx, "ldap_user"), testCase)

	ldapConfig = nil
}

func TestOnWhitelist(t *testing.T) {
	aAssert := assert.New(t)
	mockZk := &MockZk{}
	ctx := context.Background()
	ctx = context.WithValue(ctx, "zk", mockZk)
	var testCase string
	var onList bool
	var err error

	mockZk.rExists.exists = false
	mockZk.rExists.err = errors.New("Exists Error")
	mockZk.rGet.bytes = nil
	mockZk.rGet.err = errors.New("Get Error")

	testCase = "Expecting error and false when Exists function returns an error"
	mockZk.rExists.err = errors.New("Exists Error")
	onList, err = onWhitelist(ctx, "", "anyUser")
	aAssert.EqualError(err, "Exists Error", testCase)
	aAssert.False(onList, testCase)

	mockZk.rExists.err = nil

	testCase = "Expecting success and false when user hasn't already been added"
	// Also proves, no error when Exists function doesn't return an error
	mockZk.rExists.exists = false
	onList, err = onWhitelist(ctx, "", "anyUser")
	aAssert.Nil(err, testCase)
	aAssert.False(onList, testCase)

	mockZk.rExists.exists = true

	testCase = "Expecting error and false when Get function returns an error"
	mockZk.rGet.err = errors.New("Get Error")
	onList, err = onWhitelist(ctx, "", "anyUser")
	aAssert.EqualError(err, "Get Error", testCase)
	aAssert.False(onList, testCase)

	mockZk.rGet.err = nil

	testCase = "Expecting success and false when user not on whitelist"
	// Also proves, no error when Get function doesn't return an error
	mockZk.rGet.bytes = []byte("in group")
	onList, err = onWhitelist(ctx, "", "anyUser")
	aAssert.Nil(err, testCase)
	aAssert.False(onList, testCase)

	testCase = "Expecting success and true when user is on whitelist"
	mockZk.rGet.bytes = []byte("whitelist")
	onList, err = onWhitelist(ctx, "", "anyUser")
	aAssert.Nil(err, testCase)
	aAssert.True(onList, testCase)

	testCase = "Expecting success and true when data stored for user is the username"
	mockZk.rGet.bytes = []byte("anyUser")
	onList, err = onWhitelist(ctx, "", "anyUser")
	aAssert.Nil(err, testCase)
	aAssert.True(onList, testCase)
}
