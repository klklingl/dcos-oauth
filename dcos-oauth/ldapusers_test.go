package main

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/context"

	"github.com/stretchr/testify/assert"
	"errors"
	"strings"
)

func TestValidateLdapUser(t *testing.T) {
	badcases := []string{
		"#@%^%#$@#$@#.com",		// Garbage
		"@domain.com",			// @ not allowed
		"ldap user",			// space not allowed
		"u",					// too short
		"",						// can't be empty
	}
	for _, example := range badcases {
		if match := validateLdapUser(example); match {
			t.Fatalf("For ldap user validation with value: %s, expected: %v, actual: %v", example, false, match)
		}
	}

	goodcases := []string{
		"ldapuser",				// can contain lowercase
		"firstname.lastname",	// can contain dot
		"ldap-user",			// can contain dash
		"firstname_lastname",	// can contain underscore
		"ldap09_user50",		// can contain numbers
		"FIRSTname.lastNAME",	// can contain uppercase
		"us",					// can be quite short
	}

	for _, example := range goodcases {
		if match := validateLdapUser(example); !match {
			t.Fatalf("For ldap user validation with value: %s, expected: %v, actual: %v", example, true, match)
		}
	}
}

func TestIsLdapUser(t *testing.T) {
	aAssert := assert.New(t)
	mockZk := &MockZk{}
	ctx := context.Background()
	ctx = context.WithValue(ctx, "zk", mockZk)
	var testCase string
	var err error
	var isLdap bool

	ctx = context.WithValue(ctx, keyAllowLdapUsers, false)
	mockZk.rExists.exists = false
	mockZk.rExists.err = errors.New("Error")

	testCase = "Expecting false when ldap users aren't allowed"
	ctx = context.WithValue(ctx, keyAllowLdapUsers, false)
	isLdap, err = isLdapUser(ctx, "ldap_user")
	aAssert.Nil(err, testCase)
	aAssert.False(isLdap, testCase)

	ctx = context.WithValue(ctx, keyAllowLdapUsers, true)

	testCase = "Expecting false and error when Exists function returns an error"
	mockZk.rExists.err = errors.New("Error")
	isLdap, err = isLdapUser(ctx, "otherUser")
	aAssert.NotNil(err, testCase)
	aAssert.False(isLdap, testCase)

	mockZk.rExists.err = nil

	testCase = "Expecting false when ldap user hasn't been added"
	mockZk.rExists.exists = false
	isLdap, err = isLdapUser(ctx, "otherUser")
	aAssert.Nil(err, testCase)
	aAssert.False(isLdap, testCase)

	testCase = "Expecting true when ldap user has been added"
	mockZk.rExists.exists = true
	isLdap, err = isLdapUser(ctx, "otherUser")
	aAssert.Nil(err, testCase)
	aAssert.True(isLdap, testCase)
}

func TestAddLdapUser(t *testing.T) {
	aAssert := assert.New(t)
	mockZk := &MockZk{}
	ctx := context.Background()
	ctx = context.WithValue(ctx, "zk", mockZk)
	var testCase string

	mockZk.rCreate.hashSet = []byte("Invalid hash")
	mockZk.rCreate.err = errors.New("Error")
	mockZk.rExists.exists = false
	mockZk.rExists.err = errors.New("Error")

	testCase = "Expecting success when ldap users aren't allowed"
	ctx = context.WithValue(ctx, keyAllowLdapUsers, false)
	mockZk.rCreate.hashSet = nil
	aAssert.Nil(addLdapUser(ctx, "ldapUser"), testCase)
	aAssert.Nil(mockZk.rCreate.hashSet, testCase+" (shouldn't add ldap user)")

	ctx = context.WithValue(ctx, keyAllowLdapUsers, true)

	testCase = "Expecting error when Exists function returns an error"
	mockZk.rExists.err = errors.New("Error")
	aAssert.NotNil(addLdapUser(ctx, "ldapUser"), testCase)

	mockZk.rExists.err = nil

	testCase = "Expecting success and no newly added user when ldap user was already added"
	// Also proves, no error when Exists function doesn't return an error
	mockZk.rExists.exists = true
	mockZk.rCreate.hashSet = nil
	aAssert.Nil(addLdapUser(ctx, "ldapUser"), testCase)
	aAssert.Nil(mockZk.rCreate.hashSet, testCase)

	mockZk.rExists.exists = false

	testCase = "Expecting error when Create function returns an error"
	mockZk.rCreate.err = errors.New("Error")
	aAssert.NotNil(addLdapUser(ctx, "ldapUser"), testCase)

	mockZk.rCreate.err = nil

	testCase = "Expecting success and group marker in Create data when ldap user wasn't already added"
	// Also proves, no error when Create function doesn't return an error
	mockZk.rCreate.hashSet = nil
	aAssert.Nil(addLdapUser(ctx, "ldapUser"), testCase)
	aAssert.Equal("in group", string(mockZk.rCreate.hashSet), testCase)
}

func TestGetLdapUsers(t *testing.T) {
	aAssert := assert.New(t)
	mockZk := &MockZk{}
	ctx := context.Background()
	ctx = context.WithValue(ctx, "zk", mockZk)
	unusedUrl := "URL not used in testing"
	var respBody []byte
	var testCase string

	r, _ := http.NewRequest("GET", unusedUrl, nil)
	w := httptest.NewRecorder()
	mockZk.rChildren.children = []string{}
	mockZk.rChildren.err = errors.New("Error")

	testCase = "Expecting StatusInternalServerError error when Children function returns error"
	mockZk.rChildren.err = errors.New("Error")
	aAssert.Equal("Internal Server Error", getLdapUsers(ctx, w, r).Title, testCase)

	mockZk.rChildren.err = nil

	testCase = "Expecting no array in response when no ldap users have been added"
	mockZk.rChildren.children = []string{}
	aAssert.Nil(getLdapUsers(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Equal("{\"array\":null}\n", string(respBody), testCase)

	testCase = "Expecting one user in response when one ldap user has been added"
	mockZk.rChildren.children = []string{"child_ldap"}
	aAssert.Nil(getLdapUsers(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Equal("{\"array\":[{\"uid\":\"child_ldap\",\"description\":\"child_ldap\"}]}\n", string(respBody), testCase)

	testCase = "Expecting multiple users in response when multiple ldap users have been added"
	mockZk.rChildren.children = []string{"child_ldap", "child2_ldap"}
	aAssert.Nil(getLdapUsers(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Equal("{\"array\":[{\"uid\":\"child_ldap\",\"description\":\"child_ldap\"},{\"uid\":\"child2_ldap\",\"description\":\"child2_ldap\"}]}\n", string(respBody), testCase)
}

func TestGetLdapUser(t *testing.T) {
	aAssert := assert.New(t)
	mockZk := &MockZk{}
	ctx := context.Background()
	ctx = context.WithValue(ctx, "zk", mockZk)
	unusedUrl := "URL not used in testing"
	var respBody []byte
	var testCase string

	r, _ := http.NewRequest("GET", unusedUrl, nil)
	w := httptest.NewRecorder()
	mockZk.rExists.exists = false
	mockZk.rExists.err = errors.New("Error")
	uidFromUrl = func(r *http.Request) string {return "bad@LdapUser"}

	testCase = "Expecting StatusBadRequest error when URL has an invalid username"
	uidFromUrl = func(r *http.Request) string {return "bad@username"}
	aAssert.Equal("Bad Request", getLdapUser(ctx, w, r).Title, testCase)

	uidFromUrl = func(r *http.Request) string {return "child_ldap"}

	testCase = "Expecting StatusInternalServerError error when Exists function returns an error"
	// Also proves, no error when URL has valid username
	mockZk.rExists.err = errors.New("Error")
	aAssert.Equal("Internal Server Error", getLdapUser(ctx, w, r).Title, testCase)

	mockZk.rExists.err = nil

	testCase = "Expecting StatusNotFound error when matching ldap user has not been added"
	// Also proves, no error when Exists function doesn't return an error
	mockZk.rExists.exists = false
	aAssert.Equal("Not Found", getLdapUser(ctx, w, r).Title, testCase)

	testCase = "Expecting user in response when matching ldap user has been added"
	mockZk.rExists.exists = true
	aAssert.Nil(getLdapUser(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Equal("{\"uid\":\"child_ldap\",\"description\":\"child_ldap\"}\n", string(respBody), testCase)
}

func TestPostLdapUsers(t *testing.T) {
	aAssert := assert.New(t)
	mockZk := &MockZk{}
	ctx := context.Background()
	ctx = context.WithValue(ctx, "zk", mockZk)
	unusedUrl := "URL not used in testing"
	var respBody []byte
	var testCase string

	r, _ := http.NewRequest("POST", unusedUrl, nil)
	w := httptest.NewRecorder()
	ctx = context.WithValue(ctx, keyAllowLdapUsers, false)
	ctx = context.WithValue(ctx, keyLdapWhitelistOnly, false)
	ctx = context.WithValue(ctx, keyLdapGroupsOnly, true)
	mockZk.rCreate.hashSet = []byte("Invalid hash")
	mockZk.rCreate.err = errors.New("Error")
	mockZk.rExists.exists = true
	mockZk.rExists.err = errors.New("Error")
	uidFromUrl = func(r *http.Request) string {return "bad@LdapUser"}

	testCase = "Expecting StatusServiceUnavailable error when ldap users aren't allowed"
	ctx = context.WithValue(ctx, keyAllowLdapUsers, false)
	aAssert.Equal("Service Unavailable", postLdapUsers(ctx, w, r).Title, testCase)

	ctx = context.WithValue(ctx, keyAllowLdapUsers, true)

	testCase = "Expecting StatusBadRequest error when not whitelist only and requires an ldap group check"
	r, _ = http.NewRequest("POST", unusedUrl, nil)
	ctx = context.WithValue(ctx, keyLdapWhitelistOnly, false)
	ctx = context.WithValue(ctx, keyLdapGroupsOnly, true)
	aAssert.Equal("Bad Request", postLdapUsers(ctx, w, r).Title, testCase)

	ctx = context.WithValue(ctx, keyLdapGroupsOnly, false)

	testCase = "Expecting StatusBadRequest error when request body has invalid json"
	// Also proves, no error when not whitelist only but doesn't require an ldap group check
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader("test"))
	aAssert.Equal("Bad Request", postLdapUsers(ctx, w, r).Title, testCase)

	ctx = context.WithValue(ctx, keyLdapWhitelistOnly, true)

	testCase = "Expecting StatusBadRequest error when request body has invalid username"
	// Also proves, no error when whitelist only
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader("{\"username\":\"us@2\"}"))
	aAssert.Equal("Bad Request", postLdapUsers(ctx, w, r).Title, testCase)

	testCase = "Expecting StatusBadRequest error when URL has no username and request body has no username"
	// Also proves, no problem with extra json in the request body
	uidFromUrl = func(r *http.Request) string {return ""}
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader("{\"oldpassword\":\"ldappass1\",\"newpassword\":\"ldappass2\"}"))
	aAssert.Equal("Bad Request", postLdapUsers(ctx, w, r).Title, testCase)

	testCase = "Expecting StatusBadRequest error when URL has an invalid username and request body has no username"
	// Also proves, request body can be empty
	uidFromUrl = func(r *http.Request) string {return "bad@LdapUser"}
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader("{}"))
	aAssert.Equal("Bad Request", postLdapUsers(ctx, w, r).Title, testCase)

	testCase = "Expecting StatusInternalServerError error when Exists function returns an error"
	// Also proves, no error when request body has valid username
	// Also proves, username in request body overrides bad username from URL
	mockZk.rExists.err = errors.New("Error")
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader("{\"username\":\"ldap.user\"}"))
	uidFromUrl = func(r *http.Request) string {return "bad@LdapUser"}
	aAssert.Equal("Internal Server Error", postLdapUsers(ctx, w, r).Title, testCase)

	mockZk.rExists.err = nil

	testCase = "Expecting StatusConflict error when ldap user already exists"
	// Also proves, no error when Exists function doesn't return an error
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader("{\"username\":\"ldap_user\"}"))
	mockZk.rExists.exists = true
	aAssert.Equal("Conflict", postLdapUsers(ctx, w, r).Title, testCase)

	mockZk.rExists.exists = false

	testCase = "Expecting StatusInternalServerError error when Create function returns an error"
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader("{\"username\":\"ldap_user\"}"))
	mockZk.rCreate.err = errors.New("Error")
	aAssert.Equal("Internal Server Error", postLdapUsers(ctx, w, r).Title, testCase)

	mockZk.rCreate.err = nil

	testCase = "Expecting success when request body has valid username and that ldap user wasn't already added"
	// Also proves, no error when Create function doesn't return an error
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader("{\"username\":\"new-user\"}"))
	mockZk.rCreate.hashSet = nil
	aAssert.Nil(postLdapUsers(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Empty(string(respBody), testCase)
	aAssert.Equal("whitelist", string(mockZk.rCreate.hashSet), "Expecting whitelist marker in created data")

	testCase = "Expecting success when valid username comes from URL and that ldap user wasn't already added"
	uidFromUrl = func(r *http.Request) string {return "ldap_URL"}
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader("{}"))
	aAssert.Nil(postLdapUsers(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Empty(string(respBody), testCase)
}

func TestDeleteLdapUsers(t *testing.T) {
	aAssert := assert.New(t)
	mockZk := &MockZk{}
	ctx := context.Background()
	ctx = context.WithValue(ctx, "zk", mockZk)
	unusedUrl := "URL not used in testing"
	var respBody []byte
	var testCase string

	r, _ := http.NewRequest("DELETE", unusedUrl, nil)
	w := httptest.NewRecorder()
	mockZk.rDeleteErr = errors.New("Error")
	mockZk.rExists.exists = false
	mockZk.rExists.err = errors.New("Error")
	uidFromUrl = func(r *http.Request) string {return "bad@LdapUser"}

	testCase = "Expecting StatusBadRequest error when URL has an invalid username"
	uidFromUrl = func(r *http.Request) string {return "bad@LdapUser"}
	aAssert.Equal("Bad Request", deleteLdapUsers(ctx, w, r).Title, testCase)

	uidFromUrl = func(r *http.Request) string {return "child_ldap"}

	testCase = "Expecting StatusInternalServerError error when Exists function returns an error"
	// Also proves, no error when URL has valid username
	mockZk.rExists.err = errors.New("Error")
	aAssert.Equal("Internal Server Error", deleteLdapUsers(ctx, w, r).Title, testCase)

	mockZk.rExists.err = nil

	testCase = "Expecting StatusNotFound error when ldap user wasn't already added"
	// Also proves, no error when Exists function doesn't return an error
	mockZk.rExists.exists = false
	aAssert.Equal("Not Found", deleteLdapUsers(ctx, w, r).Title, testCase)

	mockZk.rExists.exists = true

	testCase = "Expecting StatusInternalServerError error when Delete function returns an error"
	// Also proves, no error when ldap user has been added
	mockZk.rDeleteErr = errors.New("Error")
	aAssert.Equal("Internal Server Error", deleteLdapUsers(ctx, w, r).Title, testCase)

	mockZk.rDeleteErr = nil

	testCase = "Expecting success when ldap user was already added"
	// Also proves, no error when Delete function doesn't return an error
	aAssert.Nil(deleteLdapUsers(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Empty(string(respBody), testCase)
}
