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

var (
	validTokenJson string = "{\"token\":\"eyJhbGciOiJIUzI1NiIsImtpZCI6InNlY3JldCIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImxvY2FsYWRtaW4iLCJ1aWQiOiJsb2NhbGFkbWluIn0.IH4ZKekBL4J24bLih4YCrhm8ZMT0SLrqJ86o88AJBAk\"}"
	tokenUsername string = "localadmin"
)

func TestHandleLogin(t *testing.T) {
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
	ctx = context.WithValue(ctx, "issuer-url", "https://dcos.auth0.com/")
	ctx = context.WithValue(ctx, "client-id", "3yF5TOSzdlI45Q1xspxzeoGBe9fNxm9m")
	ctx = context.WithValue(ctx, "secret-key", "12345")

	testCase = "Expecting StatusBadRequest error when request body has invalid json"
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader("test"))
	aAssert.Equal("Bad Request", handleLogin(ctx, w, r).Title, testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Equal("", string(respBody), testCase)

	ctx = context.WithValue(ctx, keyAllowLocalUsers, true) // Elimiates need for OpenId check to actually succeed
	ctx = context.WithValue(ctx, keyLdapCheckOnOauth, false)

	testCase = "Expecting success when using a token with a local user that was already added"
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader(validTokenJson))
	mockZk.rChildren.children = []string{tokenUsername}
	mockZk.rChildren.err = nil
	mockZk.rExists.exists = true
	mockZk.rExists.err = nil
	mockZk.rGet.bytes = []byte("whitelist")
	mockZk.rGet.err = nil
	aAssert.Nil(handleLogin(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Contains(string(respBody), "\"token\":\"", "Expecting response to contain a new token")
}

func TestHandleLogout(t *testing.T) {
	aAssert := assert.New(t)
	ctx := context.Background()
	unusedUrl := "URL not used in testing"
	var testCase string

	testCase = "Expecting success on logout"
	r, _ := http.NewRequest("GET", unusedUrl, nil)
	w := httptest.NewRecorder()
	aAssert.Nil(handleLogout(ctx, w, r), testCase)
}

func TestOauthGroupsCheck(t *testing.T) {
	aAssert := assert.New(t)
	mockZk := &MockZk{}
	ctx := context.Background()
	ctx = context.WithValue(ctx, "zk", mockZk)
	testUid := "child@domain.com"
	var testCase string

	oauthAdminGroups = make(map[string]bool)
	mockZk.rExists.exists = false
	mockZk.rGet.bytes = nil

	testCase = "Expecting success when oauth user is on whitelist"
	mockZk.rExists.exists = true
	mockZk.rGet.bytes = []byte("whitelist")
	aAssert.Nil(oauthGroupsCheck(ctx, testUid, []string{}), testCase)

	mockZk.rExists.exists = false
	mockZk.rGet.bytes = nil

	testCase = "Expecting error when using non-whitelist oauth user and there are no oauth groups with admin role"
	oauthAdminGroups = make(map[string]bool)
	aAssert.EqualError(oauthGroupsCheck(ctx, testUid, []string{}), "User "+testUid+" is not authorized for this cluster", testCase)

	testCase = "Expecting success when non-whitelist oauth user is in an oauth group with admin role"
	oauthAdminGroups["adminGroup"] = true
	aAssert.Nil(oauthGroupsCheck(ctx, testUid, []string{"adminGroup"}), testCase)

	testCase = "Expecting error when non-whitelist oauth user isn't in an oauth group with admin role"
	// Also proves, check handles oauth users associated with multiple groups
	aAssert.EqualError(oauthGroupsCheck(ctx, testUid, []string{"otherGroup","moreGroup","myGroup"}), "User "+testUid+" is not a member of an oauth group with admin role for this cluster", testCase)

	testCase = "Expecting success when non-whitelist oauth user is in at least one oauth group with admin role"
	// Also proves, check handles multiple oauth groups having admin role
	oauthAdminGroups["adminGroupToo"] = true
	aAssert.Nil(oauthGroupsCheck(ctx, testUid, []string{"otherGroup","adminGroupToo"}), testCase)
}
