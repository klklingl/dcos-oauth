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
	"github.com/samuel/go-zookeeper/zk"
)

func TestValidateLocalUser(t *testing.T) {
	badcases := []string{
		"#@%^%#$@#$@#.com",		// Garbage
		"@domain.com",			// @ not allowed
		"local user",			// space not allowed
		"u",					// too short
		"",						// can't be empty
	}
	for _, example := range badcases {
		if match := validateLocalUser(example); match {
			t.Fatalf("For local user validation with value: %s, expected: %v, actual: %v", example, false, match)
		}
	}

	goodcases := []string{
		"localuser",			// can contain lowercase
		"firstname.lastname",	// can contain dot
		"local-user",			// can contain dash
		"firstname_lastname",	// can contain underscore
		"local09_user50",		// can contain numbers
		"FIRSTname.lastNAME",	// can contain uppercase
		"us",					// can be quite short
	}

	for _, example := range goodcases {
		if match := validateLocalUser(example); !match {
			t.Fatalf("For local user validation with value: %s, expected: %v, actual: %v", example, true, match)
		}
	}
}

func TestHasLocalUsers(t *testing.T) {
	aAssert := assert.New(t)
	mockZk := &MockZk{}
	ctx := context.Background()
	ctx = context.WithValue(ctx, "zk", mockZk)
	var testCase string
	var err error
	var hasUsers bool

	mockZk.rChildren.children = []string{}
	mockZk.rChildren.err = errors.New("Error")

	testCase = "Expecting error when Children function returns error"
	mockZk.rChildren.err = errors.New("Error")
	_, err = hasLocalUsers(ctx)
	aAssert.NotNil(err, testCase)

	testCase = "Expecting success when Children function returns ErrNoNode error"
	// Also proves, no error when Children function returns an expected error
	mockZk.rChildren.err = zk.ErrNoNode
	_, err = hasLocalUsers(ctx)
	aAssert.Nil(err, testCase)

	mockZk.rChildren.err = nil

	testCase = "Expecting false when no local users have been added"
	// Also proves, no error when Children function doesn't return an error
	mockZk.rChildren.children = []string{}
	hasUsers, err = hasLocalUsers(ctx)
	aAssert.Nil(err, testCase)
	aAssert.False(hasUsers, testCase)

	testCase = "Expecting true when local users have been added"
	mockZk.rChildren.children = []string{"child_local"}
	hasUsers, err = hasLocalUsers(ctx)
	aAssert.Nil(err, testCase)
	aAssert.True(hasUsers, testCase)
}

func TestIsLocalUser(t *testing.T) {
	aAssert := assert.New(t)
	mockZk := &MockZk{}
	ctx := context.Background()
	ctx = context.WithValue(ctx, "zk", mockZk)
	ctx = context.WithValue(ctx, keyDefaultLocalUser, "defaultUser")
	var testCase string
	var err error
	var isLocal bool

	ctx = context.WithValue(ctx, keyAllowLocalUsers, false)
	mockZk.rChildren.children = []string{}
	mockZk.rChildren.err = errors.New("Error")
	mockZk.rExists.exists = false
	mockZk.rExists.err = errors.New("Error")

	testCase = "Expecting false when local users aren't allowed"
	ctx = context.WithValue(ctx, keyAllowLocalUsers, false)
	isLocal, err = isLocalUser(ctx, "local_user")
	aAssert.Nil(err, testCase)
	aAssert.False(isLocal, testCase)

	ctx = context.WithValue(ctx, keyAllowLocalUsers, true)

	testCase = "Expecting error when Children function returns an error"
	mockZk.rChildren.err = errors.New("Error")
	isLocal, err = isLocalUser(ctx, "local_user")
	aAssert.NotNil(err, testCase)
	aAssert.False(isLocal, testCase)

	mockZk.rChildren.err = nil

	testCase = "Expecting true for default user when no local users have been added"
	// Also proves, no error when Children function doesn't return an error
	mockZk.rChildren.children = []string{}
	isLocal, err = isLocalUser(ctx, "defaultUser")
	aAssert.Nil(err, testCase)
	aAssert.True(isLocal, testCase)

	testCase = "Expecting false for non-default user when no local users have been added"
	mockZk.rChildren.children = []string{}
	isLocal, err = isLocalUser(ctx, "otherUser")
	aAssert.Nil(err, testCase)
	aAssert.False(isLocal, testCase)

	mockZk.rChildren.children = []string{"someUser"}

	testCase = "Expecting false and error when Exists function returns an error"
	mockZk.rExists.err = errors.New("Error")
	isLocal, err = isLocalUser(ctx, "otherUser")
	aAssert.NotNil(err, testCase)
	aAssert.False(isLocal, testCase)

	mockZk.rExists.err = nil
	mockZk.rExists.exists = false

	testCase = "Expecting false for default user when only other local users have been added"
	mockZk.rChildren.children = []string{"otherUser"}
	isLocal, err = isLocalUser(ctx, "defaultUser")
	aAssert.Nil(err, testCase)
	aAssert.False(isLocal, testCase)

	testCase = "Expecting false when local user hasn't been added"
	mockZk.rChildren.children = []string{"defaultUser"}
	isLocal, err = isLocalUser(ctx, "otherUser")
	aAssert.Nil(err, testCase)
	aAssert.False(isLocal, testCase)

	mockZk.rChildren.children = []string{"defaultUser","otherUser"}
	mockZk.rExists.exists = true

	testCase = "Expecting true for default user when default local user has been added"
	isLocal, err = isLocalUser(ctx, "defaultUser")
	aAssert.Nil(err, testCase)
	aAssert.True(isLocal, testCase)

	testCase = "Expecting true when local user has been added"
	isLocal, err = isLocalUser(ctx, "otherUser")
	aAssert.Nil(err, testCase)
	aAssert.True(isLocal, testCase)
}

func TestAddDefaultLocalUser(t *testing.T) {
	aAssert := assert.New(t)
	mockZk := &MockZk{}
	ctx := context.Background()
	ctx = context.WithValue(ctx, "zk", mockZk)
	ctx = context.WithValue(ctx, keyDefaultLocalUser, "defaultUser")
	ctx = context.WithValue(ctx, keyDefaultLocalUserHash, "defaultPass")
	var testCase string

	mockZk.rCreate.hashSet = []byte("Invalid hash")
	mockZk.rCreate.err = errors.New("Error")
	mockZk.rExists.exists = false
	mockZk.rExists.err = errors.New("Error")

	testCase = "Expecting success when local users aren't allowed"
	ctx = context.WithValue(ctx, keyAllowLocalUsers, false)
	mockZk.rCreate.hashSet = nil
	aAssert.Nil(addDefaultLocalUser(ctx), testCase)
	aAssert.Nil(mockZk.rCreate.hashSet, testCase+" (shouldn't add default local user)")

	ctx = context.WithValue(ctx, keyAllowLocalUsers, true)

	testCase = "Expecting error when Exists function returns an error"
	mockZk.rExists.err = errors.New("Error")
	aAssert.NotNil(addDefaultLocalUser(ctx), testCase)

	mockZk.rExists.err = nil

	testCase = "Expecting success and no newly added user when default local user was already added"
	// Also proves, no error when Exists function doesn't return an error
	mockZk.rExists.exists = true
	mockZk.rCreate.hashSet = nil
	aAssert.Nil(addDefaultLocalUser(ctx), testCase)
	aAssert.Nil(mockZk.rCreate.hashSet, testCase)

	mockZk.rExists.exists = false

	testCase = "Expecting error when Create function returns an error"
	mockZk.rCreate.err = errors.New("Error")
	aAssert.NotNil(addDefaultLocalUser(ctx), testCase)

	mockZk.rCreate.err = nil

	testCase = "Expecting success and matching saved hash when using bcrypt hash and default local user wasn't already added"
	// Also proves, no error when Create function doesn't return an error
	ctx = context.WithValue(ctx, keyDefaultLocalUserHash, "$2a$10$czNEDhNOb9xhejUE")
	mockZk.rCreate.hashSet = nil
	aAssert.Nil(addDefaultLocalUser(ctx), testCase)
	aAssert.Equal("$2a$10$czNEDhNOb9xhejUE", string(mockZk.rCreate.hashSet), testCase)

	testCase = "Expecting success and generated hash when using plain text password and default local user wasn't already added"
	ctx = context.WithValue(ctx, keyDefaultLocalUserHash, "plainText")
	mockZk.rCreate.hashSet = nil
	aAssert.Nil(addDefaultLocalUser(ctx), testCase)
	aAssert.Regexp("^[$]", string(mockZk.rCreate.hashSet), testCase)
}

func TestGetLocalUsers(t *testing.T) {
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
	aAssert.Equal("Internal Server Error", getLocalUsers(ctx, w, r).Title, testCase)

	mockZk.rChildren.err = nil

	testCase = "Expecting no array in response when no local users have been added"
	mockZk.rChildren.children = []string{}
	aAssert.Nil(getLocalUsers(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Equal("{\"array\":null}\n", string(respBody), testCase)

	testCase = "Expecting one user in response when one local user has been added"
	mockZk.rChildren.children = []string{"child_local"}
	aAssert.Nil(getLocalUsers(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Equal("{\"array\":[{\"uid\":\"child_local\",\"description\":\"child_local\"}]}\n", string(respBody), testCase)

	testCase = "Expecting multiple users in response when multiple local users have been added"
	mockZk.rChildren.children = []string{"child_local", "child2_local"}
	aAssert.Nil(getLocalUsers(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Equal("{\"array\":[{\"uid\":\"child_local\",\"description\":\"child_local\"},{\"uid\":\"child2_local\",\"description\":\"child2_local\"}]}\n", string(respBody), testCase)
}

func TestGetLocalUser(t *testing.T) {
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
	uidFromUrl = func(r *http.Request) string {return "bad@localuser"}

	testCase = "Expecting StatusBadRequest error when URL has an invalid username"
	uidFromUrl = func(r *http.Request) string {return "bad@username"}
	aAssert.Equal("Bad Request", getLocalUser(ctx, w, r).Title, testCase)

	uidFromUrl = func(r *http.Request) string {return "child_local"}

	testCase = "Expecting StatusInternalServerError error when Exists function returns an error"
	// Also proves, no error when URL has valid username
	mockZk.rExists.err = errors.New("Error")
	aAssert.Equal("Internal Server Error", getLocalUser(ctx, w, r).Title, testCase)

	mockZk.rExists.err = nil

	testCase = "Expecting StatusNotFound error when matching local user has not been added"
	// Also proves, no error when Exists function doesn't return an error
	mockZk.rExists.exists = false
	aAssert.Equal("Not Found", getLocalUser(ctx, w, r).Title, testCase)

	testCase = "Expecting user in response when matching local user has been added"
	mockZk.rExists.exists = true
	aAssert.Nil(getLocalUser(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Equal("{\"uid\":\"child_local\",\"description\":\"child_local\"}\n", string(respBody), testCase)
}

func TestPostLocalUsers(t *testing.T) {
	aAssert := assert.New(t)
	mockZk := &MockZk{}
	ctx := context.Background()
	ctx = context.WithValue(ctx, "zk", mockZk)
	unusedUrl := "URL not used in testing"
	var respBody []byte
	var testCase string

	r, _ := http.NewRequest("POST", unusedUrl, nil)
	w := httptest.NewRecorder()
	ctx = context.WithValue(ctx, keyAllowLocalUsers, false)
	mockZk.rCreate.hashSet = []byte("Invalid hash")
	mockZk.rCreate.err = errors.New("Error")
	mockZk.rExists.exists = true
	mockZk.rExists.err = errors.New("Error")
	uidFromUrl = func(r *http.Request) string {return "bad@localuser"}

	testCase = "Expecting StatusServiceUnavailable error when local users aren't allowed"
	ctx = context.WithValue(ctx, keyAllowLocalUsers, false)
	aAssert.Equal("Service Unavailable", postLocalUsers(ctx, w, r).Title, testCase)

	ctx = context.WithValue(ctx, keyAllowLocalUsers, true)

	testCase = "Expecting StatusBadRequest error when request body has invalid json"
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader("test"))
	aAssert.Equal("Bad Request", postLocalUsers(ctx, w, r).Title, testCase)

	testCase = "Expecting StatusBadRequest error when request body has invalid username"
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader("{\"username\":\"us@2\"}"))
	aAssert.Equal("Bad Request", postLocalUsers(ctx, w, r).Title, testCase)

	testCase = "Expecting StatusBadRequest error when URL has no username and request body has no username"
	// Also proves, no problem with extra json in the request body
	uidFromUrl = func(r *http.Request) string {return ""}
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader("{\"oldpassword\":\"localpass1\",\"newpassword\":\"localpass2\"}"))
	aAssert.Equal("Bad Request", postLocalUsers(ctx, w, r).Title, testCase)

	testCase = "Expecting StatusBadRequest error when URL has an invalid username and request body has no username"
	uidFromUrl = func(r *http.Request) string {return "bad@localuser"}
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader("{\"oldpassword\":\"localpass1\",\"newpassword\":\"localpass2\"}"))
	aAssert.Equal("Bad Request", postLocalUsers(ctx, w, r).Title, testCase)

	testCase = "Expecting StatusInternalServerError error when Exists function returns an error"
	// Also proves, no error when request body has valid username
	// Also proves, username in request body overrides bad username from URL
	mockZk.rExists.err = errors.New("Error")
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader("{\"username\":\"local.user\"}"))
	uidFromUrl = func(r *http.Request) string {return "bad@localuser"}
	aAssert.Equal("Internal Server Error", postLocalUsers(ctx, w, r).Title, testCase)

	mockZk.rExists.err = nil

	testCase = "Expecting StatusConflict error when local user already exists"
	// Also proves, no error when Exists function doesn't return an error
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader("{\"username\":\"local_user\"}"))
	mockZk.rExists.exists = true
	aAssert.Equal("Conflict", postLocalUsers(ctx, w, r).Title, testCase)

	mockZk.rExists.exists = false

	testCase = "Expecting StatusBadRequest error when newpassword is not specified"
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader("{\"username\":\"local_user\"}"))
	aAssert.Equal("Bad Request", postLocalUsers(ctx, w, r).Title, testCase)

	testCase = "Expecting StatusBadRequest error when newpassword is too short"
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader("{\"username\":\"new-user\",\"newpassword\":\"tooshort\"}"))
	aAssert.Equal("Bad Request", postLocalUsers(ctx, w, r).Title, testCase)

	testCase = "Expecting StatusInternalServerError error when Create function returns an error"
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader("{\"username\":\"new-user\",\"newpassword\":\"plentyofchars\"}"))
	mockZk.rCreate.err = errors.New("Error")
	aAssert.Equal("Internal Server Error", postLocalUsers(ctx, w, r).Title, testCase)

	mockZk.rCreate.err = nil

	testCase = "Expecting success when request body has valid username and newpassword and that local user wasn't already added"
	// Also proves, no error when Create function doesn't return an error
	// Also proves, try limits are reset for newly added local user
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader("{\"username\":\"new-user\",\"newpassword\":\"plentyofchars\"}"))
	tryLimitsCheck("new-user")
	mockZk.rCreate.hashSet = nil
	aAssert.Nil(postLocalUsers(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Empty(string(respBody), testCase)
	_, hasEntry := tryLimitsTracker.users["new-user"]
	aAssert.False(hasEntry, "Not expecting tryLimitsTracker entry after new local user added")
	aAssert.NotNil(mockZk.rCreate.hashSet, "Expecting saved data during Create when new local user added")

	testCase = "Expecting success when valid username comes from URL and that local user wasn't already added"
	uidFromUrl = func(r *http.Request) string {return "local_URL"}
	r, _ = http.NewRequest("POST", unusedUrl, strings.NewReader("{\"newpassword\":\"plentyofchars\"}"))
	aAssert.Nil(postLocalUsers(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Empty(string(respBody), testCase)
}

func TestPutLocalUsers(t *testing.T) {
	aAssert := assert.New(t)
	mockZk := &MockZk{}
	ctx := context.Background()
	ctx = context.WithValue(ctx, "zk", mockZk)
	unusedUrl := "URL not used in testing"
	var respBody []byte
	var testCase string

	r, _ := http.NewRequest("PUT", unusedUrl, nil)
	w := httptest.NewRecorder()
	ctx = context.WithValue(ctx, keyAllowLocalUsers, false)
	mockZk.rDeleteErr = errors.New("Error")
	mockZk.rCreate.hashSet = []byte("Invalid hash")
	mockZk.rCreate.err = errors.New("Error")
	mockZk.rExists.exists = false
	mockZk.rExists.err = errors.New("Error")
	mockZk.rGet.bytes = []byte("")
	mockZk.rGet.err = errors.New("Error")
	uidFromUrl = func(r *http.Request) string {return "bad@localuser"}

	testCase = "Expecting StatusServiceUnavailable error when local users aren't allowed"
	ctx = context.WithValue(ctx, keyAllowLocalUsers, false)
	aAssert.Equal("Service Unavailable", putLocalUsers(ctx, w, r).Title, testCase)

	ctx = context.WithValue(ctx, keyAllowLocalUsers, true)

	testCase = "Expecting StatusBadRequest error when URL has an invalid username"
	aAssert.Equal("Bad Request", putLocalUsers(ctx, w, r).Title, testCase)

	uidFromUrl = func(r *http.Request) string {return "child_local"}

	testCase = "Expecting StatusInternalServerError error when Exists function returns an error"
	// Also proves, no error when URL has valid username
	mockZk.rExists.err = errors.New("Error")
	aAssert.Equal("Internal Server Error", putLocalUsers(ctx, w, r).Title, testCase)

	mockZk.rExists.err = nil

	testCase = "Expecting StatusNotFound error when local user has not been added"
	// Also proves, no error when Exists function doesn't return an error
	mockZk.rExists.exists = false
	aAssert.Equal("Not Found", putLocalUsers(ctx, w, r).Title, testCase)

	mockZk.rExists.exists = true

	testCase = "Expecting StatusBadRequest error when request body has invalid json"
	// Also proves, no error when local user has been added
	r, _ = http.NewRequest("PUT", unusedUrl, strings.NewReader("test"))
	aAssert.Equal("Bad Request", putLocalUsers(ctx, w, r).Title, testCase)

	testCase = "Expecting StatusBadRequest error when oldpassword is not specified"
	// Also proves, no error when request body has unexpected but valid json
	r, _ = http.NewRequest("PUT", unusedUrl, strings.NewReader("{\"username\":\"newuser\"}"))
	aAssert.Equal("Bad Request", putLocalUsers(ctx, w, r).Title, testCase)

	testCase = "Expecting StatusBadRequest error when newpassword is not specified"
	// Also proves, no error when request body has invalid username (since username comes from URL for PUT)
	r, _ = http.NewRequest("PUT", unusedUrl, strings.NewReader("{\"username\":\"bad@username\",\"oldpassword\":\"oldpass\"}"))
	aAssert.Equal("Bad Request", putLocalUsers(ctx, w, r).Title, testCase)

	testCase = "Expecting StatusBadRequest error when newpassword is too short"
	r, _ = http.NewRequest("PUT", unusedUrl, strings.NewReader("{\"oldpassword\":\"oldpass\",\"newpassword\":\"tooshort\"}"))
	aAssert.Equal("Bad Request", putLocalUsers(ctx, w, r).Title, testCase)

	testCase = "Expecting StatusBadRequest error when hash and oldpassword don't match"
	// Also proves, no error when request body has valid newpassword
	// Also proves, silently ignores error when Get function has an error
	r, _ = http.NewRequest("PUT", unusedUrl, strings.NewReader("{\"oldpassword\":\"localpass1\",\"newpassword\":\"morethan12char\"}"))
	mockZk.rGet.bytes = []byte("nomatch")
	mockZk.rGet.err = errors.New("Ignored error")
	aAssert.Equal("Bad Request", putLocalUsers(ctx, w, r).Title, testCase)

	mockZk.rGet.err = nil

	testCase = "Expecting StatusInternalServerError error when Delete function returns an error"
	// Also proves, no error when hash and oldpassword match
	r, _ = http.NewRequest("PUT", unusedUrl, strings.NewReader("{\"oldpassword\":\"localpass1\",\"newpassword\":\"morethan12char\"}"))
	mockZk.rGet.bytes = []byte("$2a$10$czNEDhNOb9xhejUEafbupeBmbSyC5CSvdXENxiZtv3LeZdhxhweeq")
	mockZk.rDeleteErr = errors.New("Error")
	aAssert.Equal("Internal Server Error", putLocalUsers(ctx, w, r).Title, testCase)

	mockZk.rDeleteErr = nil

	testCase = "Expecting StatusInternalServerError error when Create function returns an error"
	r, _ = http.NewRequest("PUT", unusedUrl, strings.NewReader("{\"oldpassword\":\"localpass1\",\"newpassword\":\"plentyofchars\"}"))
	mockZk.rCreate.err = errors.New("Error")
	aAssert.Equal("Internal Server Error", putLocalUsers(ctx, w, r).Title, testCase)

	mockZk.rCreate.err = nil

	testCase = "Expecting success when local user has been added previously and valid request body"
	// Also proves, no error when Delete function doesn't return an error
	// Also proves, try limits are reset for updated local user
	r, _ = http.NewRequest("PUT", unusedUrl, strings.NewReader("{\"oldpassword\":\"localpass1\",\"newpassword\":\"plentyofchars\"}"))
	tryLimitsCheck("child_local")
	mockZk.rCreate.hashSet = nil
	aAssert.Nil(putLocalUsers(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Empty(string(respBody), testCase)
	_, hasEntry := tryLimitsTracker.users["child_local"]
	aAssert.False(hasEntry, "Not expecting tryLimitsTracker entry after local user updated")
	aAssert.NotNil(mockZk.rCreate.hashSet, "Expecting saved data during Create when updating local user")
}

func TestDeleteLocalUsers(t *testing.T) {
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
	uidFromUrl = func(r *http.Request) string {return "bad@localuser"}

	testCase = "Expecting StatusBadRequest error when URL has an invalid username"
	uidFromUrl = func(r *http.Request) string {return "bad@localuser"}
	aAssert.Equal("Bad Request", deleteLocalUsers(ctx, w, r).Title, testCase)

	uidFromUrl = func(r *http.Request) string {return "child_local"}

	testCase = "Expecting StatusInternalServerError error when Exists function returns an error"
	// Also proves, no error when URL has valid username
	mockZk.rExists.err = errors.New("Error")
	aAssert.Equal("Internal Server Error", deleteLocalUsers(ctx, w, r).Title, testCase)

	mockZk.rExists.err = nil

	testCase = "Expecting StatusNotFound error when local user has not been added"
	// Also proves, no error when Exists function doesn't return an error
	mockZk.rExists.exists = false
	aAssert.Equal("Not Found", deleteLocalUsers(ctx, w, r).Title, testCase)

	mockZk.rExists.exists = true

	testCase = "Expecting StatusInternalServerError error when Delete function returns an error"
	// Also proves, no error when local user has been added
	mockZk.rDeleteErr = errors.New("Error")
	aAssert.Equal("Internal Server Error", deleteLocalUsers(ctx, w, r).Title, testCase)

	mockZk.rDeleteErr = nil

	testCase = "Expecting success when local user has been added previously"
	// Also proves, no error when Delete function doesn't return an error
	aAssert.Nil(deleteLocalUsers(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Empty(string(respBody), testCase)
}
