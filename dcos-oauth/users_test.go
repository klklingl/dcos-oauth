package main

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/context"

	"github.com/dcos/dcos-oauth/common"
	"github.com/samuel/go-zookeeper/zk"
	"github.com/stretchr/testify/assert"
	"errors"
	"strings"
)

type MockZk struct {
	path string
	rDeleteErr error
	rCreate struct {
		hashSet []byte
		err error
	}
	rChildren struct {
		children []string
		err error
	}
	rExists struct {
		exists bool
		err error
	}
	rGet struct {
		bytes []byte
		err error
	}
}

func (m *MockZk) Children(path string) ([]string, *zk.Stat, error) {
	return m.rChildren.children, nil, m.rChildren.err
}

func (m *MockZk) Create(path string, data []byte, flags int32, acl []zk.ACL) (string, error) {
	m.rCreate.hashSet = data
	return "", m.rCreate.err
}

func (m *MockZk) Delete(path string, version int32) error {
	return m.rDeleteErr
}

func (m *MockZk) Exists(path string) (bool, *zk.Stat, error) {
	return m.rExists.exists, nil, m.rExists.err
}

func (m *MockZk) Get(path string) ([]byte, *zk.Stat, error) {
	return m.rGet.bytes, nil, m.rGet.err
}

func TestGetUsers(t *testing.T) {
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
	aAssert.Equal("Internal Server Error", getUsers(ctx, w, r).Title, testCase)

	mockZk.rChildren.err = nil

	testCase = "Expecting no array in response when no oauth users have been added"
	mockZk.rChildren.children = []string{}
	aAssert.Nil(getUsers(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Equal("{\"array\":null}\n", string(respBody), testCase)

	testCase = "Expecting one user in response when one oauth user has been added"
	mockZk.rChildren.children = []string{"child_oauth"}
	aAssert.Nil(getUsers(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Equal("{\"array\":[{\"uid\":\"child_oauth\",\"description\":\"child_oauth\"}]}\n", string(respBody), testCase)

	testCase = "Expecting multiple users in response when multiple oauth users have been added"
	mockZk.rChildren.children = []string{"child_oauth", "child2_oauth"}
	aAssert.Nil(getUsers(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Equal("{\"array\":[{\"uid\":\"child_oauth\",\"description\":\"child_oauth\"},{\"uid\":\"child2_oauth\",\"description\":\"child2_oauth\"}]}\n", string(respBody), testCase)
}

func TestGetUser(t *testing.T) {
	aAssert := assert.New(t)
	mockZk := &MockZk{}
	ctx := context.Background()
	ctx = context.WithValue(ctx, "zk", mockZk)
	ctx = context.WithValue(ctx, keyAllowLocalUsers, false)
	ctx = context.WithValue(ctx, keyAllowLdapUsers, false)
	unusedUrl := "URL not used in testing"
	var respBody []byte
	var testCase string

	r, _ := http.NewRequest("GET", unusedUrl, nil)
	w := httptest.NewRecorder()
	mockZk.rExists.exists = false
	mockZk.rExists.err = errors.New("Error")
	uidFromUrl = func(r *http.Request) string {return "bad@username"}

	testCase = "Expecting StatusBadRequest error when URL has an invalid username"
	uidFromUrl = func(r *http.Request) string {return "bad@username"}
	aAssert.Equal("Bad Request", getUser(ctx, w, r).Title, testCase)

	uidFromUrl = func(r *http.Request) string {return "child@domain.com"}

	testCase = "Expecting StatusInternalServerError error when Exists function returns an error"
	// Also proves, no error when URL has valid username
	mockZk.rExists.err = errors.New("Error")
	aAssert.Equal("Internal Server Error", getUser(ctx, w, r).Title, testCase)

	mockZk.rExists.err = nil

	testCase = "Expecting StatusNotFound error when matching oauth user wasn't already added"
	// Also proves, no error when Exists function doesn't return an error
	mockZk.rExists.exists = false
	aAssert.Equal("Not Found", getUser(ctx, w, r).Title, testCase)

	testCase = "Expecting user in response when matching oauth user was already added"
	mockZk.rExists.exists = true
	aAssert.Nil(getUser(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Equal("{\"uid\":\"child@domain.com\",\"description\":\"child@domain.com\"}\n", string(respBody), testCase)

	// Testing local users being returned
	ctx = context.WithValue(ctx, keyAllowLocalUsers, true)
	ctx = context.WithValue(ctx, keyDefaultLocalUser, "defaultUser")
	mockZk.rChildren.children = []string{"child_local"}
	mockZk.rChildren.err = nil
	mockZk.rExists.exists = false
	mockZk.rExists.err = errors.New("Error")
	uidFromUrl = func(r *http.Request) string {return "child_local"}

	testCase = "Expecting StatusInternalServerError error when local users allowed and Exists function returns an error"
	mockZk.rExists.err = errors.New("Error")
	aAssert.Equal("Internal Server Error", getUser(ctx, w, r).Title, testCase)

	testCase = "Expecting user in response when local users allowed and matching local user was already added"
	mockZk.rExists.exists = true
	mockZk.rExists.err = nil
	aAssert.Nil(getUser(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Equal("{\"uid\":\"child_local\",\"description\":\"child_local\"}\n", string(respBody), testCase)

	// Testing ldap users being returned
	ctx = context.WithValue(ctx, keyAllowLocalUsers, false)
	ctx = context.WithValue(ctx, keyAllowLdapUsers, true)
	uidFromUrl = func(r *http.Request) string {return "child_ldap"}
	mockZk.rExists.exists = false
	mockZk.rExists.err = errors.New("Error")

	testCase = "Expecting StatusInternalServerError error when ldap users allowed and Exists function returns an error"
	mockZk.rExists.err = errors.New("Error")
	aAssert.Equal("Internal Server Error", getUser(ctx, w, r).Title, testCase)

	testCase = "Expecting user in response when ldap users allowed and matching ldap user was already added"
	mockZk.rExists.exists = true
	mockZk.rExists.err = nil
	aAssert.Nil(getUser(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Equal("{\"uid\":\"child_ldap\",\"description\":\"child_ldap\"}\n", string(respBody), testCase)
}

func TestPutUsers(t *testing.T) {
	aAssert := assert.New(t)
	mockZk := &MockZk{}
	ctx := context.Background()
	ctx = context.WithValue(ctx, "zk", mockZk)
	ctx = context.WithValue(ctx, "segment-key", "39uhSEOoRHMw6cMR6st9tYXDbAL3JSaP")
	unusedUrl := "URL not used in testing"
	var respBody []byte
	var testCase string

	r, _ := http.NewRequest("PUT", unusedUrl, nil)
	w := httptest.NewRecorder()
	mockZk.rCreate.hashSet = []byte("Invalid hash")
	mockZk.rCreate.err = errors.New("Error")
	mockZk.rExists.exists = true
	mockZk.rExists.err = errors.New("Error")
	uidFromUrl = func(r *http.Request) string {return "bad_OauthUser"}

	testCase = "Expecting StatusBadRequest error when URL has an invalid username"
	uidFromUrl = func(r *http.Request) string {return "bad_OauthUser"}
	r, _ = http.NewRequest("PUT", unusedUrl, strings.NewReader("{}"))
	aAssert.Equal("Bad Request", putUsers(ctx, w, r).Title, testCase)

	uidFromUrl = func(r *http.Request) string {return "child@domain.com"}

	testCase = "Expecting StatusInternalServerError error when Exists function returns an error"
	mockZk.rExists.err = errors.New("Error")
	r, _ = http.NewRequest("PUT", unusedUrl, strings.NewReader("{}"))
	aAssert.Equal("Internal Server Error", putUsers(ctx, w, r).Title, testCase)

	mockZk.rExists.err = nil

	testCase = "Expecting StatusConflict error when oauth user was already added"
	// Also proves, no error when Exists function doesn't return an error
	r, _ = http.NewRequest("PUT", unusedUrl, strings.NewReader("{}"))
	mockZk.rExists.exists = true
	aAssert.Equal("Conflict", putUsers(ctx, w, r).Title, testCase)

	mockZk.rExists.exists = false

	testCase = "Expecting StatusBadRequest error when request body has invalid json"
	// Also proves, no error when oauth user wasn't already added
	r, _ = http.NewRequest("PUT", unusedUrl, strings.NewReader("test"))
	aAssert.Equal("Bad Request", putUsers(ctx, w, r).Title, testCase)

	testCase = "Expecting StatusInternalServerError error when Create function returns an error"
	// Also proves, no error when json is empty
	r, _ = http.NewRequest("PUT", unusedUrl, strings.NewReader("{}"))
	mockZk.rCreate.err = errors.New("Error")
	aAssert.Equal("Internal Server Error", putUsers(ctx, w, r).Title, testCase)

	mockZk.rCreate.err = nil

	testCase = "Expecting success when valid username comes from URL and that oauth user wasn't already added"
	// Also proves, no error when Create function doesn't return an error
	r, _ = http.NewRequest("PUT", unusedUrl, strings.NewReader("{}"))
	mockZk.rCreate.hashSet = nil
	aAssert.Nil(putUsers(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Empty(string(respBody), testCase)
	aAssert.NotNil(mockZk.rCreate.hashSet, "Expecting saved data during Create when new oauth user added")
}

func TestDeleteUsers(t *testing.T) {
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
	uidFromUrl = func(r *http.Request) string {return "bad_OauthUser"}

	testCase = "Expecting StatusBadRequest error when URL has an invalid username"
	uidFromUrl = func(r *http.Request) string {return "bad_OauthUser"}
	aAssert.Equal("Bad Request", deleteUsers(ctx, w, r).Title, testCase)

	uidFromUrl = func(r *http.Request) string {return "child@domain.com"}

	testCase = "Expecting StatusInternalServerError error when Exists function returns an error"
	// Also proves, no error when URL has valid username
	mockZk.rExists.err = errors.New("Error")
	aAssert.Equal("Internal Server Error", deleteUsers(ctx, w, r).Title, testCase)

	mockZk.rExists.err = nil

	testCase = "Expecting StatusNotFound error when oauth user wasn't already added"
	// Also proves, no error when Exists function doesn't return an error
	mockZk.rExists.exists = false
	aAssert.Equal("Not Found", deleteUsers(ctx, w, r).Title, testCase)

	mockZk.rExists.exists = true

	testCase = "Expecting StatusInternalServerError error when Delete function returns an error"
	// Also proves, no error when oauth user has been added
	mockZk.rDeleteErr = errors.New("Error")
	aAssert.Equal("Internal Server Error", deleteUsers(ctx, w, r).Title, testCase)

	mockZk.rDeleteErr = nil

	testCase = "Expecting success when oauth user was already added"
	// Also proves, no error when Delete function doesn't return an error
	aAssert.Nil(deleteUsers(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Empty(string(respBody), testCase)
}

func TestValidateEmail(t *testing.T) {

	//Note: Our regex support for the following invalid email examples:
	//".email@domain.com",        // Leading dot in address is not allowed
	//"email.@domain.com",        // Trailing dot in address is not allowed
	//"email..email@domain.com",  // Multiple dots
	//"email@-domain.com",        // Leading dash in front of domain is invalid

	badcases := []string{
		"#@%^%#$@#$@#.com",             // Garbage
		"@domain.com",                  // Missing username
		"Test Name <email@domain.com>", // Encoded html within email is invalid
		"email.domain.com",             // Missing @
		"email@domain@domain.com",      // Two @ sign

		"email@domain.com (Test Name)", // Text followed email is not allowed
		"email@domain",                 // Missing top level domain (.com/.net/.org/etc)
		"email@111.222.333.44444 ",     // Invalid IP format
		"nomatching",                   // Missing @ sign and domain
		"email@domain..com",            // Multiple dot in the domain portion is invalid
	}
	for _, example := range badcases {
		if match := common.ValidateEmail(example); match {
			t.Fatalf("For email validation with value: %s, expected: %v, actual: %v", example, false, match)
		}
	}

	goodcases := []string{
		"email@domain.com",              //Valid email
		"firstname.lastname@domain.com", //Email contains dot in the address field
		"email@subdomain.domain.com",    //Email contains dot with subdomain
		"firstname+lastname@domain.com", //Plus sign is considered valid character
		"1234567890@domain.com",         //Digits in address are valid
		"email@domain-one.com",          //Dash in domain name is valid
		"_______@domain.com",            //Underscore in the address field is valid
		"email@domain.co.jp",            //Dot in Top Level Domain name also considered valid (use co.jp as example here)
		"firstname-lastname@domain.com", //Dash in address field is valid
		"email@123.123.123.123",         //Domain is valid IP address
		"email@[123.123.123.123]",       //Square bracket around IP address is considered valid
		"“email”@domain.com",            //Quotes around email is con
	}

	for _, example := range goodcases {
		if match := common.ValidateEmail(example); !match {
			t.Fatalf("For email validation with value: %s, expected: %v, actual: %v", example, true, match)
		}
	}
}
