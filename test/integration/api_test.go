package integration

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

type userTest struct {
	userType           string
	uri                string
	exampleUser        string
	postStatusExpected int	// 0 means has no Post method
	putStatusExpected  int	// 0 means has no Put method
	includesType       bool
}

type userPasswordInfo struct{
	Username    string `json:"username,omitempty"`
	OldPassword string `json:"oldpassword,omitempty"`
	NewPassword string `json:"newpassword,omitempty"`
}

func TestUsers(t *testing.T) {
	var testCase, bodyGet string
	var err error
	assert := assert.New(t)
	dockerArgs := []string{
		"-e=OAUTH_ALLOW_LOCAL_USERS=true",
		"-e=OAUTH_ALLOW_LDAP_USERS=true",
	}

	assert.NoError(startZk())
	assert.NoError(startOAuthAPI(dockerArgs))
	defer cleanup("dcos-oauth")

	user := &userPasswordInfo{
		Username: "test-user",
		OldPassword: "testPassword",
		NewPassword: "testPassword",
	}

	userTests := []*userTest{
		&userTest{
			userType: "Oauth",
			uri: "/acs/api/v1/users",
			exampleUser: "test@domain.com",
			postStatusExpected: 0,
			putStatusExpected: 201,
			includesType: true,
		},
		&userTest{
			userType: "Local",
			uri: "/acs/api/v1/localusers",
			exampleUser: "test-local",
			postStatusExpected: 201,
			putStatusExpected: 202,
			includesType: false,
		},
		&userTest{
			userType: "LDAP",
			uri: "/acs/api/v1/ldapusers",
			exampleUser: "test_ldap",
			postStatusExpected: 201,
			putStatusExpected: 0,
			includesType: true,
		},
	}

	for _, tc := range userTests {

		user.Username = tc.exampleUser
		encoded := url.QueryEscape(tc.exampleUser)

		getResponse := `{"array":[{"uid":"` + tc.exampleUser + `","description":"` + tc.exampleUser + `"`
		if tc.includesType {
			getResponse = getResponse + `,"type":"whitelist"`
		}
		getResponse = getResponse + "}]}"

		testCase = "Expecting success and empty users list when calling GET method for " + tc.userType + " users"
		bodyGet, err = send("GET", tc.uri, 200, nil, nil)
		assert.NoError(err, testCase)
		assert.Equal(`{"array":null}`, bodyGet, testCase)

		testCase = "Expecting success when calling POST method for " + tc.userType + " users"
		if tc.postStatusExpected != 0 {
			_, err = send("POST", tc.uri + "/" + encoded, tc.postStatusExpected, user, nil)
			assert.NoError(err, testCase)
		}

		testCase = "Expecting success when calling PUT method for " + tc.userType + " users"
		if tc.putStatusExpected != 0 {
			_, err = send("PUT", tc.uri + "/" + encoded, tc.putStatusExpected, user, nil)
			assert.NoError(err, testCase)
		}

		testCase = "Expecting success and one user when calling GET method for " + tc.userType + " users"
		bodyGet, err = send("GET", tc.uri, 200, nil, nil)
		assert.NoError(err, testCase)
		assert.Equal(getResponse, bodyGet, testCase + ": " + tc.exampleUser)

		testCase = "Expecting success and one user's info when calling GET/user method for " + tc.userType + " users"
		bodyGet, err = send("GET", tc.uri + "/" + encoded, 200, nil, nil)
		assert.NoError(err, testCase)
		assert.Equal(`{"uid":"` + tc.exampleUser + `","description":"` + tc.exampleUser + `"}`, bodyGet, testCase + ": " + tc.exampleUser)

		testCase = "Expecting success when calling DELETE method for " + tc.userType + " users"
		_, err = send("DELETE", tc.uri + "/" + encoded, 204, nil, nil)
		assert.NoError(err, testCase)

		testCase = "Expecting success and empty users list when calling GET method after DELETE for " + tc.userType + " users"
		bodyGet, err = send("GET", tc.uri, 200, nil, nil)
		assert.NoError(err, testCase)
		assert.Equal(`{"array":null}`, bodyGet, testCase)

		testCase = "Expecting StatusNotFound error when calling GET/user method with empty users list for " + tc.userType + " users"
		bodyGet, err = send("GET", tc.uri + "/" + encoded, 404, nil, nil)
		assert.NoError(err, testCase)
		assert.Equal(`{"title":"Not Found","description":"`+ tc.userType +` User Not Found"}`, bodyGet, testCase)
	}

	// Test Local user login
	user.Username = "test-local"
	_, err = send("POST", "/acs/api/v1/localusers", 201, user, nil)

	bAuth := &basicAuth{username: "test-local", password: "testPassword"}

	testCase = "Expecting success when logging in as a Local user"
	bodyGet, err = send("GET", "/acs/api/v1/auth/locallogin", 200, nil, bAuth)
	assert.NoError(err, testCase)
	assert.Contains(bodyGet, `{"token":"`, bodyGet, testCase)
}

func TestLoginNotAllowed(t *testing.T) {
	assert := assert.New(t)
	dockerArgs := []string{
		"-e=OAUTH_ALLOW_LOCAL_USERS=false",
		"-e=OAUTH_ALLOW_LDAP_USERS=false",
	}

	assert.NoError(startZk())
	assert.NoError(startOAuthAPI(dockerArgs))
	defer cleanup("dcos-oauth")

	var testCase, bodyGet string
	var err error

	testCase = "Expecting StatusServiceUnavailable error when Local users are not allowed"
	bodyGet, err = send("GET", "/acs/api/v1/auth/locallogin", 503, nil, nil)
	assert.NoError(err, testCase)
	assert.Equal(`{"title":"Service Unavailable","description":"Local user login is not allowed"}`, bodyGet, testCase)

	testCase = "Expecting StatusServiceUnavailable error when LDAP users are not allowed"
	bodyGet, err = send("GET", "/acs/api/v1/auth/ldaplogin", 503, nil, nil)
	assert.NoError(err, testCase)
	assert.Equal(`{"title":"Service Unavailable","description":"LDAP user login is not allowed"}`, bodyGet, testCase)
}
