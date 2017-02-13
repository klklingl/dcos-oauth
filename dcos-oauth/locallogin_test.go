package main

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/context"

	"github.com/stretchr/testify/assert"
	"errors"
	"time"
	"github.com/coreos/go-oidc/jose"
)

func TestTryLimitsCheck(t *testing.T) {
	aAssert := assert.New(t)
	lockedOutTime := time.Duration(2 * time.Second)
	saveTryLimitsTracker := tryLimitsTracker
	tryLimitsTracker = &tryLimits{
		lockoutDuration: lockedOutTime,
		samplePeriod: time.Duration(10 * time.Minute),
		maxTries: 3,
		users: make(map[string]*tryLimitsUser),
	}
	var testCase string
	var hasEntry bool

	testCase = "Expecting success on initial try limits check"
	aAssert.Nil(tryLimitsCheck("user"), testCase)
	_, hasEntry = tryLimitsTracker.users["user"]
	aAssert.True(hasEntry, "Expecting tryLimitsTracker entry after initial check")

	testCase = "Expecting success on 3rd try limits check"
	tryLimitsCheck("user")
	aAssert.Nil(tryLimitsCheck("user"), testCase)

	testCase = "Expecting Locked out error with explanation after 4th try limits check"
	aAssert.EqualError(tryLimitsCheck("user"), "Locked out, too many recent login attempts", testCase)

	testCase = "Expecting Locked out error after 5th try limits check"
	// Also proves, at most 4 checks are tracked
	aAssert.EqualError(tryLimitsCheck("user"), "Locked out", testCase)
	_, hasEntry = tryLimitsTracker.users["user"]
	aAssert.True(hasEntry, "Expecting tryLimitsTracker entry after 8th check")
	aAssert.EqualValues(4, len(tryLimitsTracker.users["user"].tries), "Expecting tryLimitsTracker to keep only most recent 4 tries")

	tryLimitsTracker.samplePeriod = lockedOutTime
	time.Sleep(lockedOutTime*2)

	testCase = "Expecting no longer Locked out after lockout time expires"
	// Also proves, old try entries removed from tracker when timestamp is before sample period
	aAssert.Nil(tryLimitsCheck("user"), testCase)
	aAssert.EqualValues(1, len(tryLimitsTracker.users["user"].tries), "Expecting tryLimitsTracker to only have the latest entry")

	// Restore try limits tracker for other tests
	tryLimitsTracker = saveTryLimitsTracker
}

func TestTryLimitsReset(t *testing.T) {
	aAssert := assert.New(t)
	tryLimitsTracker.users = make(map[string]*tryLimitsUser)
	var testCase string
	var hasEntry bool

	tryLimitsTracker.users["user"] = &tryLimitsUser{
		lockout: time.Now().UTC(),
		tries: []time.Time {time.Now().UTC(), time.Now().UTC()},
	}
	tryLimitsTracker.users["user-next"] = &tryLimitsUser{
		lockout: time.Now().UTC(),
		tries: []time.Time {time.Now().UTC(), time.Now().UTC()},
	}

	testCase = "Expecting no tryLimitsTracker entry after reset"
	// Also proves, other user being tracked is not affected by reset
	tryLimitsReset("user")
	_, hasEntry = tryLimitsTracker.users["user"]
	aAssert.False(hasEntry, testCase)
	_, hasEntry = tryLimitsTracker.users["user-next"]
	aAssert.True(hasEntry, "Expecting other users being tracked to not be affected by reset")
}

func TestVerifyLocalUser(t *testing.T) {
	aAssert := assert.New(t)
	mockZk := &MockZk{}
	ctx := context.Background()
	ctx = context.WithValue(ctx, "zk", mockZk)
	ctx = context.WithValue(ctx, keyAllowLocalUsers, true)
	var testCase string

	mockZk.rChildren.children = []string{"local_user"}
	mockZk.rChildren.err = errors.New("Error")
	mockZk.rExists.exists = false
	jwtValid, err := jose.ParseJWT("eyJhbGciOiJIUzI1NiIsImtpZCI6InNlY3JldCIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6ImxvY2FsYWRtaW4iLCJ1aWQiOiJsb2NhbGFkbWluIn0.IH4ZKekBL4J24bLih4YCrhm8ZMT0SLrqJ86o88AJBAk")
	aAssert.Nil(err, "Expecting valid json token to parse without error")

	testCase = "Expecting error when token is invalid"
	jwtInvalid := jwtValid
	jwtInvalid.Payload = []byte("Bad payload")
	aAssert.NotNil(verifyLocalUser(ctx, jwtInvalid), testCase)

	testCase = "Expecting error when Children function returns an error"
	mockZk.rChildren.err = errors.New("Children Error")
	aAssert.EqualError(verifyLocalUser(ctx, jwtValid), "Children Error", testCase)

	mockZk.rChildren.err = nil

	testCase = "Expecting error when local user hasn't already been added"
	mockZk.rExists.exists = false
	aAssert.EqualError(verifyLocalUser(ctx, jwtValid), "No matching local user: "+tokenUsername, testCase)

	testCase = "Expecting success when local user has already been added"
	mockZk.rExists.exists = true
	aAssert.Nil(verifyLocalUser(ctx, jwtValid), testCase)
}

func TestHandleLocalLogin(t *testing.T) {
	aAssert := assert.New(t)
	mockZk := &MockZk{}
	ctx := context.Background()
	ctx = context.WithValue(ctx, "zk", mockZk)
	ctx = context.WithValue(ctx, "secret-key", "12345")
	unusedUrl := "URL not used in testing"
	var respBody []byte
	var testCase string

	r, _ := http.NewRequest("POST", unusedUrl, nil)
	w := httptest.NewRecorder()
	mockZk.rChildren.children = []string{}
	mockZk.rChildren.err = errors.New("Error")
	mockZk.rExists.exists = false
	mockZk.rExists.err = errors.New("Error")
	mockZk.rGet.bytes = nil
	mockZk.rGet.err = errors.New("Error")
	mockZk.rCreate.err = errors.New("Error")
	ctx = context.WithValue(ctx, keyAllowLocalUsers, false)

	testCase = "Expecting StatusServiceUnavailable error when local users aren't allowed"
	ctx = context.WithValue(ctx, keyAllowLocalUsers, false)
	aAssert.Equal("Service Unavailable", handleLocalLogin(ctx, w, r).Title, testCase)

	ctx = context.WithValue(ctx, keyAllowLocalUsers, true)

	testCase = "Expecting StatusUnauthorized error when no BasicAuth header found"
	// Also proves, no error when local users are allowed
	aAssert.Equal("Unauthorized", handleLocalLogin(ctx, w, r).Title, testCase)

	testCase = "Expecting StatusUnauthorized error when username in BasicAuth header is empty"
	// Also proves, no error when BasicAuth header is found
	r.SetBasicAuth("", "localpass1")
	aAssert.Equal("Unauthorized", handleLocalLogin(ctx, w, r).Title, testCase)

	r.SetBasicAuth("anyUser", "pass")

	testCase = "Expecting StatusUnauthorized error when try limits exceeded"
	tryLimitsTracker.users["anyUser"] = &tryLimitsUser{
		lockout: time.Now().UTC().Add(tryLimitsTracker.lockoutDuration),
		tries: nil,
	}
	aAssert.Equal("Unauthorized", handleLocalLogin(ctx, w, r).Title, testCase)

	tryLimitsReset("anyUser")

	testCase = "Expecting StatusInternalServerError error when Children function returns an error"
	mockZk.rChildren.err = errors.New("Error")
	aAssert.Equal("Internal Server Error", handleLocalLogin(ctx, w, r).Title, testCase)

	mockZk.rChildren.children = []string{tokenUsername}
	mockZk.rChildren.err = nil

	testCase = "Expecting StatusInternalServerError error when Exists function returns an error"
	// Also proves, no error when Children function doesn't return an error
	mockZk.rExists.err = errors.New("Error")
	aAssert.Equal("Internal Server Error", handleLocalLogin(ctx, w, r).Title, testCase)

	mockZk.rChildren.children = []string{}
	mockZk.rExists.err = nil
	ctx = context.WithValue(ctx, keyDefaultLocalUser, tokenUsername)
	r.SetBasicAuth(tokenUsername, "badPass")

	testCase = "Expecting StatusUnauthorized error when default plain text password and password don't match for unadded default local user"
	// Also proves, no error when Exists function doesn't return an error
	ctx = context.WithValue(ctx, keyDefaultLocalUserHash, "goodPass")
	aAssert.Equal("Unauthorized", handleLocalLogin(ctx, w, r).Title, testCase)

	ctx = context.WithValue(ctx, keyDefaultLocalUserHash, "$2a$10$czNEDhNOb9xhejUEafbupeBmbSyC5CSvdXENxiZtv3LeZdhxhweeq")

	testCase = "Expecting StatusUnauthorized error when default hash and password don't match for unadded default local user"
	aAssert.Equal("Unauthorized", handleLocalLogin(ctx, w, r).Title, testCase)

	r.SetBasicAuth(tokenUsername, "localpass1")

	testCase = "Expecting success when default hash and password match for unadded default local user"
	// Also proves, silently ignores error when Create function has an error
	mockZk.rCreate.err = errors.New("Error")
	aAssert.Nil(handleLocalLogin(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Contains(string(respBody), "\"token\":\"", "Expecting response to contain a new token for default local user")

	mockZk.rCreate.err = nil
	r.SetBasicAuth("local_user", "anyPass")

	testCase = "Expecting StatusUnauthorized error when non-default local user not previously added"
	mockZk.rExists.exists = false
	aAssert.Equal("Unauthorized", handleLocalLogin(ctx, w, r).Title, testCase)

	mockZk.rChildren.children = []string{"anyUser"}
	mockZk.rExists.exists = true
	mockZk.rGet.bytes = []byte("$2a$10$czNEDhNOb9xhejUEafbupeBmbSyC5CSvdXENxiZtv3LeZdhxhweeq")
	r.SetBasicAuth(tokenUsername, "badPass")

	testCase = "Expecting StatusUnauthorized error when stored hash and password don't match"
	// Also proves, silently ignores error when Get function has an error
	mockZk.rGet.err = errors.New("Error")
	aAssert.Equal("Unauthorized", handleLocalLogin(ctx, w, r).Title, testCase)

	mockZk.rGet.err = nil
	r.SetBasicAuth(tokenUsername, "localpass1")

	testCase = "Expecting success when logging in as local user that was already added"
	// Also proves, no error when stored hash and password match
	mockZk.rChildren.children = []string{tokenUsername}
	aAssert.Nil(handleLocalLogin(ctx, w, r), testCase)
	respBody, _ = ioutil.ReadAll(w.Body)
	aAssert.Contains(string(respBody), "\"token\":\"", "Expecting response to contain a new token")
}
