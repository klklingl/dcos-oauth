package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/samuel/go-zookeeper/zk"
	"golang.org/x/net/context"
	"golang.org/x/crypto/bcrypt"

	"github.com/dcos/dcos-oauth/common"
)

type userPasswordInfo struct {
	Username    string `json:"username,omitempty"`
	OldPassword string `json:"oldpassword,omitempty"`
	NewPassword string `json:"newpassword,omitempty"`
}

const (
	zkLocalPath = "/dcos/localusers"
	minPasswordLength = 12
)

var (
	localUserRe = regexp.MustCompile(`^[a-zA-Z0-9“”._-]{2,}$`)
	bcryptCost = bcrypt.DefaultCost
)

func validateLocalUser(uid string) bool {
	return localUserRe.MatchString(uid)
}

func hasLocalUsers(ctx context.Context) (bool, error) {
	c := ctx.Value("zk").(common.IZk)

	users, _, err := c.Children(zkLocalPath)
	if err != nil && err != zk.ErrNoNode {
		return false, err
	}

	return len(users) != 0, nil
}

func isLocalUser(ctx context.Context, uid string) (bool, error) {
	if !allowLocalUsers(ctx) {
		return false, nil
	}

	if hasLocal, err := hasLocalUsers(ctx); !hasLocal || err != nil {
		return uid == defaultLocalUser(ctx) && err == nil, err
	}

	c := ctx.Value("zk").(common.IZk)

	path := fmt.Sprintf("%s/%s", zkLocalPath, uid)
	exists, _, err := c.Exists(path)
	if err != nil {
		return false, err
	}

	return exists, nil
}

func addDefaultLocalUser(ctx context.Context) error {
	if !allowLocalUsers(ctx) {
		return nil
	}

	uid := defaultLocalUser(ctx)

	c := ctx.Value("zk").(common.IZk)

	path := fmt.Sprintf("%s/%s", zkLocalPath, uid)
	exists, _, err := c.Exists(path)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}

	hash := []byte(defaultLocalUserHash(ctx))
	// In the future may only want to allow a hash instead of a hash or plain text password
	if !strings.HasPrefix(string(hash), "$") {
		hash, err = bcrypt.GenerateFromPassword(hash, bcryptCost)
		if err != nil {
			return err
		}
	}

	err = common.CreateParents(c, path, hash)
	if err != nil {
		return err
	}
	log.Printf("Default local user created: %s", uid)

	return nil
}

func getLocalUsers(ctx context.Context, w http.ResponseWriter, r *http.Request) *common.HttpError {
	c := ctx.Value("zk").(common.IZk)
	users, _, err := c.Children(zkLocalPath)
	if err != nil && err != zk.ErrNoNode {
		return common.NewHttpError("invalid email", http.StatusInternalServerError)
	}

	// users will be an empty list on ErrNoNode
	var usersJson Users
	for _, user := range users {
		userJson := &User{
			Uid:         user,
			Description: user,
			URL:         "",
			IsRemote:    false,
		}
		usersJson.Array = append(usersJson.Array, userJson)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(usersJson)
	log.Debugf("Local users listed: %+v\n", users)
	return nil
}

func getLocalUser(ctx context.Context, w http.ResponseWriter, r *http.Request) *common.HttpError {
	// uid is already unescaped here
	uid := mux.Vars(r)["uid"]
	if !validateLocalUser(uid) {
		return common.NewHttpError("invalid local user", http.StatusInternalServerError)
	}

	c := ctx.Value("zk").(common.IZk)

	path := fmt.Sprintf("%s/%s", zkLocalPath, uid)
	exists, _, err := c.Exists(path)
	if err != nil {
		log.Debugf("getLdapUsers: Zookeeper error: %v", err)
		return common.NewHttpError("Zookeeper error", http.StatusInternalServerError)
	}
	if !exists {
		log.Printf("getLocalUser: %v doesn't exist", path)
		return common.NewHttpError("Local User Not Found", http.StatusNotFound)
	}

	w.Header().Set("Content-Type", "application/json")
	userJson := &User{
		Uid:         uid,
		Description: uid,
		IsRemote:    false,
	}
	json.NewEncoder(w).Encode(userJson)

	log.Debugf("Local user listed: %+v\n", uid)

	return nil
}

func postLocalUsers(ctx context.Context, w http.ResponseWriter, r *http.Request) *common.HttpError {
	if !allowLocalUsers(ctx) {
		return common.NewHttpError("Local users are not allowed", http.StatusServiceUnavailable)
	}

	var info userPasswordInfo
	err := json.NewDecoder(r.Body).Decode(&info) // OldPassword not expected and would be ignored since local user can't already exist
	if err != nil {
		log.Debugf("postLocalUsers: Decode error: %v", err)
		return common.NewHttpError("invalid json", http.StatusBadRequest)
	}

	// Prefer user specified in the body over one from the URL
	var uid string
	if info.Username != "" {
		uid = info.Username
	} else {
		uid = mux.Vars(r)["uid"]
	}
	if uid == "" {
		return common.NewHttpError("Local user required", http.StatusBadRequest)
	}
	if !validateLocalUser(uid) {
		return common.NewHttpError("invalid local user", http.StatusInternalServerError)
	}
	log.Debugf("Creating local user: %+v", uid)

	c := ctx.Value("zk").(common.IZk)

	path := fmt.Sprintf("%s/%s", zkLocalPath, uid)
	exists, _, err := c.Exists(path)
	if err != nil {
		log.Debugf("postLocalUsers: Zookeeper error: %v", err)
		return common.NewHttpError("Zookeeper error", http.StatusInternalServerError)
	}
	if exists {
		return common.NewHttpError(fmt.Sprintf("Local user %s already exists", uid), http.StatusConflict)
	}

	if info.NewPassword == "" {
		return common.NewHttpError("invalid json for new user. Requires \"newpassword\":\"newpass\"", http.StatusBadRequest)
	}
	if len(info.NewPassword) < minPasswordLength {
		return common.NewHttpError(
			fmt.Sprintf("Password must have at least %d characters", minPasswordLength),
			http.StatusBadRequest)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(info.NewPassword), bcryptCost)
	if err != nil {
		return common.NewHttpError("Encryption error", http.StatusInternalServerError)
	}

	err = common.CreateParents(c, path, hash)
	if err != nil {
		return common.NewHttpError("Zookeeper error", http.StatusInternalServerError)
	}
	w.WriteHeader(http.StatusCreated)

	log.Printf("Local user created: %+v", uid)

	return nil
}

func putLocalUsers(ctx context.Context, w http.ResponseWriter, r *http.Request) *common.HttpError {
	if !allowLocalUsers(ctx) {
		return common.NewHttpError("Local users are not allowed", http.StatusServiceUnavailable)
	}

	uid := mux.Vars(r)["uid"]
	if !validateLocalUser(uid) {
		return common.NewHttpError(fmt.Sprintf("invalid local user: %s", uid), http.StatusBadRequest)
	}

	c := ctx.Value("zk").(common.IZk)

	path := fmt.Sprintf("%s/%s", zkLocalPath, uid)
	exists, _, err := c.Exists(path)
	if err != nil {
		log.Debugf("putLocalUsers: Zookeeper error: %v", err)
		return common.NewHttpError("Zookeeper error", http.StatusInternalServerError)
	}
	if !exists {
		return common.NewHttpError(fmt.Sprintf("Local user %s not found", uid), http.StatusNotFound)
	}

	var info userPasswordInfo
	err = json.NewDecoder(r.Body).Decode(&info) // Username not expected and would be ignored since it always comes from the URL for PUT
	if err != nil {
		log.Debugf("putLocalUsers: Decode error: %v", err)
		return common.NewHttpError("invalid json", http.StatusBadRequest)
	}
	if info.OldPassword == "" || info.NewPassword == "" {
		return common.NewHttpError(
			"invalid json for changing password. Requires \"oldpassword\":\"oldpass\",\"newpassword\":\"newpass\"",
			http.StatusBadRequest)
	}
	if len(info.NewPassword) < minPasswordLength {
		return common.NewHttpError(
			fmt.Sprintf("Password must have at least %d characters", minPasswordLength),
			http.StatusBadRequest)
	}

	hash, _, err := c.Get(path)
	if err != nil {
		log.Printf("putLocalUsers: error getting hash for comparison: %v", err)
	}

	err = bcrypt.CompareHashAndPassword(hash, []byte(info.OldPassword))
	if err != nil {
		log.Debugf("putLocalUsers: error comparing passwords for user %s: %v", uid, err)
		return common.NewHttpError("Current password and OldPassword do not match", http.StatusBadRequest)
	}

	hash, err = bcrypt.GenerateFromPassword([]byte(info.NewPassword), bcryptCost)
	if err != nil {
		return common.NewHttpError("Encryption error", http.StatusInternalServerError)
	}

	//TODO: Need a Set function instead of deleting and adding in case there are other attributes
	err = c.Delete(path, 0)
	if err != nil {
		log.Debugf("putLocalUsers: Zookeeper delete error: %v", err)
		return common.NewHttpError("Zookeeper delete error", http.StatusInternalServerError)
	}
	err = common.CreateParents(c, path, hash)
	if err != nil {
		return common.NewHttpError("Zookeeper error", http.StatusInternalServerError)
	}
	w.WriteHeader(http.StatusAccepted)

	log.Printf("Password changed for local user: %+v", uid)

	return nil
}

func deleteLocalUsers(ctx context.Context, w http.ResponseWriter, r *http.Request) *common.HttpError {
	uid := mux.Vars(r)["uid"]
	if !validateLocalUser(uid) {
		return common.NewHttpError("invalid local user", http.StatusInternalServerError)
	}

	c := ctx.Value("zk").(common.IZk)
	path := fmt.Sprintf("%s/%s", zkLocalPath, uid)
	exists, _, err := c.Exists(path)
	if err != nil {
		return common.NewHttpError("Zookeeper error", http.StatusInternalServerError)
	}
	if !exists {
		return common.NewHttpError("Local user not found", http.StatusNotFound)
	}

	err = c.Delete(path, 0)
	if err != nil {
		return common.NewHttpError("Zookeeper error", http.StatusInternalServerError)
	}

	w.WriteHeader(http.StatusNoContent)
	log.Printf("Local user deleted: %+v", uid)
	return nil
}
