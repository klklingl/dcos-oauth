package main

import (
	"encoding/json"
	"fmt"
	"net/http"

	log "github.com/Sirupsen/logrus"
	"github.com/gorilla/mux"
	"github.com/samuel/go-zookeeper/zk"
	"golang.org/x/net/context"

	"github.com/dcos/dcos-oauth/common"
	"regexp"
)

const (
	zkLocalPath = "/dcos/localusers"
	defaultLocalUser = "admin"
)

var (
	localUserRe = regexp.MustCompile(`^[a-zA-Z0-9“”._-]{2,}$`)
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
	if !localLoginEnabled {
		return false, nil
	}

	if hasLocal, err := hasLocalUsers(ctx); !hasLocal || err != nil {
		return uid == defaultLocalUser && err == nil, err
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
	if !localLoginEnabled {
		return nil
	}

	uid := defaultLocalUser

	c := ctx.Value("zk").(common.IZk)

	path := fmt.Sprintf("%s/%s", zkLocalPath, uid)
	exists, _, err := c.Exists(path)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("Default local user already exists: %s", uid)
	}

	err = common.CreateParents(c, path, []byte(uid))
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

func putLocalUsers(ctx context.Context, w http.ResponseWriter, r *http.Request) *common.HttpError {
	if !localLoginEnabled {
		return common.NewHttpError("Local login not enabled", http.StatusServiceUnavailable)
	}

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
	if exists {
		return common.NewHttpError("Already Exists", http.StatusConflict)
	}

	var user User
	err = json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		log.Debugf("putLocalUsers: Decode: %v", err)
		return common.NewHttpError("invalid user json", http.StatusBadRequest)
	}
	log.Printf("Create local user: %+v", user)

	err = common.CreateParents(c, path, []byte(uid))
	if err != nil {
		return common.NewHttpError("Zookeeper error", http.StatusInternalServerError)
	}
	w.WriteHeader(http.StatusCreated)

	log.Debugf("Local user created: %+v", uid)

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
