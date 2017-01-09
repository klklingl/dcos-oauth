package main

import (
	"github.com/dcos/dcos-oauth/common"
)

var routes = map[string]map[string]common.Handler{
	"POST": {
		"/acs/api/v1/auth/login":          handleLogin,
		"/acs/api/v1/auth/locallogin":     handleLocalLogin,
		"/acs/api/v1/auth/ldaplogin":      handleLdapLogin,
		"/acs/api/v1/ldapusers":           postLdapUsers,
		"/acs/api/v1/ldapusers/{uid:.*}":  postLdapUsers,
		"/acs/api/v1/localusers":          postLocalUsers,
		"/acs/api/v1/localusers/{uid:.*}": postLocalUsers,
	},
	"PUT": {
		"/acs/api/v1/users/{uid:.*}":      putUsers,
		"/acs/api/v1/localusers/{uid:.*}": putLocalUsers, // Change password
	},
	"GET": {
		"/dcos-metadata/ui-config.json":   handleUIConfig,
		"/acs/api/v1/auth/logout":         handleLogout,
		"/acs/api/v1/users":               getUsers,
		"/acs/api/v1/localusers":          getLocalUsers,
		"/acs/api/v1/ldapusers":           getLdapUsers,
		"/acs/api/v1/users/{uid:.*}":      getUser,
		"/acs/api/v1/localusers/{uid:.*}": getLocalUser,
		"/acs/api/v1/ldapusers/{uid:.*}":  getLdapUser,
		"/acs/api/v1/groups":              getGroups,
		"/acs/api/v1/auth/locallogin":     handleLocalLogin,
		"/acs/api/v1/auth/ldaplogin":      handleLdapLogin,
	},
	"DELETE": {
		"/acs/api/v1/users/{uid:.*}":      deleteUsers,
		"/acs/api/v1/localusers/{uid:.*}": deleteLocalUsers,
		"/acs/api/v1/ldapusers/{uid:.*}":  deleteLdapUsers,
	},
}
