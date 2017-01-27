package main

import (
	"golang.org/x/net/context"
)

const (
	keyAllowLocalUsers = "allow-local-users"
	keyDefaultLocalUser = "default-local-user"
	keyDefaultLocalUserHash = "default-local-user-hash"
	keyAllowLdapUsers = "allow-ldap-users"
	keyLdapConfigFile = "ldap-config-file"
	keyLdapWhitelistOnly = "ldap-whitelist-only"
	keyLdapGroupsOnly = "ldap-groups-only"
	keyLdapCheckOnOauth = "ldap-check-on-oauth"
	keyAdminGroupsFile = "admin-groups-file"
)

func allowLocalUsers(ctx context.Context) bool {
	return ctx.Value(keyAllowLocalUsers).(bool)
}

func defaultLocalUser(ctx context.Context) string {
	return ctx.Value(keyDefaultLocalUser).(string)
}

func defaultLocalUserHash(ctx context.Context) string {
	return ctx.Value(keyDefaultLocalUserHash).(string)
}

func allowLdapUsers(ctx context.Context) bool {
	return ctx.Value(keyAllowLdapUsers).(bool)
}

func ldapConfigFile(ctx context.Context) string {
	return ctx.Value(keyLdapConfigFile).(string)
}

func ldapWhitelistOnly(ctx context.Context) bool {
	return ctx.Value(keyLdapWhitelistOnly).(bool)
}

func ldapGroupsOnly(ctx context.Context) bool {
	return ctx.Value(keyLdapGroupsOnly).(bool)
}

func ldapCheckOnOauth(ctx context.Context) bool {
	return ctx.Value(keyLdapCheckOnOauth).(bool)
}

func oauthAdminGroupsFile(ctx context.Context) string {
	return ctx.Value(keyAdminGroupsFile).(string)
}

