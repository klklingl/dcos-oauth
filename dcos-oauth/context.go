package main

import (
	"golang.org/x/net/context"
)

const (
	keyAllowLocalUsers = "allow-local-users"
	keyAllowLdapUsers = "allow-ldap-users"
	keyLdapConfigFile = "ldap-config-file"
	keyLdapWhitelistOnly = "ldap-whitelist-only"
)

func allowLocalUsers(ctx context.Context) bool {
	return ctx.Value(keyAllowLocalUsers).(bool)
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
