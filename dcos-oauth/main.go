package main

import (
	"os"
	"fmt"
	"strconv"

	"github.com/codegangsta/cli"
	"golang.org/x/net/context"

	"github.com/dcos/dcos-oauth/common"
)

func main() {
	serveCommand := cli.Command{
		Name:      "serve",
		ShortName: "s",
		Usage:     "Serve the API",
		Flags:     []cli.Flag{common.FlAddr, common.FlZkAddr, flIssuerURL, flClientID, flSecretKeyPath, flSegmentKey,
				flAllowLocalUsers, flDefaultLocalUser, flDefaultLocalUserHash,
				flAllowLdapUsers, flLdapConfigFile, flLdapWhitelistOnly, flLdapGroupsOnly,
				flLdapCheckOnOauth, flOauthAdminGroupsFile},
		Action:    action(serveAction),
	}

	common.Run("dcos-oauth", serveCommand)
}

func serveAction(c *cli.Context) error {
	ctx := context.Background()

	ctx = context.WithValue(ctx, "issuer-url", c.String("issuer-url"))
	ctx = context.WithValue(ctx, "client-id", c.String("client-id"))
	ctx = context.WithValue(ctx, "segment-key", c.String("segment-key"))

	secretKey, err := common.ReadLine(c.String("secret-key-path"))
	if err != nil {
		return err
	}
	ctx = context.WithValue(ctx, "secret-key", secretKey)

	// TODO not used everywhere yet
	ctx = context.WithValue(ctx, "zk-path", "/dcos/users")

	bVal, err := strconv.ParseBool(c.String(keyAllowLocalUsers))
	if err != nil {
		return err
	}
	ctx = context.WithValue(ctx, keyAllowLocalUsers, bVal)
	if allowLocalUsers(ctx) {
		fmt.Println("Local users allowed")

		ctx = context.WithValue(ctx, keyDefaultLocalUser, c.String(keyDefaultLocalUser))
		uid := defaultLocalUser(ctx)
		if uid == "" {
			fmt.Println("No default local user specified")
		} else {
			if !validateLocalUser(uid) {
				return fmt.Errorf("Invalid default local user %s", uid)
			}
			fmt.Printf("Using %s as default local user\n", uid)

			// If the default local user already exists, the stored hash will take precedence over this hash
			hash := c.String(keyDefaultLocalUserHash)
			if hash == "" {
				return fmt.Errorf("Setting a default local user requires a password hash")
			}
			ctx = context.WithValue(ctx, keyDefaultLocalUserHash, hash)
		}
	} else {
		fmt.Println("Local users NOT allowed")
		ctx = context.WithValue(ctx, keyDefaultLocalUser, "")
	}

	bVal, err = strconv.ParseBool(c.String(keyAllowLdapUsers))
	if err != nil {
		return err
	}
	ctx = context.WithValue(ctx, keyAllowLdapUsers, bVal)
	if allowLdapUsers(ctx) {
		fmt.Println("LDAP users allowed")

		bVal, err = strconv.ParseBool(c.String(keyLdapWhitelistOnly))
		if err != nil {
			return err
		}
		ctx = context.WithValue(ctx, keyLdapWhitelistOnly, bVal)
		if ldapWhitelistOnly(ctx) {
			fmt.Println("LDAP users must be on the whitelist")
		}

		bVal, err = strconv.ParseBool(c.String(keyLdapGroupsOnly))
		if err != nil {
			return err
		}
		ctx = context.WithValue(ctx, keyLdapGroupsOnly, bVal)
		if ldapGroupsOnly(ctx) {
			fmt.Println("LDAP users must be in an LDAP group with admin role")
		}
	} else {
		fmt.Println("LDAP users NOT allowed")
	}

	bVal, err = strconv.ParseBool(c.String(keyLdapCheckOnOauth))
	if err != nil {
		return err
	}
	ctx = context.WithValue(ctx, keyLdapCheckOnOauth, bVal)
	if ldapCheckOnOauth(ctx) {
		fmt.Println("LDAP groups checked during Oauth login")
	}

	ctx = context.WithValue(ctx, keyLdapConfigFile, c.String(keyLdapConfigFile))

	ctx = context.WithValue(ctx, keyAdminGroupsFile, c.String(keyAdminGroupsFile))

	return common.ServeCmd(c, ctx, routes)
}

func action(f func(c *cli.Context) error) func(c *cli.Context) {
	return func(c *cli.Context) {
		err := f(c)
		if err != nil {
			os.Exit(1)
		}
	}
}
