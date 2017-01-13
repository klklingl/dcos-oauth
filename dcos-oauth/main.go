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
				flAllowLocalUsers, flAllowLdapUsers, flLdapConfigFile, flLdapWhitelistOnly},
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
	} else {
		fmt.Println("Local users NOT allowed")
	}

	bVal, err = strconv.ParseBool(c.String(keyAllowLdapUsers))
	if err != nil {
		return err
	}
	ctx = context.WithValue(ctx, keyAllowLdapUsers, bVal)
	if allowLdapUsers(ctx) {
		fmt.Println("LDAP users allowed")
	} else {
		fmt.Println("LDAP users NOT allowed")
	}

	ctx = context.WithValue(ctx, keyLdapConfigFile, c.String(keyLdapConfigFile))

	bVal, err = strconv.ParseBool(c.String(keyLdapWhitelistOnly))
	if err != nil {
		return err
	}
	ctx = context.WithValue(ctx, keyLdapWhitelistOnly, bVal)
	if ldapWhitelistOnly(ctx) {
		fmt.Println("LDAP users must be on the whitelist")
	}

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
