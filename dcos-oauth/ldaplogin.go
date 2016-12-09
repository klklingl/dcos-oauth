package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/net/context"

	"github.com/coreos/go-oidc/jose"

	"github.com/dcos/dcos-oauth/common"
	"github.com/dcos/dcos-oauth/security/ldap"
)

const (
	ldapLoginEnabled = true  //TODO: This should come from a config file somewhere
	ldapConfig = "/opt/mesosphere/etc/ldap.toml"
	ldapWhitelistOnly = false  //TODO: This should come from a config file somewhere
)

func verifyLdapUser(ctx context.Context, token jose.JWT) error {
	claims, err := token.Claims()
	if err != nil {
		return err
	}

	uid, ok, err := claims.StringClaim("email")
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("Invalid email claim for local user")
	}

	isLdap, err := isLdapUser(ctx, uid)
	if err != nil {
		return err
	}
	if !isLdap {
		return fmt.Errorf("No matching ldap user: %s", uid)
	}
	return nil
}

func handleLdapLogin(ctx context.Context, w http.ResponseWriter, r *http.Request) *common.HttpError {
	if !ldapLoginEnabled {
		return common.NewHttpError("LDAP login not enabled", http.StatusServiceUnavailable)
	}

	uid, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="Ethos Cluster LDAP Login"`)
		return common.NewHttpError("Not authorized for Ethos cluster access", http.StatusUnauthorized)
	}

	config, err := ldap.ConfigFromFile(ldapConfig)
	if err != nil {
		log.Printf("Config: error: %v", err)
		return common.NewHttpError("LDAP reading config failed", http.StatusInternalServerError)
	}

	provider := ldap.NewProvider(config)
	if err := provider.Initialize("ldap"); err != nil {
		log.Printf("Initialize: error: %v", err)
		return common.NewHttpError("LDAP initialization failed", http.StatusInternalServerError)
	}

	defer provider.Close()
	_, err = provider.ValidateUser(uid, password)
	if err != nil {
		log.Printf("ValidateUser: error: %v", err)
		w.Header().Set("WWW-Authenticate", `Basic realm="Ethos Cluster LDAP Login"`)
		return common.NewHttpError("Invalid LDAP username or password", http.StatusUnauthorized)
	}

	isLdap, err := isLdapUser(ctx, uid)
	if err != nil {
		log.Printf("isLdapUser: error: %v", err)
		return common.NewHttpError("LDAP user processing error", http.StatusInternalServerError)
	}
	if !isLdap {
		if ldapWhitelistOnly {
			log.Printf("handleLdapLogin: LDAP user %s is not on the whitelist", uid)
			w.Header().Set("WWW-Authenticate", `Basic realm="Ethos Cluster LDAP Login"`)
			return common.NewHttpError("LDAP user unauthorized", http.StatusUnauthorized)
		}
		log.Printf("Adding LDAP user %s", uid)
		err = addLdapUser(ctx, uid)
		if err != nil {
			log.Printf("handleLdapLogin: error adding LDAP user: %v", err)
		}
	}

	claims := make(jose.Claims)
	claims.Add("uid", uid)
	claims.Add("email", uid)

	secretKey, _ := ctx.Value("secret-key").([]byte)

	clusterToken, err := jose.NewSignedJWT(claims, jose.NewSignerHMAC("secret", secretKey))
	if err != nil {
		return common.NewHttpError("JWT creation error", http.StatusInternalServerError)
	}
	encodedClusterToken := clusterToken.Encode()

	const cookieMaxAge = 388800
	// required for IE 6, 7 and 8
	expiresTime := time.Now().Add(cookieMaxAge * time.Second)

	authCookie := &http.Cookie{
		Name:     "dcos-acs-auth-cookie",
		Value:    encodedClusterToken,
		Path:     "/",
		HttpOnly: true,
		Expires:  expiresTime,
		MaxAge:   cookieMaxAge,
	}
	http.SetCookie(w, authCookie)

	user := User{
		Uid:         uid,
		Description: uid,
		IsRemote:    false,
	}
	userBytes, err := json.Marshal(user)
	if err != nil {
		log.Printf("Marshal: %v", err)
		return common.NewHttpError("JSON marshalling failed", http.StatusInternalServerError)
	}
	infoCookie := &http.Cookie{
		Name:    "dcos-acs-info-cookie",
		Value:   base64.URLEncoding.EncodeToString(userBytes),
		Path:    "/",
		Expires: expiresTime,
		MaxAge:  cookieMaxAge,
	}
	http.SetCookie(w, infoCookie)

	json.NewEncoder(w).Encode(loginResponse{Token: encodedClusterToken})

	return nil
}
