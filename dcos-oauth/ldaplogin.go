package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"strings"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/net/context"

	"github.com/coreos/go-oidc/jose"

	"github.com/dcos/dcos-oauth/common"
	"github.com/dcos/dcos-oauth/security/ldap"
	"github.com/dcos/dcos-oauth/security"
)

var (
	ldapConfig *ldap.Config
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
		return fmt.Errorf("Invalid email claim for ldap user")
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
	if !allowLdapUsers(ctx) {
		log.Printf("LDAP login attempted but LDAP users are not allowed")
		return common.NewHttpError("LDAP user login is not allowed", http.StatusServiceUnavailable)
	}

	uid, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="Ethos Cluster LDAP Login"`)
		return common.NewHttpError("Not authorized for Ethos cluster access", http.StatusUnauthorized)
	}
	if uid == "" {
		log.Debugf("handleLdapLogin: no user specified")
		w.Header().Set("WWW-Authenticate", `Basic realm="Ethos Cluster Local Login"`)
		return common.NewHttpError("Invalid LDAP username or password", http.StatusUnauthorized)
	}
	log.Printf("Attempting LDAP login for user %s", uid)
	var err error

	if ldapConfig == nil {
		ldapConfig, err = ldap.ConfigFromFile(ldapConfigFile(ctx))
		if err != nil {
			log.Printf("Config: error: %v", err)
			return common.NewHttpError("LDAP reading config failed", http.StatusInternalServerError)
		}
	}

	provider := ldap.NewProvider(ldapConfig)
	if err := provider.Initialize("ldap"); err != nil {
		log.Printf("Initialize: error: %v", err)
		return common.NewHttpError("LDAP initialization failed", http.StatusInternalServerError)
	}

	defer provider.Close()

	ldapuser, err := provider.ValidateUser(uid, password)
	if err != nil || !ldapuser.Identity().IsAuthenticated() {
		if (err != nil) {
			log.Printf("ValidateUser: error: %v", err)
		} else {
			log.Printf("ValidateUser: user not successfully authenticated")
		}
		w.Header().Set("WWW-Authenticate", `Basic realm="Ethos Cluster LDAP Login"`)
		return common.NewHttpError("Invalid LDAP username or password", http.StatusUnauthorized)
	}

	isLdap, err := isLdapUser(ctx, uid)
	if err != nil {
		log.Printf("isLdapUser: error: %v", err)
		return common.NewHttpError("LDAP user processing error", http.StatusInternalServerError)
	}
	if !isLdap && ldapWhitelistOnly(ctx) {
		log.Printf("handleLdapLogin: LDAP user %s is not on the whitelist", uid)
		w.Header().Set("WWW-Authenticate", `Basic realm="Ethos Cluster LDAP Login"`)
		return common.NewHttpError("LDAP user unauthorized", http.StatusUnauthorized)
	}

	checkNeeded := true
	if !ldapGroupsOnly(ctx) && isLdap  {
		isOnWhitelist, err := onWhitelist(ctx, zkLdapPath, uid)
		if (isOnWhitelist && err == nil) {
			checkNeeded = false
		}
	}
	if checkNeeded {
		if !(ldapuser.IsInRole(string(security.ROLE_ADMIN)) ||
			(len(ldapuser.GetRoles()) == 0 && ldapConfig.Server.DefaultRole == string(security.ROLE_ADMIN))) {
			log.Printf("handleLdapLogin: LDAP user %s is not a member of an LDAP group with admin role for this cluster", uid)
			w.Header().Set("WWW-Authenticate", `Basic realm="Ethos Cluster LDAP Login"`)
			return common.NewHttpError("LDAP user unauthorized", http.StatusUnauthorized)
		}
	}

	claims := make(jose.Claims)
	claims.Add("uid", uid)
	claims.Add("email", uid)

	secretKey, _ := ctx.Value("secret-key").([]byte)

	clusterToken, err := jose.NewSignedJWT(claims, jose.NewSignerHMAC("secret", secretKey))
	if err != nil {
		log.Printf("JWT: error: %v", err)
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

	if !isLdap {
		log.Printf("Adding LDAP user %s", uid)
		err = addLdapUser(ctx, uid)
		if err != nil {
			log.Printf("handleLdapLogin: error adding LDAP user: %v", err)
		}
	}

	log.Printf("Successful LDAP login for user %s", uid)
	return nil
}

func ldapGroupsCheck(ctx context.Context, uid string) error {
	isOauth := strings.ContainsAny(uid, "@")

	var zkPath string
	if isOauth {
		zkPath = "/dcos/users"
	} else {
		zkPath = zkLdapPath
	}

	isOnWhitelist, err := onWhitelist(ctx, zkPath, uid)
	if err != nil {
		return err
	}
	if isOnWhitelist {
		// No need to check groups if the user was specifically put on the list
		return nil
	}

	if ldapConfig == nil {
		ldapConfig, err = ldap.ConfigFromFile(ldapConfigFile(ctx))
		if err != nil {
			return err
		}
	}

	provider := ldap.NewProvider(ldapConfig)
	if err := provider.Initialize("ldap"); err != nil {
		return err
	}

	defer provider.Close()

	var ldapuser security.Principal
	if isOauth {
		ldapuser, err = provider.GetUserByEmail(uid)
	} else {
		ldapuser, err = provider.GetUser(uid)
	}
	if err != nil {
		return err
	}

	if !(ldapuser.IsInRole(string(security.ROLE_ADMIN)) ||
		(len(ldapuser.GetRoles()) == 0 && ldapConfig.Server.DefaultRole == string(security.ROLE_ADMIN))) {
		return fmt.Errorf("handleLogin: LDAP user %s is not a member of an LDAP group with admin role for this cluster", uid)
	}

	return nil
}

func onWhitelist(ctx context.Context, path, uid string) (bool, error) {
	c := ctx.Value("zk").(common.IZk)
	zkPath := fmt.Sprintf("%s/%s", path, uid)
	exists, _, err := c.Exists(zkPath)
	if err == nil && exists {
		val, _, err := c.Get(zkPath)
		if err != nil {
			log.Printf("onWhitelist: error getting zk data: %v", err)
		} else {
			if strings.Compare(string(val), markerWhitelist) == 0 ||
				strings.Compare(string(val), uid) == 0 { // Compare to uid for backwards compatibility
				return true, nil
			}
		}
	}
	return false, err
}