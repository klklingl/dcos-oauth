package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/net/context"
	"golang.org/x/crypto/bcrypt"

	"github.com/coreos/go-oidc/jose"

	"github.com/dcos/dcos-oauth/common"
)

const (
	defaultLocalUserPassword = "admin"
)

func verifyLocalUser(ctx context.Context, token jose.JWT) error {
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

	isLocal, err := isLocalUser(ctx, uid)
	if err != nil {
		return err
	}
	if !isLocal {
		return fmt.Errorf("No matching local user: %s", uid)
	}
	return nil
}

func handleLocalLogin(ctx context.Context, w http.ResponseWriter, r *http.Request) *common.HttpError {
	if !allowLocalUsers(ctx) {
		log.Printf("Local user login attempted but local users are not allowed")
		return common.NewHttpError("Local user login is not allowed", http.StatusServiceUnavailable)
	}

	uid, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="Ethos Cluster Local Login"`)
		return common.NewHttpError("Not authorized for Ethos cluster access", http.StatusUnauthorized)
	}
	log.Printf("Attempting local login for user %s", uid)

	hasLocal, err1 := hasLocalUsers(ctx)
	isLocal, err2 := isLocalUser(ctx, uid)
	if err1 != nil || err2 != nil {
		log.Printf("handleLocalLogin: errors: %v; %v", err1, err2)
		return common.NewHttpError("local user processing error", http.StatusInternalServerError)
	}
	if hasLocal && isLocal {
		c := ctx.Value("zk").(common.IZk)

		path := fmt.Sprintf("%s/%s", zkLocalPath, uid)
		hash, _, err := c.Get(path)
		if err != nil {
			log.Printf("handleLocalLogin: error getting password for comparison: %v", err)
		}

		err = bcrypt.CompareHashAndPassword(hash, []byte(password))
		if err != nil {
			log.Debugf("handleLocalLogin: error comparing passwords for user %s: %v", uid, err)
			w.Header().Set("WWW-Authenticate", `Basic realm="Ethos Cluster Local Login"`)
			return common.NewHttpError("Invalid username or password", http.StatusUnauthorized)
		}
	} else if uid != defaultLocalUser || password != defaultLocalUserPassword || (hasLocal && !isLocal) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Ethos Cluster Local Login"`)
		return common.NewHttpError("Invalid username or password", http.StatusUnauthorized)
	} else if !hasLocal { // Should only get here for defaultLocalUser, has correct password, and hasn't been removed from local users
		err := addDefaultLocalUser(ctx)
		if err != nil {
			log.Printf("handleLocalLogin: error adding default local user: %v", err)
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

	log.Printf("Successful local login for user %s", uid)
	return nil
}
