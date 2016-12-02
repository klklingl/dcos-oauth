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
)

const (
	defaultLocalUserPassword = "admin"
	prependPassword = "local"
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
	//TODO: Is there a way to set a TTL for the header

	uid, password, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="Ethos Cluster"`)
		return common.NewHttpError("Not authorized for Ethos cluster access", http.StatusUnauthorized)
	}

	hasLocal, err1 := hasLocalUsers(ctx)
	isLocal, err2 := isLocalUser(ctx, uid)
	if err1 != nil || err2 != nil {
		log.Printf("handleLocalLogin: errors: %v; %v", err1, err2)
		return common.NewHttpError("local user processing error", http.StatusInternalServerError)
	}
	if hasLocal && isLocal {
		isMatchingPassword := false
		if uid == defaultLocalUser {
			isMatchingPassword = password == defaultLocalUserPassword
		} else {
			isMatchingPassword = password == prependPassword + uid
		}
		if !isMatchingPassword {
			w.Header().Set("WWW-Authenticate", `Basic realm="Ethos Cluster"`)
			return common.NewHttpError("Invalid username or password", http.StatusUnauthorized)
		}
	} else if uid != defaultLocalUser || password != defaultLocalUserPassword || (hasLocal && !isLocal) {
		w.Header().Set("WWW-Authenticate", `Basic realm="Ethos Cluster"`)
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
