package main

import (
	"encoding/base64"
	"encoding/json"
	"encoding/csv"
	"fmt"
	"net/http"
	"time"
	"os"
	"bufio"
	"io"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/net/context"

	"github.com/coreos/go-oidc/jose"
	"github.com/coreos/go-oidc/oidc"
	"github.com/samuel/go-zookeeper/zk"

	"github.com/dcos/dcos-oauth/common"
)

var (
	oauthAdminGroups map[string]bool
)

type loginRequest struct {
	Uid string `json:"uid,omitempty"`

	Password string `json:"password,omitempty"`

	Token string `json:"token,omitempty"`
}

type loginResponse struct {
	Token string `json:"token,omitempty"`
}

func handleLogin(ctx context.Context, w http.ResponseWriter, r *http.Request) *common.HttpError {
	var lr loginRequest
	err := json.NewDecoder(r.Body).Decode(&lr)
	if err != nil {
		log.Printf("Decode: %v", err)
		return common.NewHttpError("JSON decode error", http.StatusBadRequest)
	}

	issuerURL, _ := ctx.Value("issuer-url").(string)
	provCfg, err := oidc.FetchProviderConfig(httpClient, issuerURL)
	if err != nil {
		log.Printf("FetchProviderConfig: %v", err)
		return common.NewHttpError("[OIDC] Fetch provider config error", http.StatusInternalServerError)
	}

	clientID, _ := ctx.Value("client-id").(string)

	cliCfg := oidc.ClientConfig{
		HTTPClient:     httpClient,
		ProviderConfig: provCfg,
		Credentials: oidc.ClientCredentials{
			ID: clientID,
		},
	}
	oidcCli, err := oidc.NewClient(cliCfg)
	if err != nil {
		log.Printf("oidc.NewClient: %v", err)
		return common.NewHttpError("[OIDC] Client creation error", http.StatusInternalServerError)
	}

	token, err := jose.ParseJWT(lr.Token)
	if err != nil {
		log.Printf("ParseJWT: %v", err)
		return common.NewHttpError("JWT parsing failed", http.StatusBadRequest)
	}

	err = oidcCli.VerifyJWT(token)
	if err != nil {
		if err2 := verifyLocalUser(ctx, token); err2 != nil {
			if err3 := verifyLdapUser(ctx, token); err3 != nil {
				log.Printf("VerifyJWT: %v; %v; %v", err, err2, err3)
				return common.NewHttpError("JWT verification failed", http.StatusUnauthorized)
			}
		}
	}

	claims, err := token.Claims()
	if err != nil {
		log.Printf("Claims: %v", err)
		return common.NewHttpError("invalid claims", http.StatusBadRequest)
	}

	// check for Auth0 email verification
	if verified, ok := claims["email_verified"]; ok {
		if b, ok := verified.(bool); ok && !b {
			log.Printf("email not verified")
			return common.NewHttpError("email not verified", http.StatusBadRequest)
		}
	}

	uid, ok, err := claims.StringClaim("email")
	if !ok || err != nil {
		return common.NewHttpError("invalid email claim", http.StatusBadRequest)
	}

	c := ctx.Value("zk").(*zk.Conn)

	users, _, err := c.Children("/dcos/users")
	if err != nil && err != zk.ErrNoNode {
		return common.NewHttpError("invalid email", http.StatusInternalServerError)
	}

	userPath := fmt.Sprintf("/dcos/users/%s", uid)
	if len(users) == 0 && defaultLocalUser(ctx) == "" { // No users yet and no default local user was specified
		// create first user
		log.Printf("creating first user %v", uid)
		err = common.CreateParents(c, userPath, []byte(markerWhitelist))
		if err != nil {
			return common.NewHttpError("Zookeeper error", http.StatusInternalServerError)
		}
	}

	var isOauth, isLocal, isLdap bool
	isOauth, _, err = c.Exists(userPath)
	if err != nil {
		log.Printf("handleLogin: error: %v", err)
		return common.NewHttpError("User unauthorized", http.StatusUnauthorized)
	}
	if !isOauth {
		isLocal, err = isLocalUser(ctx, uid)
		if err != nil {
			log.Printf("handleLogin: error: %v", err)
			return common.NewHttpError("User unauthorized", http.StatusUnauthorized)
		}
		if !isLocal {
			isLdap, err = isLdapUser(ctx, uid)
			if err != nil {
				log.Printf("handleLogin: error: %v", err)
				return common.NewHttpError("User unauthorized", http.StatusUnauthorized)
			}
		}
	}

	if (!isLocal && ldapCheckOnOauth(ctx)) || isLdap {
		err = ldapGroupsCheck(ctx, uid)
		if err != nil {
			log.Printf("handleLogin: LDAP groups check error: %v", err)
			return common.NewHttpError("User unauthorized", http.StatusUnauthorized)
		}
	} else if !isLocal {
		err = oauthGroupsCheck(ctx, uid, nil)
		if err != nil {
			log.Printf("handleLogin: Oauth groups check error: %v", err)
			return common.NewHttpError("User unauthorized", http.StatusUnauthorized)
		}
	}

	if !isOauth && !isLocal && !isLdap {
		// Passed the group check so add new oauth user to the authorized list
		err = common.CreateParents(c, userPath, []byte(markerGroup))
	}

	claims.Add("uid", uid)

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

func handleLogout(ctx context.Context, w http.ResponseWriter, r *http.Request) *common.HttpError {
	// required for IE 6, 7 and 8
	expiresTime := time.Unix(1, 0)

	for _, name := range []string{"dcos-acs-auth-cookie", "dcos-acs-info-cookie"} {
		cookie := &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			Expires:  expiresTime,
			MaxAge:   -1,
		}

		http.SetCookie(w, cookie)
	}

	return nil
}

func oauthGroupsCheck(ctx context.Context, uid string, userGroups []string) error {
	isOnWhitelist, err := onWhitelist(ctx, "/dcos/users", uid)
	if err != nil {
		return err
	}
	if isOnWhitelist {
		// No need to check groups if the user was specifically put on the list
		return nil
	}

	// Get the list of groups that are allowed
	if oauthAdminGroups == nil {
		oauthAdminGroups = make(map[string]bool)
		if oauthAdminGroupsFile(ctx) != "" {
			f, err := os.Open(oauthAdminGroupsFile(ctx))
			if err != nil {
				log.Printf("Error opening oauth admin groups file (%s): %v", oauthAdminGroupsFile(ctx), err)
			} else {
				r := csv.NewReader(bufio.NewReader(f))
				for {
					record, err := r.Read()
					if err == io.EOF { // Stop at EOF.
						break
					} else if err != nil {
						log.Printf("Error parsing content of oauth admin groups file (%s): %v", oauthAdminGroupsFile(ctx), err)
						break
					}
					for _, group := range record {
						if len(group) != 0 {
							oauthAdminGroups[group] = true
						}
					}
				}
			}
		}
	}

	if len(oauthAdminGroups) == 0 {
		return fmt.Errorf("User %s is not authorized for this cluster", uid)
	}

	// Go through all groups for this user until a matching one is found
	for _, userGroup := range userGroups {
		if oauthAdminGroups[userGroup] {
			return nil
		}
	}

	return fmt.Errorf("User %s is not a member of an oauth group with admin role for this cluster", uid)
}
