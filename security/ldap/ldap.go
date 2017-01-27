package ldap

import (
	"github.com/dcos/dcos-oauth/security"
	"crypto/tls"
	"errors"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/go-ldap/ldap"
	"strings"
)

type LdapResultCode uint8

const (
	INVALID_CREDENTIALS LdapResultCode = 49
)

func (s *ServerConfig) Address() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

func (s *ServerConfig) getConn() (conn *ldap.Conn, err error) {
	if s.UseSSL {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: s.SkipVerifySSL,
			ServerName:         s.Host,
		}
		conn, err = ldap.DialTLS("tcp", s.Address(), tlsCfg)
	} else {
		conn, err = ldap.Dial("tcp", s.Address())
	}
	return
}

func (s *ServerConfig) getBindPath(username string) string {
	bindPath := s.BindDN
	if strings.Contains(bindPath, "%s") {
		bindPath = fmt.Sprintf(s.BindDN, username)
	}
	return bindPath
}

func (a *Provider) dial() (err error) {
	a.conn, err = a.server.getConn()
	return
}

func (a *Provider) secondBind(ldapUser *User, userPassword string) error {
	return a.bind(ldapUser.DN, userPassword)
}

func (a *Provider) initialBind(username, userPassword string) error {
	if a.server.BindPassword != "" || a.server.BindDN == "" {
		userPassword = a.server.BindPassword
		a.requireSecondBind = true
	}
	return a.bind(
		a.server.getBindPath(username),
		userPassword,
	)
}

func (a *Provider) bind(path, pw string) error {
	if err := a.conn.Bind(path, pw); err != nil {
		log.Info("LDAP initial bind failed, %v", err)
		if ldapErr, ok := err.(*ldap.Error); ok {
			if ldapErr.ResultCode == uint8(INVALID_CREDENTIALS) {
				return security.ErrInvalidCredentials
			}
		}
		return err
	}
	return nil
}

func (a *Provider) validateUser(un, pwd string) (user *User, err error) {
	// perform initial authentication
	if err := a.initialBind(un, pwd); err != nil {
		return nil, err
	}
	// find user entry & attributes
	if user, err := a.searchForUser(un); err != nil {
		return nil, err
	} else {
		log.Debug("Ldap User Info: %#v", user)
		// check if a second user bind is needed
		if a.requireSecondBind {
			if err := a.secondBind(user, pwd); err != nil {
				return nil, err
			}
		}
		user.isAuthenticated = true
		return user, nil
	}
}

func (a *Provider) first(search *ldap.SearchRequest) (searchResult *ldap.SearchResult, err error) {
	for _, searchBase := range a.server.SearchBaseDNs {
		search.BaseDN = searchBase
		searchResult, err = a.conn.Search(search)
		if err != nil {
			return
		}
		if len(searchResult.Entries) > 0 {
			break
		}
	}
	if len(searchResult.Entries) > 1 {
		return nil, errors.New("Ldap search matched more than one entry, please review your filter setting")
	}
	return
}

func (a *Provider) searchForUserByEmail(email string) (*User, error) {
	return a.searchForUserByFilter(strings.Replace(a.server.EmailFilter, "%s", email, -1))
}

func (a *Provider) searchForUser(username string) (*User, error) {
	return a.searchForUserByFilter(strings.Replace(a.server.SearchFilter, "%s", username, -1))
}

func (a *Provider) searchForUserByFilter(filter string) (*User, error) {
	searchReq := &ldap.SearchRequest{
		Scope:        ldap.ScopeWholeSubtree,
		DerefAliases: ldap.NeverDerefAliases,
		Attributes: []string{
			a.server.Attr.Username,
			a.server.Attr.Surname,
			a.server.Attr.Email,
			a.server.Attr.Name,
			a.server.Attr.MemberOf,
		},
		Filter: filter,
	}
	searchResult, err := a.first(searchReq)
	if err != nil {
		return nil, err
	}
	if len(searchResult.Entries) == 0 {
		return nil, security.ErrInvalidCredentials
	}
	return a.buildUserFromSearchResult(searchResult), nil
}

func (a *Provider) buildUserFromSearchResult(sr *ldap.SearchResult) *User {
	return &User{
		DN:         sr.Entries[0].DN,
		LastName:   getLdapAttr(a.server.Attr.Surname, sr),
		FirstName:  getLdapAttr(a.server.Attr.Name, sr),
		Username:   getLdapAttr(a.server.Attr.Username, sr),
		Email:      getLdapAttr(a.server.Attr.Email, sr),
		Membership: getLdapAttrArray(a.server.Attr.MemberOf, sr),
	}
}

func (a *Provider) mapToOrgUser(u *User) *security.User {
	roles := make([]security.RoleType, 0, 0)
	for _, g := range a.server.LdapGroups {
		for _, r := range u.Membership {
			if g.GroupDN == r {
				roles = append(roles, g.OrgRole)
			}
		}
	}
	return &security.User{
		Username:      u.Username,
		FirstName:     u.FirstName,
		LastName:      u.LastName,
		Email:         u.Email,
		Roles:         roles,
		Authenticated: u.isAuthenticated,
	}
}

//func (a *User) toOrgUser() *security.User {
//	roles := []security.RoleType{
//		security.ROLE_ADMIN,
//	}
//	return &security.User{
//		Username:  a.Username,
//		FirstName: a.FirstName,
//		LastName:  a.LastName,
//		Email:     a.Email,
//		Roles:     roles,
//	}
//}

func getLdapAttr(name string, search *ldap.SearchResult) (result string) {
	for _, attr := range search.Entries[0].Attributes {
		if attr.Name == name {
			if len(attr.Values) > 0 {
				result = attr.Values[0]
				break
			}
		}
	}
	return
}

func getLdapAttrArray(name string, search *ldap.SearchResult) (result []string) {
	for _, attr := range search.Entries[0].Attributes {
		if attr.Name == name {
			result = attr.Values
			break
		}
	}
	return
}
