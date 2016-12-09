package security

type User struct {
	Username        string
	Email           string
	FirstName       string
	LastName        string
	Roles           []RoleType
	providerType    string
	isAuthenticated bool
}

func (u *User) IsAuthenticated() bool {
	return u.isAuthenticated
}

func (u *User) AuthenticationType() string {
	return u.providerType
}

func (u *User) Name() string {
	return u.Username
}

func (u *User) Identity() Identity {
	return u
}

func (u *User) GetRoles() []RoleType {
	return u.Roles
}

func (u *User) IsInRole(role string) bool {
	if len(u.Roles) == 0 {
		return false
	}
	for _, r := range u.Roles {
		if r != "" && string(r) == role {
			return true
		}
	}
	return false
}

type RoleType string

const (
	ROLE_VIEWER RoleType = "Viewer"
	ROLE_ADMIN  RoleType = "Admin"
)

func (r RoleType) IsValid() bool {
	return r == ROLE_VIEWER || r == ROLE_ADMIN
}
