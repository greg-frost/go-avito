package model

type User struct {
	ID    string `json:"id,omitempty"`
	Email string `json:"email"`
	Role  Role   `json:"role"`
}

type UserDTO struct {
	Role Role `json:"role"`
}

type Role string

const (
	RoleEmployee  Role = "employee"
	RoleModerator Role = "moderator"
)

func (r Role) Valid() bool {
	switch r {
	case RoleEmployee, RoleModerator:
		return true
	default:
		return false
	}
}
