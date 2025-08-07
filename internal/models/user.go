package models

import "time"

// User represents a user in the system
type User struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Password  string    `json:"password,omitempty"` // Don't include in JSON responses
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	FirstName string    `json:"first_name,omitempty"`
	LastName  string    `json:"last_name,omitempty"`
	Roles     []string  `json:"roles,omitempty"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// UserProfile represents a user's profile information
type UserProfile struct {
	Sub                 string   `json:"sub"`
	Name                string   `json:"name,omitempty"`
	GivenName           string   `json:"given_name,omitempty"`
	FamilyName          string   `json:"family_name,omitempty"`
	MiddleName          string   `json:"middle_name,omitempty"`
	Nickname            string   `json:"nickname,omitempty"`
	PreferredUsername   string   `json:"preferred_username,omitempty"`
	Profile             string   `json:"profile,omitempty"`
	Picture             string   `json:"picture,omitempty"`
	Website             string   `json:"website,omitempty"`
	Email               string   `json:"email,omitempty"`
	EmailVerified       bool     `json:"email_verified,omitempty"`
	Gender              string   `json:"gender,omitempty"`
	Birthdate           string   `json:"birthdate,omitempty"`
	Zoneinfo            string   `json:"zoneinfo,omitempty"`
	Locale              string   `json:"locale,omitempty"`
	PhoneNumber         string   `json:"phone_number,omitempty"`
	PhoneNumberVerified bool     `json:"phone_number_verified,omitempty"`
	Address             *Address `json:"address,omitempty"`
	UpdatedAt           int64    `json:"updated_at,omitempty"`
}

// Address represents a user's address
type Address struct {
	Formatted     string `json:"formatted,omitempty"`
	StreetAddress string `json:"street_address,omitempty"`
	Locality      string `json:"locality,omitempty"`
	Region        string `json:"region,omitempty"`
	PostalCode    string `json:"postal_code,omitempty"`
	Country       string `json:"country,omitempty"`
}

// // ValidateUser validates user data
// func (u *User) ValidateUser() error {
// 	if u.Username == "" {
// 		return ErrInvalidUsername
// 	}
// 	if u.Email == "" {
// 		return ErrInvalidEmail
// 	}
// 	return nil
// }

// GetProfile returns a user profile for OIDC
func (u *User) GetProfile() *UserProfile {
	return &UserProfile{
		Sub:               u.ID,
		Name:              u.Name,
		PreferredUsername: u.Username,
		Email:             u.Email,
		EmailVerified:     true, // You might want to track this separately
	}
}
