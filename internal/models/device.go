package models

import "time"

// DeviceAuthorization represents a device authorization request
type DeviceAuthorization struct {
	DeviceCode   string    `json:"device_code"`
	UserCode     string    `json:"user_code"`
	ClientID     string    `json:"client_id"`
	Scopes       []string  `json:"scopes"`
	Audiences    []string  `json:"audiences,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	IssuedAt     time.Time `json:"issued_at"`
	Authorized   bool      `json:"authorized"`
	UserID       string    `json:"user_id,omitempty"`
	AccessToken  string    `json:"access_token,omitempty"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	Used         bool      `json:"used"`
}

// IsExpired checks if the device authorization has expired
func (d *DeviceAuthorization) IsExpired() bool {
	return time.Now().After(d.ExpiresAt)
}

// IsPending checks if the device authorization is still pending
func (d *DeviceAuthorization) IsPending() bool {
	return !d.Authorized && !d.IsExpired()
}

// IsAuthorized checks if the device has been authorized by a user
func (d *DeviceAuthorization) IsAuthorized() bool {
	return d.Authorized && !d.IsExpired()
}

// CanIssueToken checks if the device authorization can be used to issue a token
func (d *DeviceAuthorization) CanIssueToken() bool {
	return d.Authorized && !d.Used && !d.IsExpired()
}

// DeviceCodeRequest represents a device authorization request
type DeviceCodeRequest struct {
	ClientID string `json:"client_id"`
	Scope    string `json:"scope,omitempty"`
}

// DeviceCodeResponse represents a device authorization response
type DeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete,omitempty"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

// DeviceTokenRequest represents a device token request
type DeviceTokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	DeviceCode   string `json:"device_code"`
}
