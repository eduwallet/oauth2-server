package models

// TokenRequest represents an OAuth2 token request
type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	Code         string `json:"code,omitempty"`
	RedirectURI  string `json:"redirect_uri,omitempty"`
	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
	Username     string `json:"username,omitempty"`
	Password     string `json:"password,omitempty"`
}

// TokenResponse represents an OAuth2 token response
type TokenResponse struct {
	AccessToken  string   `json:"access_token"`
	TokenType    string   `json:"token_type"`
	ExpiresIn    int      `json:"expires_in"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	Scope        string   `json:"scope,omitempty"`
	Audience     []string `json:"audience,omitempty"`
	IDToken      string   `json:"id_token,omitempty"`
}

// RefreshTokenRequest represents a refresh token request
type RefreshTokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope,omitempty"`
}

// RefreshTokenResponse represents a refresh token response (alias for TokenResponse)
type RefreshTokenResponse = TokenResponse

// TokenExchangeRequest represents a token exchange request
type TokenExchangeRequest struct {
	GrantType          string `json:"grant_type"`
	ClientID           string `json:"client_id"`
	ClientSecret       string `json:"client_secret"`
	SubjectToken       string `json:"subject_token"`
	SubjectTokenType   string `json:"subject_token_type"`
	RequestedTokenType string `json:"requested_token_type,omitempty"`
	Audience           string `json:"audience,omitempty"`
	Scope              string `json:"scope,omitempty"`
}

// TokenExchangeResponse represents a token exchange response
type TokenExchangeResponse struct {
	AccessToken     string   `json:"access_token"`
	IssuedTokenType string   `json:"issued_token_type"`
	TokenType       string   `json:"token_type"`
	ExpiresIn       int64    `json:"expires_in"`
	Scope           string   `json:"scope,omitempty"`
	Audience        []string `json:"audience,omitempty"`
	RefreshToken    string   `json:"refresh_token,omitempty"`
}

// IntrospectionRequest represents a token introspection request
type IntrospectionRequest struct {
	Token         string `json:"token"`
	TokenTypeHint string `json:"token_type_hint,omitempty"`
}

// TokenValidationResponse represents a token validation response
type TokenValidationResponse struct {
	Valid  bool   `json:"valid"`
	Active bool   `json:"active"`
	Token  string `json:"token,omitempty"`
}

// IntrospectionResponse represents a token introspection response
type IntrospectionResponse struct {
	Active    bool     `json:"active"`
	ClientID  string   `json:"client_id,omitempty"`
	Username  string   `json:"username,omitempty"`
	Scope     string   `json:"scope,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
	Exp       int64    `json:"exp,omitempty"`
	Iat       int64    `json:"iat,omitempty"`
	Nbf       int64    `json:"nbf,omitempty"`
	Sub       string   `json:"sub,omitempty"`
	Aud       []string `json:"aud,omitempty"`
	Iss       string   `json:"iss,omitempty"`
	Jti       string   `json:"jti,omitempty"`
}
