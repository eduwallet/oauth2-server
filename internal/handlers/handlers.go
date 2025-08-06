package handlers

import (
	"html/template"

	"github.com/sirupsen/logrus"

	"oauth2-server/internal/config"
	"oauth2-server/internal/storage"

	"golang.org/x/oauth2"
)

// Handlers holds all the dependencies needed by HTTP handlers
type Handlers struct {
	Config         *config.Config
	Store           *storage.Storage
	Templates      *template.Template
	Logger         *logrus.Logger
	OAuth2Provider *oauth2.Provider
}

// NewHandlers creates a new handlers instance with dependencies
func NewHandlers(
	config *config.Config,
	store *storage.Storage,
	templates *template.Template,
	logger *logrus.Logger,
	oauth2Provider *oauth2.Provider,
) *Handlers {
	return &Handlers{
		Config:         config,
		Store:          store,
		Templates:      templates,
		Logger:         logger,
		OAuth2Provider: oauth2Provider,
	}
}

// OAuth2 request/response structures
type AuthorizeRequest = storage.AuthorizeRequest
type DeviceCodeResponse = storage.DeviceCodeResponse
type DeviceCodeState = storage.DeviceCodeState

type TokenRequest struct {
	GrantType          string `json:"grant_type"`
	Code               string `json:"code,omitempty"`
	RedirectURI        string `json:"redirect_uri,omitempty"`
	ClientID           string `json:"client_id,omitempty"`
	ClientSecret       string `json:"client_secret,omitempty"`
	Username           string `json:"username,omitempty"`
	Password           string `json:"password,omitempty"`
	Scope              string `json:"scope,omitempty"`
	SubjectToken       string `json:"subject_token,omitempty"`
	SubjectTokenType   string `json:"subject_token_type,omitempty"`
	RequestedTokenType string `json:"requested_token_type,omitempty"`
	DeviceCode         string `json:"device_code,omitempty"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}
