package handlers

import (
	"fmt"
	"html/template"
	"net/http"
	"oauth2-server/pkg/config"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// ClaimsHandler displays user claims after successful authentication
type ClaimsHandler struct {
	Config *config.Config
	Logger *logrus.Logger
}

// ClaimsData represents the data passed to the claims template
type ClaimsData struct {
	ClientID         string
	AuthTime         string
	Scopes           []string
	UserClaims       UserClaimsData
	AccessToken      string
	IDToken          string
	RefreshToken     string
	AdditionalClaims map[string]interface{}
}

// UserClaimsData represents user claim information
type UserClaimsData struct {
	Subject   string
	Username  string
	Name      string
	Email     string
	Issuer    string
	IssuedAt  string
	ExpiresAt string
	Audience  string
}

// NewClaimsHandler creates a new claims display handler
func NewClaimsHandler(config *config.Config, logger *logrus.Logger) *ClaimsHandler {
	return &ClaimsHandler{
		Config: config,
		Logger: logger,
	}
}

// ServeHTTP handles the claims display request
func (h *ClaimsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Logger.Info("📋 Displaying user claims page")

	// In a real implementation, you would:
	// 1. Validate the session/token
	// 2. Extract claims from the authenticated user's session or token
	// 3. Get the actual token values from the session

	// For demo purposes, we'll extract data from query parameters or session
	claimsData := h.extractClaimsFromRequest(r)

	// Load and execute the template
	tmpl, err := template.ParseFiles("templates/claims_display.html")
	if err != nil {
		h.Logger.WithError(err).Error("Failed to parse claims template")
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, claimsData); err != nil {
		h.Logger.WithError(err).Error("Failed to execute claims template")
		http.Error(w, "Template execution error", http.StatusInternalServerError)
		return
	}

	h.Logger.Info("✅ Claims page displayed successfully")
}

// extractClaimsFromRequest extracts claims data from the request
// In a real implementation, this would come from validated tokens/sessions
func (h *ClaimsHandler) extractClaimsFromRequest(r *http.Request) ClaimsData {
	// Extract parameters (in real implementation, this would come from session/token)
	query := r.URL.Query()

	clientID := query.Get("client_id")
	if clientID == "" {
		clientID = "demo-client"
	}

	username := query.Get("username")
	if username == "" {
		username = "john.doe"
	}

	// Get user information from config
	var user *config.User
	if foundUser, exists := h.Config.GetUserByUsername(username); exists {
		user = foundUser
	} else {
		// Fallback demo user
		user = &config.User{
			ID:       "demo-user-1",
			Username: "john.doe",
			Name:     "John Doe",
			Email:    "john.doe@example.com",
			Password: "password123",
		}
	}

	// Extract tokens from query parameters (in real implementation, from actual auth flow)
	accessToken := query.Get("access_token")
	idToken := query.Get("id_token")
	refreshToken := query.Get("refresh_token")

	// Parse scopes
	scopesStr := query.Get("scope")
	scopes := []string{"openid", "profile", "email"}
	if scopesStr != "" {
		scopes = strings.Split(scopesStr, " ")
	}

	now := time.Now()
	issuer := h.Config.PublicBaseURL
	if issuer == "" {
		issuer = fmt.Sprintf("http://localhost:%d", h.Config.Server.Port)
	}

	claimsData := ClaimsData{
		ClientID: clientID,
		AuthTime: now.Format("2006-01-02 15:04:05 MST"),
		Scopes:   scopes,
		UserClaims: UserClaimsData{
			Subject:   user.Username,
			Username:  user.Username,
			Name:      user.Name,
			Email:     user.Email,
			Issuer:    issuer,
			IssuedAt:  now.Format("2006-01-02 15:04:05 MST"),
			ExpiresAt: now.Add(time.Hour).Format("2006-01-02 15:04:05 MST"),
			Audience:  clientID,
		},
		AccessToken:  accessToken,
		IDToken:      idToken,
		RefreshToken: refreshToken,
		AdditionalClaims: map[string]interface{}{
			"auth_time": now.Unix(),
			"locale":    "en-US",
			"zoneinfo":  "America/New_York",
		},
	}

	return claimsData
}

// HandleCallback handles OAuth2 callback and redirects to claims display
func (h *ClaimsHandler) HandleCallback(w http.ResponseWriter, r *http.Request) {
	h.Logger.Info("🔄 Handling OAuth2 callback")

	// Extract authorization code and state from callback
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")

	if errorParam != "" {
		h.Logger.Errorf("❌ OAuth2 error in callback: %s", errorParam)
		errorDescription := r.URL.Query().Get("error_description")
		http.Error(w, "Authorization error: "+errorParam+" - "+errorDescription, http.StatusBadRequest)
		return
	}

	if code == "" {
		h.Logger.Error("❌ No authorization code in callback")
		http.Error(w, "Missing authorization code", http.StatusBadRequest)
		return
	}

	h.Logger.Infof("✅ Authorization code received: %s", code[:20]+"...")
	h.Logger.Infof("📋 State parameter: %s", state)

	// In a real implementation, you would:
	// 1. Exchange the authorization code for tokens
	// 2. Validate the tokens
	// 3. Extract claims from the ID token
	// 4. Store session information

	// For demo purposes, simulate successful token exchange
	// and redirect to claims display with demo tokens
	claimsURL := "/claims?client_id=demo-client&username=john.doe&scope=openid%20profile%20email"
	claimsURL += "&access_token=demo_access_token_" + code[:10]
	claimsURL += "&id_token=demo_id_token_" + code[:10]
	claimsURL += "&refresh_token=demo_refresh_token_" + code[:10]
	claimsURL += "&auth_code=" + code
	if state != "" {
		claimsURL += "&state=" + state
	}

	h.Logger.Infof("🔄 Redirecting to claims display: %s", claimsURL)
	http.Redirect(w, r, claimsURL, http.StatusFound)
}
