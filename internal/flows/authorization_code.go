package flows

import (
	"crypto/rand"
	"encoding/base64"

	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"oauth2-server/internal/auth"
	"oauth2-server/internal/utils"
	"oauth2-server/pkg/config"

	"github.com/ory/fosite"
)

// AuthorizationCodeFlow handles the OAuth2 authorization code flow
type AuthorizationCodeFlow struct {
	oauth2Provider fosite.OAuth2Provider
	config         *config.Config
}

// NewAuthorizationCodeFlow creates a new authorization code flow handler
func NewAuthorizationCodeFlow(oauth2Provider fosite.OAuth2Provider, config *config.Config) *AuthorizationCodeFlow {
	return &AuthorizationCodeFlow{
		oauth2Provider: oauth2Provider,
		config:         config,
	}
}

// generateRandomState returns a secure random string for use as state
func generateRandomState() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "state1234" // fallback for testing only
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// HandleAuthorization handles the authorization endpoint
func (f *AuthorizationCodeFlow) HandleAuthorization(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	log.Printf("🔄 Authorization request: %s %s", r.Method, r.URL.String())
	log.Printf("🔍 Query parameters: %+v", r.URL.Query())

	// If state is missing, generate one and redirect to the same URL with state set
	/* 	if r.URL.Query().Get("state") == "" {
	   		q := r.URL.Query()
	   		q.Set("state", generateRandomState())
	   		r.URL.RawQuery = q.Encode()
	   		http.Redirect(w, r, r.URL.String(), http.StatusFound)
	   		return
	   	}
	*/

	// Create a new authorization request object and catch any errors
	ar, err := f.oauth2Provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		log.Printf("❌ Error creating authorization request: %v", err)
		f.oauth2Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	log.Printf("✅ Authorization request created successfully for client: %s", ar.GetClient().GetID())

	// Check if this is a login form submission
	if r.Method == "POST" && r.FormValue("action") == "login" {
		f.handleLogin(w, r, ar)
		return
	}

	// Check if user is already authenticated via session or basic auth
	var userID string

	// Try to get authenticated user from basic auth (for testing)
	if username, password, ok := r.BasicAuth(); ok {
		if user := f.authenticateUser(username, password); user != nil {
			userID = user.ID
		}
	} else {
		userID = r.FormValue("user_id")
	}

	// If no user authenticated, show login form
	if userID == "" {
		f.showLoginForm(w, r, ar)
		return
	}

	// Check if this is a consent form submission
	if r.Method == "POST" && r.FormValue("action") == "consent" {
		f.handleConsent(w, r, ar, userID)
		return
	}

	// Show consent form
	f.showConsentForm(w, r, ar, userID)
}

// handleLogin processes the login form submission
func (f *AuthorizationCodeFlow) handleLogin(w http.ResponseWriter, r *http.Request, ar fosite.AuthorizeRequester) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	// Authenticate the user
	user := f.authenticateUser(username, password)
	if user == nil {
		// Authentication failed - show login form with error
		f.showLoginFormWithError(w, r, ar, "Invalid username or password")
		return
	}

	// Authentication successful - show consent form
	f.showConsentForm(w, r, ar, user.ID)
}

// showLoginFormWithError displays the login form with an error message
func (f *AuthorizationCodeFlow) showLoginFormWithError(w http.ResponseWriter, r *http.Request, ar fosite.AuthorizeRequester, errorMsg string) {
	// Create query string to preserve authorization request parameters
	query := r.URL.RawQuery
	if query != "" {
		query = "?" + query
	}

	errorHTML := ""
	if errorMsg != "" {
		errorHTML = fmt.Sprintf(`<div class="error">❌ %s</div>`, errorMsg)
	}

	loginHTML := `<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>OAuth2 Login</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 50px; background-color: #f5f5f5; }
		.container { max-width: 400px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
		.form-group { margin-bottom: 20px; }
		label { display: block; margin-bottom: 5px; font-weight: bold; }
		input[type="text"], input[type="password"] { width: 100%%; padding: 10px; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
		.btn { background-color: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; width: 100%%; }
		.btn:hover { background-color: #0056b3; }
		.info { background-color: #e7f3ff; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
		.error { background-color: #f8d7da; color: #721c24; padding: 15px; border-radius: 4px; margin-bottom: 20px; border: 1px solid #f5c6cb; }
		.test-users { margin-top: 20px; padding: 15px; background-color: #f8f9fa; border-radius: 4px; }
		.test-users h4 { margin: 0 0 10px 0; color: #6c757d; }
		.test-users ul { margin: 0; padding-left: 20px; }
		.test-users li { margin-bottom: 5px; font-family: monospace; font-size: 12px; }
	</style>
</head>
<body>
	<div class="container">
		<h2>🔐 OAuth2 Login</h2>
		` + errorHTML + `
		<div class="info">
			<strong>Client:</strong> ` + ar.GetClient().GetID() + `<br>
			<strong>Scopes:</strong> ` + strings.Join(ar.GetRequestedScopes(), ", ") + `<br>
			<strong>Redirect URI:</strong> ` + ar.GetRedirectURI().String() + `
		</div>
		
		<form method="post" action="/auth` + query + `">
			<input type="hidden" name="action" value="login">
			<div class="form-group">
				<label for="username">Username:</label>
				<input type="text" id="username" name="username" required>
			</div>
			<div class="form-group">
				<label for="password">Password:</label>
				<input type="password" id="password" name="password" required>
			</div>
			<button type="submit" class="btn">Login</button>
		</form>

		<div class="test-users">
			<h4>Available Test Users:</h4>
			<ul>` + f.generateTestUsersList() + `</ul>
		</div>
	</div>
</body>
</html>`

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(loginHTML))
}

// authenticateUser validates user credentials against the configured users
func (f *AuthorizationCodeFlow) authenticateUser(username, password string) *config.User {
	// Look up user in the configuration
	if user, found := f.config.GetUserByUsername(username); found {
		// In a real implementation, you'd hash and compare passwords properly
		if user.Password == password {
			return user
		}
	}
	return nil
}

// showLoginForm displays the login form
func (f *AuthorizationCodeFlow) showLoginForm(w http.ResponseWriter, r *http.Request, ar fosite.AuthorizeRequester) {
	f.showLoginFormWithError(w, r, ar, "")
}

// generateTestUsersList creates an HTML list of available test users
func (f *AuthorizationCodeFlow) generateTestUsersList() string {
	var usersList strings.Builder

	for _, user := range f.config.Users {
		usersList.WriteString(fmt.Sprintf(
			"<li><strong>%s</strong> / %s (%s)</li>",
			user.Username,
			user.Password,
			user.Name,
		))
	}

	if usersList.Len() == 0 {
		usersList.WriteString("<li>No test users configured</li>")
	}

	return usersList.String()
}

// showConsentForm displays the consent form
func (f *AuthorizationCodeFlow) showConsentForm(w http.ResponseWriter, r *http.Request, ar fosite.AuthorizeRequester, userID string) {
	// Create query string to preserve authorization request parameters
	query := r.URL.RawQuery
	if query != "" {
		query = "?" + query
	}

	// Get user information
	var userName string
	if user, found := f.config.GetUserByUsername(userID); found {
		userName = user.Name
	} else {
		userName = userID
	}

	consentHTML := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>OAuth2 Consent</title>
	<style>
		body { font-family: Arial, sans-serif; margin: 50px; background-color: #f5f5f5; }
		.container { max-width: 500px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
		.form-group { margin-bottom: 20px; }
		.btn { padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; margin-right: 10px; }
		.btn-primary { background-color: #28a745; color: white; }
		.btn-secondary { background-color: #6c757d; color: white; }
		.btn:hover { opacity: 0.8; }
		.info { background-color: #e7f3ff; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
		.scopes { background-color: #f8f9fa; padding: 15px; border-radius: 4px; margin-bottom: 20px; }
		.scopes ul { margin: 0; padding-left: 20px; }
		.scopes li { margin-bottom: 5px; }
	</style>
</head>
<body>
	<div class="container">
		<h2>🛡️ Authorization Request</h2>
		<div class="info">
			<strong>Hello, %s!</strong><br><br>
			The application <strong>%s</strong> is requesting access to your account.
		</div>
		
		<div class="scopes">
			<h4>Requested Permissions:</h4>
			<ul>
				%s
			</ul>
		</div>
		
		<form method="post" action="/auth%s">
			<input type="hidden" name="action" value="consent">
			<input type="hidden" name="user_id" value="%s">
			<button type="submit" name="consent" value="allow" class="btn btn-primary">Allow</button>
			<button type="submit" name="consent" value="deny" class="btn btn-secondary">Deny</button>
		</form>
	</div>
</body>
</html>`,
		userName,
		ar.GetClient().GetID(),
		f.generateScopesList(ar.GetRequestedScopes()),
		query,
		userID,
	)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(consentHTML))
}

// generateScopesList creates an HTML list of requested scopes
func (f *AuthorizationCodeFlow) generateScopesList(scopes []string) string {
	scopeDescriptions := map[string]string{
		"openid":    "Verify your identity",
		"profile":   "Access your basic profile information",
		"email":     "Access your email address",
		"api:read":  "Read access to API resources",
		"api:write": "Write access to API resources",
		"api:admin": "Administrative access to API resources",
		"offline":   "Access your data when you're not actively using the app",
	}

	var scopesList strings.Builder
	for _, scope := range scopes {
		description := scopeDescriptions[scope]
		if description == "" {
			description = fmt.Sprintf("Access to %s", scope)
		}
		scopesList.WriteString(fmt.Sprintf("<li><strong>%s:</strong> %s</li>", scope, description))
	}

	return scopesList.String()
}

// handleConsent processes the consent form submission
func (f *AuthorizationCodeFlow) handleConsent(w http.ResponseWriter, r *http.Request, ar fosite.AuthorizeRequester, userID string) {
	ctx := context.Background()

	// Check if user consented
	consent := r.FormValue("consent")
	if consent != "allow" {
		// User denied consent
		err := fosite.ErrAccessDenied.WithHint("The user denied the request.")
		f.oauth2Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Get the username for the session
	var username string
	if user, found := f.config.GetUserByUsername(userID); found {
		username = user.Username
	} else {
		username = userID
	}

	// Create a new session that implements fosite.Session
	mySessionData := &auth.UserSession{
		UserID:   userID,
		Username: username,
		Subject:  userID,
	}
	log.Printf("Client %s grant_types: %v, response_types: %v", ar.GetClient().GetID(), ar.GetClient().GetGrantTypes(), ar.GetClient().GetResponseTypes())
	log.Printf("Authorize request response_type: %v", ar.GetResponseTypes())

	// Generate the authorization code response
	response, err := f.oauth2Provider.NewAuthorizeResponse(ctx, ar, mySessionData)
	if err != nil {
		log.Printf("❌ Error creating authorization response: %v", err)
		f.oauth2Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	// Redirect the user back to the client with the authorization code
	f.oauth2Provider.WriteAuthorizeResponse(ctx, w, ar, response)

	log.Printf("✅ Authorization code issued for user %s, client %s", userID, ar.GetClient().GetID())
}

// HandleCallback handles the authorization callback (typically not used in auth code flow)
func (f *AuthorizationCodeFlow) HandleCallback(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	errorParam := r.URL.Query().Get("error")

	// For testing: warn if state is missing or too short
	var stateWarning string
	if state == "" {
		stateWarning = `<div style="color:red;margin-bottom:10px;">⚠️ State parameter is missing! This is insecure and not recommended for production.</div>`
	} else if len(state) < 8 {
		stateWarning = `<div style="color:orange;margin-bottom:10px;">⚠️ State parameter is very short. Use a random, unguessable value for security.</div>`
	}

	if errorParam != "" {
		errorDescription := r.URL.Query().Get("error_description")
		content := fmt.Sprintf(`
			<h2>❌ Authorization Error</h2>
			<p><strong>Error:</strong> %s</p>
			<p><strong>Description:</strong> %s</p>
			<p><strong>State:</strong> %s</p>
			%s
		`, errorParam, errorDescription, state, stateWarning)
		utils.WriteHTMLResponse(w, http.StatusBadRequest, content)
		return
	}

	if code == "" {
		content := `
			<h2>❌ Missing Authorization Code</h2>
			<p>No authorization code received in callback.</p>
		`
		utils.WriteHTMLResponse(w, http.StatusBadRequest, content)
		return
	}

	// Display successful callback
	content := fmt.Sprintf(`
		<h2>✅ Authorization Successful</h2>
		%s
		<p><strong>Authorization Code:</strong></p>
		<div class="code">%s</div>
		<p><strong>State:</strong> %s</p>
		<p>You can now exchange this code for an access token at the token endpoint.</p>
	`, stateWarning, code, state)
	utils.WriteHTMLResponse(w, http.StatusOK, content)

	log.Printf("✅ Authorization callback received: code=%s, state=%s", code, state)
}
