package handlers

import (
	"html/template"
	"net/http"
	"oauth2-server/pkg/config"
	"path/filepath"

	"github.com/ory/fosite"
	"github.com/sirupsen/logrus"
)

// AuthorizeHandler manages OAuth2 authorization requests
type AuthorizeHandler struct {
	OAuth2Provider fosite.OAuth2Provider
	Configuration  *config.Config
	Log            *logrus.Logger
}

// NewAuthorizeHandler creates a new authorization handler
func NewAuthorizeHandler(oauth2Provider fosite.OAuth2Provider, configuration *config.Config, log *logrus.Logger) *AuthorizeHandler {
	return &AuthorizeHandler{
		OAuth2Provider: oauth2Provider,
		Configuration:  configuration,
		Log:            log,
	}
}

// ServeHTTP handles authorization requests following fosite-example patterns
func (h *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Add panic recovery to catch any internal fosite panics
	defer func() {
		if rec := recover(); rec != nil {
			h.Log.Printf("🚨 PANIC in authorization handler: %v", rec)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}()

	// This context will be passed to all methods.
	ctx := r.Context()

	h.Log.Printf("🔍 Authorization request: %s %s", r.Method, r.URL.String())
	h.Log.Printf("🔍 Form values: %v", r.Form)

	// Let's create an AuthorizeRequest object!
	// It will analyze the request and extract important information like scopes, response type and others.
	ar, err := h.OAuth2Provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		h.Log.Printf("❌ Error occurred in NewAuthorizeRequest: %v", err)
		h.OAuth2Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	h.Log.Printf("✅ Authorization request created successfully")
	h.Log.Printf("🔍 Client ID: %s", ar.GetClient().GetID())
	h.Log.Printf("🔍 Redirect URI: %s", ar.GetRedirectURI().String())
	h.Log.Printf("🔍 Response types: %v", ar.GetResponseTypes())
	h.Log.Printf("🔍 Requested scopes: %v", ar.GetRequestedScopes())

	// Normally, this would be the place where you would check if the user is logged in and gives his consent.
	// We're simplifying things and just checking if the request includes a valid username
	r.ParseForm()
	username := r.PostForm.Get("username")

	if username == "" {
		// Show unified authorization template for login
		h.showAuthorizationTemplate(w, r, ar, "", false)
		return
	}

	// let's see what scopes the user gave consent to
	for _, scope := range r.PostForm["scopes"] {
		ar.GrantScope(scope)
	}

	// Now that the user is authorized, we set up a session using the proper newSession helper:
	mySessionData := userSession(h.Configuration.BaseURL, username, []string{})

	// Debug: Log session creation
	h.Log.Printf("✅ Created session for user: %s", username)
	h.Log.Printf("🔍 Session subject: %s", mySessionData.Claims.Subject)
	h.Log.Printf("🔍 Session issuer: %s", mySessionData.Claims.Issuer)

	// When using the HMACSHA strategy you must use something that implements the HMACSessionContainer.
	// It brings you the power of overriding the default values.
	//
	// mySessionData.HMACSession = &strategy.HMACSession{
	//	AccessTokenExpiry: time.Now().Add(time.Day),
	//	AuthorizeCodeExpiry: time.Now().Add(time.Day),
	// }

	// If you're using the JWT strategy, there's currently no distinction between access token and authorize code claims.
	// Therefore, you both access token and authorize code will have the same "exp" claim. If this is something you
	// need let us know on github.
	//
	// mySessionData.JWTClaims.ExpiresAt = time.Now().Add(time.Day)

	// It's also wise to check the requested scopes, e.g.:
	// if ar.GetRequestedScopes().Has("admin") {
	//     http.Error(w, "you're not allowed to do that", http.StatusForbidden)
	//     return
	// }

	h.Log.Printf("🔍 About to create authorization response...")
	h.Log.Printf("🔍 Granted scopes: %v", ar.GetGrantedScopes())
	h.Log.Printf("🔍 Session subject: %s", mySessionData.Claims.Subject)
	h.Log.Printf("🔍 Session issuer: %s", mySessionData.Claims.Issuer)

	// Add very detailed debugging before NewAuthorizeResponse
	h.Log.Printf("🔍 Debugging session data before NewAuthorizeResponse:")
	h.Log.Printf("🔍 Session type: %T", mySessionData)
	h.Log.Printf("🔍 Session Claims: %+v", mySessionData.Claims)
	h.Log.Printf("🔍 Session Headers: %+v", mySessionData.Headers)
	h.Log.Printf("🔍 Authorization request details:")
	h.Log.Printf("🔍 AR Client: %+v", ar.GetClient())
	h.Log.Printf("🔍 AR ResponseTypes: %+v", ar.GetResponseTypes())
	h.Log.Printf("🔍 AR GrantedScopes: %+v", ar.GetGrantedScopes())
	h.Log.Printf("🔍 AR RequestedScopes: %+v", ar.GetRequestedScopes())
	h.Log.Printf("🔍 AR RedirectURI: %s", ar.GetRedirectURI())

	// Try with enhanced error capture
	var response fosite.AuthorizeResponder
	var authErr error
	func() {
		defer func() {
			if rec := recover(); rec != nil {
				h.Log.Printf("🚨 PANIC in NewAuthorizeResponse: %v", rec)
				h.Log.Printf("🚨 Stack trace: %+v", rec)
				authErr = fosite.ErrServerError.WithHint("Internal panic during authorization response generation")
			}
		}()
		// Now we need to get a response. This is the place where the AuthorizeEndpointHandlers kick in and start processing the request.
		// NewAuthorizeResponse is capable of running multiple response type handlers which in turn enables this library
		// to support open id connect.
		h.Log.Printf("🔍 Calling NewAuthorizeResponse with context and session...")
		response, authErr = h.OAuth2Provider.NewAuthorizeResponse(ctx, ar, mySessionData)
		h.Log.Printf("🔍 NewAuthorizeResponse completed - response: %+v, error: %v", response, authErr)
	}()

	// Catch any errors, e.g.:
	// * unknown client
	// * invalid redirect
	// * ...
	if authErr != nil {
		h.Log.Printf("❌ Error occurred in NewAuthorizeResponse: %v", authErr)
		h.Log.Printf("🔍 Error type: %T", authErr)
		h.Log.Printf("🔍 Error details: %+v", authErr)

		// Try to get more details about the error
		if fositeErr, ok := authErr.(*fosite.RFC6749Error); ok {
			h.Log.Printf("🔍 Fosite error code: %s", fositeErr.ErrorField)
			h.Log.Printf("🔍 Fosite error description: %s", fositeErr.DescriptionField)
			h.Log.Printf("🔍 Fosite error hint: %s", fositeErr.HintField)
		}

		h.OAuth2Provider.WriteAuthorizeError(ctx, w, ar, authErr)
		return
	}
	h.Log.Printf("🔍 Sending back response to requestor...")
	h.Log.Printf("🔍 Response details before WriteAuthorizeResponse:")
	h.Log.Printf("🔍 Response headers: %+v", response.GetHeader())
	h.Log.Printf("🔍 Response parameters: %+v", response.GetParameters())
	h.Log.Printf("🔍 Redirect URI from request: %s", ar.GetRedirectURI().String())

	// Add response headers logging after WriteAuthorizeResponse
	h.Log.Printf("🔍 About to call WriteAuthorizeResponse...")

	// Last but not least, send the response!
	h.OAuth2Provider.WriteAuthorizeResponse(ctx, w, ar, response)

	h.Log.Printf("🔍 WriteAuthorizeResponse completed")
	h.Log.Printf("🔍 HTTP response headers after WriteAuthorizeResponse: %+v", w.Header())
}

// AuthTemplateData represents the data structure for the unified authorization template
type AuthTemplateData struct {
	IsDeviceFlow  bool
	ShowLoginForm bool
	Username      string
	ClientID      string
	ClientName    string
	RedirectURI   string
	State         string
	CodeChallenge string
	Scopes        []string
	Error         string
	FormAction    string
	HiddenFields  map[string]string
	UserCode      string
	DeviceCode    string
}

// showAuthorizationTemplate renders the unified authorization template
func (h *AuthorizeHandler) showAuthorizationTemplate(w http.ResponseWriter, r *http.Request, ar fosite.AuthorizeRequester, errorMsg string, isAuthenticated bool) {
	// Prepare template data
	data := AuthTemplateData{
		IsDeviceFlow:  false, // This is authorization code flow
		ShowLoginForm: !isAuthenticated,
		ClientID:      ar.GetClient().GetID(),
		RedirectURI:   ar.GetRedirectURI().String(),
		State:         ar.GetState(),
		Scopes:        ar.GetRequestedScopes(),
		Error:         errorMsg,
		FormAction:    r.URL.Path,
		HiddenFields:  make(map[string]string),
	}

	// Check for PKCE
	if challenge := ar.GetRequestForm().Get("code_challenge"); challenge != "" {
		data.CodeChallenge = challenge
	}

	// Preserve form parameters as hidden fields
	for key, values := range r.URL.Query() {
		if len(values) > 0 && key != "username" && key != "password" {
			data.HiddenFields[key] = values[0]
		}
	}

	// Load and execute template
	templatePath := filepath.Join("templates", "unified_auth.html")
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		h.Log.Printf("❌ Error loading template: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		h.Log.Printf("❌ Error executing template: %v", err)
		http.Error(w, "Template execution error", http.StatusInternalServerError)
		return
	}
}
