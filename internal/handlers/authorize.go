package handlers

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"oauth2-server/internal/metrics"
	"oauth2-server/internal/store"
	"oauth2-server/internal/utils"
	"oauth2-server/pkg/config"
	"path/filepath"
	"strings"

	"github.com/ory/fosite"
	"github.com/sirupsen/logrus"
)

// AuthorizeHandler manages OAuth2 authorization requests
type AuthorizeHandler struct {
	OAuth2Provider     fosite.OAuth2Provider
	Configuration      *config.Config
	Log                *logrus.Logger
	Metrics            *metrics.MetricsCollector
	Storage            store.Storage
	UpstreamSessionMap *map[string]UpstreamSessionData
}

// NewAuthorizeHandler creates a new authorization handler
func NewAuthorizeHandler(oauth2Provider fosite.OAuth2Provider, configuration *config.Config, log *logrus.Logger, metricsCollector *metrics.MetricsCollector, storage store.Storage, upstreamSessionMap *map[string]UpstreamSessionData) *AuthorizeHandler {
	return &AuthorizeHandler{
		OAuth2Provider:     oauth2Provider,
		Configuration:      configuration,
		Log:                log,
		Metrics:            metricsCollector,
		Storage:            storage,
		UpstreamSessionMap: upstreamSessionMap,
	}
}

// ServeHTTP handles authorization requests following fosite-example patterns
func (h *AuthorizeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Log.Printf("🚀 [AUTH-HANDLER] Authorization request received: %s %s", r.Method, r.URL.String())

	h.Log.Printf("🔍 IsProxyMode: %t, ProviderURL: %s", h.Configuration.IsProxyMode(), h.Configuration.UpstreamProvider.ProviderURL)

	// Check if proxy mode is enabled
	if h.Configuration.IsProxyMode() {
		h.Log.Printf("🔄 [AUTH-HANDLER] Proxy mode detected, calling handleProxyAuthorize")
		h.handleProxyAuthorize(w, r)
		return
	}

	h.Log.Printf("🏠 [AUTH-HANDLER] Local mode, proceeding with regular authorization")

	// Add panic recovery to catch any internal fosite panics
	defer func() {
		if rec := recover(); rec != nil {
			h.Log.Fatalf("🚨 PANIC in authorization handler: %v", rec)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}()

	// This context will be passed to all methods.
	ctx := r.Context()

	h.Log.Printf("🔍 Authorization request: %s %s", r.Method, r.URL.String())

	// Parse form data before creating authorize request
	r.ParseForm()

	// For GET requests, also populate form with query parameters since Fosite expects them in r.Form
	if r.Method == "GET" {
		for key, values := range r.URL.Query() {
			if _, exists := r.Form[key]; !exists {
				r.Form[key] = values
			}
		}
	}

	h.Log.Printf("🔍 Form values: %v", r.Form)

	// Let's create an AuthorizeRequest object!
	// It will analyze the request and extract important information like scopes, response type and others.
	ar, err := h.OAuth2Provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		h.Log.Errorf("❌ Error occurred in NewAuthorizeRequest: %v", err)
		if h.Metrics != nil {
			h.Metrics.RecordAuthRequest("unknown", "unknown", "error")
		}
		h.OAuth2Provider.WriteAuthorizeError(ctx, w, ar, err)
		return
	}

	username := r.PostForm.Get("username")

	if username == "" {
		// Show login form
		h.showAuthorizationTemplate(w, r, ar, "", false)
		return
	}

	// Validate user credentials (simplified - just check if user exists)
	var userExists bool
	for _, user := range h.Configuration.Users {
		if user.Username == username {
			userExists = true
			break
		}
	}

	if !userExists {
		h.Log.Errorf("❌ Invalid username: %s", username)
		h.showAuthorizationTemplate(w, r, ar, "Invalid username or password", false)
		return
	}

	h.Log.Printf("✅ User authenticated: %s", username)

	// Grant requested scopes
	scopeParam := r.Form.Get("scope")
	if scopeParam != "" {
		scopes := strings.Split(scopeParam, " ")
		for _, scope := range scopes {
			if scope != "" {
				ar.GrantScope(scope)
			}
		}
	} else {
		// Default to openid scope
		ar.GrantScope("openid")
	}

	// Now that the user is authorized, we set up a session using the proper newSession helper:
	mySessionData := userSession(h.Configuration.PublicBaseURL, username, []string{})

	// Store granted scopes in session for later retrieval during token exchange
	if mySessionData.Claims.Extra == nil {
		mySessionData.Claims.Extra = make(map[string]interface{})
	}
	mySessionData.Claims.Extra["granted_scopes"] = ar.GetGrantedScopes()

	// Store the original state from the authorization request in the session
	// This will be available during userinfo requests
	issuerState := r.URL.Query().Get("issuer_state")
	if issuerState != "" {
		if mySessionData.Headers.Extra == nil {
			mySessionData.Headers.Extra = make(map[string]interface{})
		}
		mySessionData.Headers.Extra["issuer_state"] = issuerState
		h.Log.Printf("🔍 Stored issuer state in session: %s", issuerState)
	}

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
				h.Log.Fatalf("🚨 PANIC in NewAuthorizeResponse: %v", rec)
				authErr = fosite.ErrServerError.WithHint("Internal panic during authorization response generation")
			}
		}()
		// Now we need to get a response. This is the place where the AuthorizeEndpointHandlers kick in and start processing the request.
		// NewAuthorizeResponse is capable of running multiple response type handlers which in turn enables this library
		// to support open id connect.
		h.Log.Printf("🔍 Calling NewAuthorizeResponse with context and session...")
		h.Log.Printf("🔍 Session pointer address: %p", mySessionData)
		h.Log.Printf("🔍 Session GetSubject(): %s", mySessionData.GetSubject())
		response, authErr = h.OAuth2Provider.NewAuthorizeResponse(ctx, ar, mySessionData)
		h.Log.Printf("🔍 NewAuthorizeResponse completed - response: %+v, error: %v", response, authErr)
		if response != nil {
			h.Log.Printf("🔍 Response parameters: %+v", response.GetParameters())
			h.Log.Printf("🔍 Response code (if any): %s", response.GetParameters().Get("code"))
		}
	}()

	// Catch any errors, e.g.:
	// * unknown client
	// * invalid redirect
	// * ...
	if authErr != nil {
		h.Log.Errorf("❌ Error occurred in NewAuthorizeResponse: %v", authErr)
		h.Log.Printf("🔍 Error type: %T", authErr)
		h.Log.Printf("🔍 Error details: %+v", authErr)

		// Try to get more details about the error
		if fositeErr, ok := authErr.(*fosite.RFC6749Error); ok {
			h.Log.Printf("🔍 Fosite error code: %s", fositeErr.ErrorField)
			h.Log.Printf("🔍 Fosite error description: %s", fositeErr.DescriptionField)
			h.Log.Printf("🔍 Fosite error hint: %s", fositeErr.HintField)
		}

		// Record authorization error metrics
		if h.Metrics != nil {
			clientID := ar.GetClient().GetID()
			responseType := ""
			if len(ar.GetResponseTypes()) > 0 {
				responseType = ar.GetResponseTypes()[0]
			}
			h.Metrics.RecordAuthRequest(clientID, responseType, "error")
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

	// Record successful authorization metrics
	if h.Metrics != nil {
		clientID := ar.GetClient().GetID()
		responseType := ""
		if len(ar.GetResponseTypes()) > 0 {
			responseType = ar.GetResponseTypes()[0]
		}
		h.Metrics.RecordAuthRequest(clientID, responseType, "success")
	}

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
		h.Log.Errorf("❌ Error loading template: %v", err)
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		h.Log.Errorf("❌ Error executing template: %v", err)
		http.Error(w, "Template execution error", http.StatusInternalServerError)
		return
	}
}

// handleProxyAuthorize proxies /authorize requests to the upstream provider,
// mapping state/nonce/pkce to internal proxy values so we can correlate the
// upstream callback back to the original client redirect.
func (h *AuthorizeHandler) handleProxyAuthorize(w http.ResponseWriter, r *http.Request) {
	h.Log.Printf("🔄 [PROXY-AUTH] Starting proxy authorization request: %s", r.URL.String())

	if h.Configuration.UpstreamProvider.Metadata == nil {
		h.Log.Errorf("❌ [PROXY-AUTH] Upstream provider metadata not configured")
		http.Error(w, "upstream provider not configured", http.StatusBadGateway)
		return
	}

	q := r.URL.Query()
	clientID := q.Get("client_id")
	redirectURI := q.Get("redirect_uri")
	h.Log.Printf("🔍 [PROXY-AUTH] ClientID: %s, RedirectURI: %s", clientID, redirectURI)

	// Validate client exists in our storage
	h.Log.Printf("🔍 [PROXY-AUTH] Validating client exists: %s", clientID)
	if _, err := h.Storage.GetClient(r.Context(), clientID); err != nil {
		h.Log.Errorf("❌ [PROXY-AUTH] Client validation failed: %v", err)
		http.Error(w, "unknown or unregistered client_id", http.StatusBadRequest)
		return
	}
	h.Log.Printf("✅ [PROXY-AUTH] Client validation passed")

	originalState := q.Get("state")
	originalNonce := q.Get("nonce")
	originalIssuerState := q.Get("issuer_state")
	originalCodeChallenge := q.Get("code_challenge")

	proxyState := utils.GenerateState()
	proxyNonce := utils.GenerateNonce()
	proxyCodeChallenge := originalCodeChallenge

	sessionID := proxyState
	h.Log.Printf("🔄 [PROXY-AUTH] Generated session ID: %s", sessionID)

	(*h.UpstreamSessionMap)[sessionID] = UpstreamSessionData{
		OriginalIssuerState:   originalIssuerState,
		OriginalState:         originalState,
		OriginalNonce:         originalNonce,
		OriginalRedirectURI:   redirectURI,
		OriginalCodeChallenge: originalCodeChallenge,
		ProxyState:            proxyState,
		ProxyNonce:            proxyNonce,
		ProxyCodeChallenge:    proxyCodeChallenge,
	}
	h.Log.Printf("✅ [PROXY-AUTH] Session data stored")

	// Build upstream authorization URL
	authzEndpoint, _ := h.Configuration.UpstreamProvider.Metadata["authorization_endpoint"].(string)
	if authzEndpoint == "" {
		h.Log.Errorf("❌ [PROXY-AUTH] Authorization endpoint not available in metadata")
		http.Error(w, "upstream authorization_endpoint not available", http.StatusBadGateway)
		return
	}
	h.Log.Printf("🔗 [PROXY-AUTH] Upstream auth endpoint: %s", authzEndpoint)

	vals := make(url.Values)
	vals.Set("client_id", h.Configuration.UpstreamProvider.ClientID)
	vals.Set("redirect_uri", h.Configuration.UpstreamProvider.CallbackURL)
	vals.Set("response_type", q.Get("response_type"))

	// Handle claims parameter - use client's registered claims if none provided
	claimsParam := q.Get("claims")
	var upstreamClaims string
	if claimsParam == "" {
		// No claims provided, use client's registered claims
		if client, err := h.Storage.GetClient(r.Context(), clientID); err == nil {
			if customClient, ok := client.(*store.CustomClient); ok {
				clientClaims := customClient.GetClaims()
				if len(clientClaims) > 0 {
					upstreamClaims = h.buildClaimsJSON(clientClaims)
					h.Log.Printf("🔍 [PROXY-AUTH] No claims provided, using client's registered claims: %s", upstreamClaims)
				}
			}
		}
	} else {
		// Parse the claims parameter - could be space-separated or JSON
		upstreamClaims = h.buildClaimsJSON(strings.Fields(claimsParam))
		h.Log.Printf("🔍 [PROXY-AUTH] Forwarding claims to upstream: %s", upstreamClaims)
	}
	if upstreamClaims != "" {
		vals.Set("claims", upstreamClaims)
	}

	// Handle scope parameter - use client's registered scopes if none provided
	scopeParam := q.Get("scope")
	if scopeParam == "" {
		// No scope provided, use client's registered scopes
		if client, err := h.Storage.GetClient(r.Context(), clientID); err == nil {
			clientScopes := client.GetScopes()
			if len(clientScopes) > 0 {
				scopeParam = strings.Join(clientScopes, " ")
				h.Log.Printf("🔍 [PROXY-AUTH] No scope provided, using client's registered scopes: %s", scopeParam)
			} else {
				// Fallback to openid if client has no scopes
				scopeParam = "openid"
				h.Log.Printf("🔍 [PROXY-AUTH] No scope provided and client has no registered scopes, using default: %s", scopeParam)
			}
		} else {
			// Fallback to openid if we can't get client
			scopeParam = "openid"
			h.Log.Printf("🔍 [PROXY-AUTH] No scope provided and failed to get client, using default: %s", scopeParam)
		}
	}

	vals.Set("scope", scopeParam)
	vals.Set("state", proxyState)
	vals.Set("nonce", proxyNonce)
	if originalCodeChallenge != "" {
		vals.Set("code_challenge", proxyCodeChallenge)
		if m := q.Get("code_challenge_method"); m != "" {
			vals.Set("code_challenge_method", m)
		}
	}

	upstreamURL := authzEndpoint + "?" + vals.Encode()
	h.Log.Printf("🔄 [PROXY-AUTH] Redirecting to upstream: %s", upstreamURL)
	http.Redirect(w, r, upstreamURL, http.StatusFound)
	h.Log.Printf("✅ [PROXY-AUTH] Redirect sent")
}

// buildClaimsJSON builds a proper OIDC claims parameter JSON from a list of claim names
func (h *AuthorizeHandler) buildClaimsJSON(claims []string) string {
	if len(claims) == 0 {
		return ""
	}

	claimsMap := make(map[string]interface{})
	for _, claim := range claims {
		claimsMap[claim] = nil
	}

	userinfoClaims := map[string]interface{}{
		"userinfo": claimsMap,
	}

	jsonBytes, err := json.Marshal(userinfoClaims)
	if err != nil {
		h.Log.Errorf("❌ [PROXY-AUTH] Failed to marshal claims JSON: %v", err)
		return ""
	}

	return string(jsonBytes)
}
