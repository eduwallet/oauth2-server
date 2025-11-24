package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"oauth2-server/internal/attestation"
	"oauth2-server/internal/store"
	"oauth2-server/pkg/config"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/sirupsen/logrus"
)

// IntrospectionHandler manages token introspection requests
type IntrospectionHandler struct {
	OAuth2Provider          fosite.OAuth2Provider
	Config                  *config.Config
	Log                     *logrus.Logger
	AttestationManager      *attestation.VerifierManager
	Storage                 store.Storage
	SecretManager           *store.SecretManager
	PrivilegedClientSecrets map[string]string
}

// NewIntrospectionHandler creates a new introspection handler
func NewIntrospectionHandler(oauth2Provider fosite.OAuth2Provider, config *config.Config, log *logrus.Logger, attestationManager *attestation.VerifierManager, storage store.Storage, secretManager *store.SecretManager, privilegedClientSecrets map[string]string) *IntrospectionHandler {
	return &IntrospectionHandler{
		OAuth2Provider:          oauth2Provider,
		Config:                  config,
		Log:                     log,
		AttestationManager:      attestationManager,
		Storage:                 storage,
		SecretManager:           secretManager,
		PrivilegedClientSecrets: privilegedClientSecrets,
	}
}

// responseCapture captures the response from Fosite to allow modification
type responseCapture struct {
	http.ResponseWriter
	statusCode int
	body       *bytes.Buffer
}

func newResponseCapture(w http.ResponseWriter) *responseCapture {
	return &responseCapture{
		ResponseWriter: w,
		statusCode:     200,
		body:           &bytes.Buffer{},
	}
}

func (rc *responseCapture) WriteHeader(code int) {
	rc.statusCode = code
}

func (rc *responseCapture) Write(data []byte) (int, error) {
	return rc.body.Write(data)
}

// handleAttestationAuthentication handles attestation-based client authentication for introspection
// determineAuthMethod determines the attestation authentication method from the request
func (h *IntrospectionHandler) determineAuthMethod(r *http.Request) string {
	clientID := r.FormValue("client_id")
	if clientID == "" {
		if username, _, ok := r.BasicAuth(); ok {
			clientID = username
		}
	}

	// Check for JWT attestation
	clientAssertionType := r.FormValue("client_assertion_type")
	if clientAssertionType == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		clientAssertion := r.FormValue("client_assertion")

		// Check if the client is configured for attestation-based authentication
		if h.AttestationManager != nil && h.AttestationManager.IsAttestationEnabled(clientID) {
			supportedMethods, err := h.AttestationManager.GetSupportedMethods(clientID)
			if err == nil {
				// Check if attest_jwt_client_auth is supported
				for _, method := range supportedMethods {
					if method == "attest_jwt_client_auth" {
						return "attest_jwt_client_auth"
					}
				}
			}
		}

		// Also check if JWT contains attestation-specific claims
		if strings.Contains(clientAssertion, "att_") {
			return "attest_jwt_client_auth"
		}

		// If we have a JWT client assertion but no attestation config, treat it as regular JWT auth
		// This allows public clients to authenticate with JWT assertions without attestation
		if clientAssertion != "" {
			return "jwt_client_auth"
		}
	}

	// Check for TLS attestation
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		// This could be TLS client certificate authentication
		// We need to check if it's specifically for attestation
		return "attest_tls_client_auth"
	}

	return ""
}

// ServeHTTP handles token introspection requests (RFC 7662)
func (h *IntrospectionHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Log the incoming request for debugging
	h.Log.Debugf("🔍 Introspection request: Method=%s, Content-Type=%s", r.Method, r.Header.Get("Content-Type"))

	// Ensure it's a POST request
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form data first to check for client credentials
	if err := r.ParseForm(); err != nil {
		h.Log.Errorf("❌ Error parsing form: %v", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// Debug: Log all form values
	h.Log.Debugf("🔍 Form values: %v", r.Form)
	for key, values := range r.Form {
		h.Log.Debugf("🔍 Form[%s] = %v", key, values)
	}

	// RFC 7662 allows client authentication via:
	// 1. Basic authentication in Authorization header
	// 2. client_id and client_secret in request body
	// 3. Other client authentication methods

	authHeader := r.Header.Get("Authorization")
	clientID := r.FormValue("client_id")
	clientSecret := r.FormValue("client_secret")

	h.Log.Debugf("🔍 Introspection auth check: auth_header_present=%t, client_id_present=%t, client_secret_present=%t",
		authHeader != "", clientID != "", clientSecret != "")

	// Check if we have some form of client authentication
	hasBasicAuth := authHeader != "" && strings.HasPrefix(authHeader, "Basic ")
	hasClientCreds := clientID != "" || clientSecret != ""
	hasJwtAssertion := r.FormValue("client_assertion_type") == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" && r.FormValue("client_assertion") != ""

	if !hasBasicAuth && !hasClientCreds && !hasJwtAssertion {
		h.Log.Errorf("❌ No client authentication provided for introspection")
		http.Error(w, "Client authentication required for introspection", http.StatusUnauthorized)
		return
	}

	h.Log.Debugf("🔍 Client authentication present for introspection (Basic: %t, Creds: %t, JWT: %t)", hasBasicAuth, hasClientCreds, hasJwtAssertion)

	// Extract client ID for privileged check (if not already set)
	if clientID == "" {
		if username, _, ok := r.BasicAuth(); ok {
			clientID = username
		}
	}

	// Check if this is the privileged client that can introspect any token
	if clientID != "" && h.Config.Security.PrivilegedClientID != "" && clientID == h.Config.Security.PrivilegedClientID {
		h.Log.Debugf("🔍 Privileged client %s requesting introspection - allowing unrestricted access via Fosite", clientID)
		// For privileged clients, let Fosite handle introspection normally
		// The audience restrictions will be bypassed due to privileged status
	}

	// Log form values (but hide sensitive data)
	token := r.FormValue("token")
	tokenTypeHint := r.FormValue("token_type_hint")
	h.Log.Debugf("🔍 Introspection details: token_present=%t, token_type_hint=%s", token != "", tokenTypeHint)

	// Handle JWT client assertion authentication AFTER attestation check
	var jwtAuthenticatedClientID string
	if hasJwtAssertion {
		clientAssertion := r.FormValue("client_assertion")
		if clientAssertion == "" {
			h.Log.Errorf("❌ JWT assertion type present but client_assertion is empty")
		} else {
			// Safely truncate for logging
			assertionPreview := clientAssertion
			if len(assertionPreview) > 50 {
				assertionPreview = assertionPreview[:50]
			}
			h.Log.Debugf("🔍 Processing JWT client assertion: %s...", assertionPreview)

			// First verify attestation if this is an attestation-based request
			if extractedClientID := h.extractClientIDFromJWT(clientAssertion); extractedClientID != "" {
				h.Log.Debugf("✅ Extracted client ID from JWT assertion: %s", extractedClientID)

				// Check if this client is configured for attestation
				if h.AttestationManager != nil && h.AttestationManager.IsAttestationEnabled(extractedClientID) {
					h.Log.Debugf("🔍 Client %s is configured for attestation - verifying attestation first", extractedClientID)

					// Get verifier for JWT attestation
					verifier, err := h.AttestationManager.GetVerifier(extractedClientID, "attest_jwt_client_auth")
					if err != nil {
						h.Log.Errorf("❌ Failed to get verifier for client %s: %v", extractedClientID, err)
					} else if jwtVerifier, ok := verifier.(attestation.AttestationVerifier); ok {
						if result, err := jwtVerifier.VerifyAttestation(clientAssertion); err == nil && result.Valid {
							h.Log.Debugf("✅ Attestation verified for client: %s", extractedClientID)
							jwtAuthenticatedClientID = extractedClientID

							// Store attestation result in request context
							attestation.WithAttestationResult(r.Context(), result)

							// Use privileged client for the actual introspection
							h.Log.Debugf("🔄 Attestation verified - using privileged client for introspection")
							h.handlePrivilegedIntrospectionWithAttestation(w, r, extractedClientID)
							return
						} else {
							h.Log.Errorf("❌ Attestation verification failed: %v", err)
						}
					} else {
						h.Log.Errorf("❌ Invalid JWT verifier type for client: %s", extractedClientID)
					}
				} else {
					// Not an attestation client, handle as regular JWT authentication
					h.Log.Debugf("🔍 Client %s not configured for attestation - treating as regular JWT auth", extractedClientID)
					jwtAuthenticatedClientID = extractedClientID
					h.handleLocalIntrospectionWithCredentials(w, r, jwtAuthenticatedClientID)
					return
				}
			} else {
				h.Log.Errorf("❌ Failed to extract client ID from JWT assertion")
			}
		}
	}

	// Extract client ID for privileged check
	if clientID == "" {
		if username, _, ok := r.BasicAuth(); ok {
			clientID = username
		}
	}

	// Check if this is the privileged client that can introspect any token
	if clientID != "" && h.Config.Security.PrivilegedClientID != "" && clientID == h.Config.Security.PrivilegedClientID {
		h.Log.Debugf("🔍 Privileged client %s requesting introspection - allowing unrestricted access via Fosite", clientID)
		// For privileged clients, let Fosite handle introspection normally
		// The audience restrictions will be bypassed due to privileged status
	}

	// Create the introspection request
	ir, err := h.OAuth2Provider.NewIntrospectionRequest(ctx, r, newSession())
	if err != nil {
		h.Log.Errorf("❌ Error creating introspection request: %v", err)

		// Provide more specific error information
		switch err.Error() {
		case "request_unauthorized":
			h.Log.Errorf("❌ Client authentication failed for introspection")
			h.Log.Debugf("🔍 This usually means: 1) Missing/invalid client credentials, 2) Client not authorized for introspection, 3) Wrong auth method")
		case "invalid_request":
			h.Log.Errorf("❌ Invalid introspection request format")
		default:
			h.Log.Errorf("❌ Introspection error details: %v", err)
		}

		h.OAuth2Provider.WriteIntrospectionError(ctx, w, err)
		return
	}

	// Capture the response to add issuer_state
	capture := newResponseCapture(w)
	h.OAuth2Provider.WriteIntrospectionResponse(ctx, capture, ir)

	// Parse the JSON response
	var response map[string]interface{}
	if err := json.Unmarshal(capture.body.Bytes(), &response); err != nil {
		h.Log.Errorf("❌ Error parsing introspection response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Debug: Log all response keys and values
	h.Log.Debugf("🔍 Main Introspection Response Keys: %v", getMapKeys(response))
	for key, value := range response {
		h.Log.Debugf("🔍 Main Response [%s]: %v", key, value)
	}

	// Add issuer_state if the token is active
	if active, ok := response["active"].(bool); ok && active {
		// issuer_state and attestation info are now automatically included by Fosite
		// from the token claims that were stored during token creation
		h.Log.Debugf("🔍 Token is active, checking for stored claims")

		// If audience is not included in the response, try to get it from the client
		if _, hasAud := response["aud"]; !hasAud {
			if resp, ok := ir.(*fosite.IntrospectionResponse); ok {
				if accessRequester := resp.AccessRequester; accessRequester != nil {
					if client := accessRequester.GetClient(); client != nil {
						if defaultClient, ok := client.(*fosite.DefaultClient); ok {
							if len(defaultClient.Audience) > 0 {
								response["aud"] = defaultClient.Audience
								h.Log.Debugf("🔍 Added audience from client to introspection response: %v", defaultClient.Audience)
							}
						}
					}
				}
			}
		}

		// Add scope to the response if not present
		if _, hasScope := response["scope"]; !hasScope {
			if resp, ok := ir.(*fosite.IntrospectionResponse); ok {
				h.Log.Debugf("🔍 IntrospectionResponse type assertion successful")
				if accessRequester := resp.AccessRequester; accessRequester != nil {
					h.Log.Debugf("🔍 AccessRequester is not nil")
					scopes := accessRequester.GetGrantedScopes()
					h.Log.Debugf("🔍 GetGrantedScopes returned: %v", scopes)
					if len(scopes) > 0 {
						response["scope"] = strings.Join(scopes, " ")
						h.Log.Debugf("🔍 Added scope to introspection response: %v", scopes)
					} else {
						h.Log.Debugf("🔍 No scopes returned from GetGrantedScopes, checking session Extra")
						// Check if scopes are stored in the session's Extra field
						if session := accessRequester.GetSession(); session != nil {
							if ds, ok := session.(*openid.DefaultSession); ok && ds.Claims != nil && ds.Claims.Extra != nil {
								if grantedScopes, ok := ds.Claims.Extra["granted_scopes"].([]interface{}); ok {
									var scopeStrings []string
									for _, scope := range grantedScopes {
										if scopeStr, ok := scope.(string); ok {
											scopeStrings = append(scopeStrings, scopeStr)
										}
									}
									if len(scopeStrings) > 0 {
										response["scope"] = strings.Join(scopeStrings, " ")
										h.Log.Debugf("🔍 Added scope from session Extra to introspection response: %v", scopeStrings)
									}
								} else if grantedScopes, ok := ds.Claims.Extra["granted_scopes"].([]string); ok {
									if len(grantedScopes) > 0 {
										response["scope"] = strings.Join(grantedScopes, " ")
										h.Log.Debugf("🔍 Added scope from session Extra to introspection response: %v", grantedScopes)
									}
								}
							}
						}
					}
				} else {
					h.Log.Debugf("🔍 AccessRequester is nil")
				}
			} else {
				h.Log.Debugf("🔍 IntrospectionResponse type assertion failed")
			}
		}
	}

	h.Log.Debugf("Response response: %v", response)

	// Write the modified response
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(capture.statusCode)
	json.NewEncoder(w).Encode(response)
}

// handlePrivilegedIntrospectionWithAttestation performs introspection using the privileged client
// after attestation has been verified
func (h *IntrospectionHandler) handlePrivilegedIntrospectionWithAttestation(w http.ResponseWriter, r *http.Request, attestedClientID string) {
	tokenValue := r.FormValue("token")
	if tokenValue == "" {
		h.Log.Errorf("❌ No token provided for privileged introspection")
		http.Error(w, "invalid_request: missing token", http.StatusBadRequest)
		return
	}

	h.Log.Debugf("🔄 Creating privileged introspection request for attested client: %s", attestedClientID)

	// Debug: Decode and log token claims
	if tokenValue != "" {
		h.logTokenClaims(tokenValue)
	}

	// Create a new request for local introspection
	localForm := make(url.Values)
	localForm.Set("token", tokenValue)
	if tokenTypeHint := r.FormValue("token_type_hint"); tokenTypeHint != "" {
		localForm.Set("token_type_hint", tokenTypeHint)
	}

	localReq, err := http.NewRequest("POST", "http://localhost:8080/introspect", strings.NewReader(localForm.Encode()))
	if err != nil {
		h.Log.Errorf("❌ Failed to create privileged introspection request: %v", err)
		http.Error(w, "failed to create privileged introspection request", http.StatusInternalServerError)
		return
	}
	// Copy the context from the original request to preserve attestation information
	localReq = localReq.WithContext(r.Context())
	localReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	localReq.PostForm = localForm

	// Use privileged client credentials for authentication
	privilegedClientID := h.Config.Security.PrivilegedClientID
	if privilegedClientID == "" {
		h.Log.Errorf("❌ No privileged client configured")
		http.Error(w, "server configuration error", http.StatusInternalServerError)
		return
	}

	privilegedClientSecret, exists := h.PrivilegedClientSecrets[privilegedClientID]
	if !exists {
		h.Log.Errorf("❌ Privileged client secret not found for client: %s", privilegedClientID)
		http.Error(w, "server configuration error", http.StatusInternalServerError)
		return
	}

	localReq.SetBasicAuth(privilegedClientID, privilegedClientSecret)
	h.Log.Debugf("✅ Using privileged client %s for introspection", privilegedClientID)

	// Create the introspection request using Fosite directly
	ctx := localReq.Context()

	ir, err := h.OAuth2Provider.NewIntrospectionRequest(ctx, localReq, newSession())
	if err != nil {
		h.Log.Errorf("❌ Error creating privileged introspection request: %v", err)
		h.OAuth2Provider.WriteIntrospectionError(ctx, w, err)
		return
	}

	// Debug: Log extra claims from the introspection session
	if resp, ok := ir.(*fosite.IntrospectionResponse); ok {
		session := resp.AccessRequester.GetSession()
		if ds, ok := session.(*openid.DefaultSession); ok {
			h.Log.Debugf("🔍 Privileged Introspection Session Subject: '%s'", ds.GetSubject())
			if ds.Claims != nil {
				h.Log.Debugf("🔍 Privileged Introspection Session Extra Claims: %+v", ds.Claims.Extra)
				for key, value := range ds.Claims.Extra {
					h.Log.Debugf("🔍 Privileged Introspection Session Extra Claim [%s]: %v", key, value)
				}
			} else {
				h.Log.Debugf("🔍 Privileged Introspection Session has no Claims")
			}
		}
	}

	// Capture the response to add issuer_state and attestation
	capture := newResponseCapture(w)
	h.OAuth2Provider.WriteIntrospectionResponse(ctx, capture, ir)

	// Parse the JSON response
	var response map[string]interface{}
	if err := json.Unmarshal(capture.body.Bytes(), &response); err != nil {
		h.Log.Errorf("❌ Error parsing privileged introspection response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Debug: Log all response keys and values
	h.Log.Debugf("🔍 Privileged Introspection Response Keys: %v", getMapKeys(response))
	for key, value := range response {
		h.Log.Debugf("🔍 Privileged Response [%s]: %v", key, value)
	}

	// Add issuer_state if the token is active
	if active, ok := response["active"].(bool); ok && active {
		h.Log.Debugf("🔍 Token is active, checking for issuer_state and attestation")

		// Add attested client information to the response
		response["attested_client_id"] = attestedClientID
		h.Log.Debugf("🔍 Added attested client ID to response: %s", attestedClientID)

		// Manually add extra claims from the introspection session
		if resp, ok := ir.(*fosite.IntrospectionResponse); ok {
			session := resp.AccessRequester.GetSession()
			if ds, ok := session.(*openid.DefaultSession); ok && ds.Claims != nil && ds.Claims.Extra != nil {
				for key, value := range ds.Claims.Extra {
					response[key] = value
					h.Log.Debugf("🔍 Added extra claim to privileged response [%s]: %v", key, value)
				}
			}

			// Add scope to the response if not present
			if _, hasScope := response["scope"]; !hasScope {
				if accessRequester := resp.AccessRequester; accessRequester != nil {
					h.Log.Debugf("🔍 Privileged AccessRequester is not nil")
					scopes := accessRequester.GetGrantedScopes()
					h.Log.Debugf("🔍 Privileged GetGrantedScopes returned: %v", scopes)
					if len(scopes) > 0 {
						response["scope"] = strings.Join(scopes, " ")
						h.Log.Debugf("🔍 Added scope to privileged introspection response: %v", scopes)
					} else {
						h.Log.Debugf("🔍 Privileged No scopes returned from GetGrantedScopes, checking session Extra")
						// Check if scopes are stored in the session's Extra field
						if session := resp.AccessRequester.GetSession(); session != nil {
							if ds, ok := session.(*openid.DefaultSession); ok && ds.Claims != nil && ds.Claims.Extra != nil {
								if grantedScopes, ok := ds.Claims.Extra["granted_scopes"].([]interface{}); ok {
									var scopeStrings []string
									for _, scope := range grantedScopes {
										if scopeStr, ok := scope.(string); ok {
											scopeStrings = append(scopeStrings, scopeStr)
										}
									}
									if len(scopeStrings) > 0 {
										response["scope"] = strings.Join(scopeStrings, " ")
										h.Log.Debugf("🔍 Added scope from session Extra to privileged introspection response: %v", scopeStrings)
									}
								} else if grantedScopes, ok := ds.Claims.Extra["granted_scopes"].([]string); ok {
									if len(grantedScopes) > 0 {
										response["scope"] = strings.Join(grantedScopes, " ")
										h.Log.Debugf("🔍 Added scope from session Extra to privileged introspection response: %v", grantedScopes)
									}
								}
							}
						}
					}
				} else {
					h.Log.Debugf("🔍 Privileged AccessRequester is nil")
				}
			}
		}

		h.Log.Debugf("✅ Attestation and issuer_state info added from privileged introspection session")
	} else {
		h.Log.Errorf("⚠️ Token is not active (active=%t, ok=%t)", active, ok)
	}

	h.Log.Debugf("🔍 Final privileged response before encoding: %+v", response)

	// Write the modified response
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(capture.statusCode)
	json.NewEncoder(w).Encode(response)
}

// handleLocalIntrospectionWithCredentials creates a local introspection request with client credentials
// This applies the same trick as the token handler: bridge JWT authentication to standard OAuth2 flow
func (h *IntrospectionHandler) handleLocalIntrospectionWithCredentials(w http.ResponseWriter, r *http.Request, clientID string) {
	tokenValue := r.FormValue("token")
	if tokenValue == "" {
		h.Log.Errorf("❌ No token provided for local introspection")
		http.Error(w, "invalid_request: missing token", http.StatusBadRequest)
		return
	}

	h.Log.Debugf("🔄 Creating local introspection request for JWT-authenticated client: %s", clientID)

	// Debug: Decode and log token claims
	if tokenValue != "" {
		h.logTokenClaims(tokenValue)
	}

	// Create a new request for local introspection instead of modifying the original
	localForm := make(url.Values)
	localForm.Set("token", tokenValue)
	if tokenTypeHint := r.FormValue("token_type_hint"); tokenTypeHint != "" {
		localForm.Set("token_type_hint", tokenTypeHint)
	}

	localReq, err := http.NewRequest("POST", "http://localhost:8080/introspect", strings.NewReader(localForm.Encode()))
	if err != nil {
		h.Log.Errorf("❌ Failed to create local introspection request: %v", err)
		http.Error(w, "failed to create local introspection request", http.StatusInternalServerError)
		return
	}
	// Copy the context from the original request to preserve attestation information
	localReq = localReq.WithContext(r.Context())
	localReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	localReq.PostForm = localForm

	// Set basic auth with the attested client's credentials
	// This assumes the client has stored credentials (like in the token handler)
	if secret, ok := GetClientSecret(clientID, h.Storage, h.SecretManager); ok {
		localReq.SetBasicAuth(clientID, secret)
		h.Log.Debugf("✅ Used stored credentials for basic auth in local introspection")
	} else {
		h.Log.Errorf("❌ No stored credentials found for client: %s", clientID)
		// For clients without stored secrets, we could create a temporary client
		// or fall back to manual introspection
		h.handleManualIntrospection(w, r, clientID)
		return
	}

	// Create the introspection request using Fosite directly
	ctx := localReq.Context()

	ir, err := h.OAuth2Provider.NewIntrospectionRequest(ctx, localReq, newSession())
	if err != nil {
		h.Log.Errorf("❌ Error creating local introspection request: %v", err)
		h.OAuth2Provider.WriteIntrospectionError(ctx, w, err)
		return
	}

	// Debug: Log extra claims from the introspection session
	if resp, ok := ir.(*fosite.IntrospectionResponse); ok {
		session := resp.AccessRequester.GetSession()
		if ds, ok := session.(*openid.DefaultSession); ok {
			h.Log.Debugf("🔍 Introspection Session Subject: '%s'", ds.GetSubject())
			if ds.Claims != nil {
				h.Log.Debugf("🔍 Introspection Session Extra Claims: %+v", ds.Claims.Extra)
				for key, value := range ds.Claims.Extra {
					h.Log.Debugf("🔍 Introspection Session Extra Claim [%s]: %v", key, value)
				}
			} else {
				h.Log.Debugf("🔍 Introspection Session has no Claims")
			}
		}
	}

	// Capture the response to add issuer_state and attestation
	capture := newResponseCapture(w)
	h.OAuth2Provider.WriteIntrospectionResponse(ctx, capture, ir)

	// Parse the JSON response
	var response map[string]interface{}
	if err := json.Unmarshal(capture.body.Bytes(), &response); err != nil {
		h.Log.Errorf("❌ Error parsing local introspection response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Debug: Log all response keys and values
	h.Log.Debugf("🔍 Introspection Response Keys: %v", getMapKeys(response))
	for key, value := range response {
		h.Log.Debugf("🔍 Response [%s]: %v", key, value)
	}

	// Add issuer_state if the token is active
	if active, ok := response["active"].(bool); ok && active {
		h.Log.Debugf("🔍 Token is active, checking for issuer_state and attestation")

		// Manually add extra claims from the introspection session
		if resp, ok := ir.(*fosite.IntrospectionResponse); ok {
			session := resp.AccessRequester.GetSession()
			if ds, ok := session.(*openid.DefaultSession); ok && ds.Claims != nil && ds.Claims.Extra != nil {
				for key, value := range ds.Claims.Extra {
					response[key] = value
					h.Log.Debugf("🔍 Added extra claim to response [%s]: %v", key, value)
				}
			}

			// Add scope to the response if not present
			if _, hasScope := response["scope"]; !hasScope {
				if accessRequester := resp.AccessRequester; accessRequester != nil {
					h.Log.Debugf("🔍 Local AccessRequester is not nil")
					scopes := accessRequester.GetGrantedScopes()
					h.Log.Debugf("🔍 Local GetGrantedScopes returned: %v", scopes)
					if len(scopes) > 0 {
						response["scope"] = strings.Join(scopes, " ")
						h.Log.Debugf("🔍 Added scope to local introspection response: %v", scopes)
					} else {
						h.Log.Debugf("🔍 Local No scopes returned from GetGrantedScopes, checking session Extra")
						// Check if scopes are stored in the session's Extra field
						if session := resp.AccessRequester.GetSession(); session != nil {
							if ds, ok := session.(*openid.DefaultSession); ok && ds.Claims != nil && ds.Claims.Extra != nil {
								if grantedScopes, ok := ds.Claims.Extra["granted_scopes"].([]interface{}); ok {
									var scopeStrings []string
									for _, scope := range grantedScopes {
										if scopeStr, ok := scope.(string); ok {
											scopeStrings = append(scopeStrings, scopeStr)
										}
									}
									if len(scopeStrings) > 0 {
										response["scope"] = strings.Join(scopeStrings, " ")
										h.Log.Debugf("🔍 Added scope from session Extra to local introspection response: %v", scopeStrings)
									}
								} else if grantedScopes, ok := ds.Claims.Extra["granted_scopes"].([]string); ok {
									if len(grantedScopes) > 0 {
										response["scope"] = strings.Join(grantedScopes, " ")
										h.Log.Debugf("🔍 Added scope from session Extra to local introspection response: %v", grantedScopes)
									}
								}
							}
						}
					}
				} else {
					h.Log.Debugf("🔍 Local AccessRequester is nil")
				}
			}
		}

		h.Log.Debugf("✅ Attestation and issuer_state info added from introspection session")
	} else {
		h.Log.Debugf("⚠️ Token is not active (active=%t, ok=%t)", active, ok)
	}

	h.Log.Debugf("🔍 Final response before encoding: %+v", response)

	// Write the modified response
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(capture.statusCode)
	json.NewEncoder(w).Encode(response)
}

// handleManualIntrospection performs token introspection manually when Fosite fails but JWT auth succeeds
func (h *IntrospectionHandler) handleManualIntrospection(w http.ResponseWriter, r *http.Request, clientID string) {
	tokenValue := r.FormValue("token")
	if tokenValue == "" {
		h.Log.Errorf("❌ No token provided for manual introspection")
		http.Error(w, "invalid_request: missing token", http.StatusBadRequest)
		return
	}

	h.Log.Debugf("🔍 Performing manual introspection for token from client: %s", clientID)

	// Parse the token to extract claims
	parts := strings.Split(tokenValue, ".")
	if len(parts) != 3 {
		h.Log.Errorf("❌ Invalid JWT format for manual introspection")
		response := map[string]interface{}{
			"active": false,
			"error":  "invalid_token",
		}
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Decode the payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		h.Log.Errorf("❌ Error decoding JWT payload: %v", err)
		response := map[string]interface{}{
			"active": false,
			"error":  "invalid_token",
		}
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Parse the claims
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		h.Log.Errorf("❌ Error parsing JWT claims: %v", err)
		response := map[string]interface{}{
			"active": false,
			"error":  "invalid_token",
		}
		w.Header().Set("Content-Type", "application/json;charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
		return
	}

	// Check if token is expired
	now := time.Now().Unix()
	var exp int64
	if expVal, ok := claims["exp"].(float64); ok {
		exp = int64(expVal)
	}

	active := exp == 0 || exp > now

	// Build introspection response
	response := map[string]interface{}{
		"active": active,
	}

	if active {
		// Add standard claims
		if sub, ok := claims["sub"].(string); ok {
			response["sub"] = sub
		}
		if iss, ok := claims["iss"].(string); ok {
			response["iss"] = iss
		}
		if aud, ok := claims["aud"].(string); ok {
			response["aud"] = aud
		}
		if clientId, ok := claims["client_id"].(string); ok {
			response["client_id"] = clientId
		}
		if scope, ok := claims["scope"].(string); ok {
			response["scope"] = scope
		}
		if tokenType, ok := claims["token_type"].(string); ok {
			response["token_type"] = tokenType
		}
		if exp > 0 {
			response["exp"] = exp
		}
		if iat, ok := claims["iat"].(float64); ok {
			response["iat"] = int64(iat)
		}

		// Add issuer_state if present
		if issuerState, exists := claims["issuer_state"]; exists {
			response["issuer_state"] = issuerState
		}

		// Add attestation information for JWT-authenticated clients
		if attestationResult, hasAttestation := attestation.GetAttestationResult(r.Context()); hasAttestation && attestationResult.Valid {
			attestationInfo := map[string]interface{}{
				"attestation_verified":    true,
				"attestation_trust_level": attestationResult.TrustLevel,
				"attestation_issued_at":   attestationResult.IssuedAt.Unix(),
				"attestation_expires_at":  attestationResult.ExpiresAt.Unix(),
			}

			if attestationResult.Claims != nil {
				if keyId, ok := attestationResult.Claims["att_device_id"].(string); ok && keyId != "" {
					attestationInfo["attestation_key_id"] = keyId
				} else if issuerKeyId, ok := attestationResult.Claims["iss"].(string); ok && strings.Contains(issuerKeyId, "hsm:") {
					// Extract key ID from issuer claim like "hsm:hsm_ae26b334"
					parts := strings.Split(issuerKeyId, ":")
					if len(parts) == 2 {
						attestationInfo["attestation_key_id"] = parts[1]
					}
				}
				if hsmBacked, ok := attestationResult.Claims["att_hardware_backed"].(bool); ok {
					attestationInfo["hsm_backed"] = hsmBacked
				}
				if bioAuth, ok := attestationResult.Claims["att_biometric"].(bool); ok {
					attestationInfo["bio_authenticated"] = bioAuth
				}
			}

			response["attestation"] = attestationInfo
		}
	}

	h.Log.Debugf("✅ Manual introspection completed - Active: %t", active)

	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// extractClientIDFromJWT extracts the client_id from a JWT client assertion
func (h *IntrospectionHandler) extractClientIDFromJWT(clientAssertion string) string {
	if clientAssertion == "" {
		return ""
	}

	// JWT format: header.payload.signature
	parts := strings.Split(clientAssertion, ".")
	if len(parts) != 3 {
		h.Log.Errorf("❌ Invalid JWT format in client assertion")
		return ""
	}

	// Decode the payload (second part)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		h.Log.Errorf("❌ Error decoding JWT payload: %v", err)
		return ""
	}

	// Parse the JSON payload
	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		h.Log.Errorf("❌ Error parsing JWT claims: %v", err)
		return ""
	}

	// Extract client_id from claims
	if clientID, ok := claims["sub"].(string); ok && clientID != "" {
		return clientID
	}

	// Also check 'iss' claim as fallback
	if clientID, ok := claims["iss"].(string); ok && clientID != "" {
		return clientID
	}

	h.Log.Errorf("❌ No client_id found in JWT claims")
	return ""
}

// logTokenClaims decodes and logs the claims from a JWT token for debugging
func (h *IntrospectionHandler) logTokenClaims(tokenValue string) {
	parts := strings.Split(tokenValue, ".")
	if len(parts) != 3 {
		h.Log.Debugf("🔍 Token is not a valid JWT (not 3 parts)")
		return
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		h.Log.Debugf("🔍 Error decoding token payload: %v", err)
		return
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		h.Log.Debugf("🔍 Error parsing token claims: %v", err)
		return
	}

	h.Log.Debugf("🔍 Token Claims: %+v", claims)
	for key, value := range claims {
		h.Log.Debugf("🔍 Token Claim [%s]: %v", key, value)
	}
}

// getMapKeys returns a slice of keys from a map
func getMapKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
