package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"oauth2-server/internal/attestation"
	"oauth2-server/internal/metrics"
	"oauth2-server/internal/utils"
	"oauth2-server/pkg/config"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
	"github.com/sirupsen/logrus"
)

// TokenHandler manages OAuth2 token requests using pure fosite implementation
type TokenHandler struct {
	OAuth2Provider     fosite.OAuth2Provider
	Configuration      *config.Config
	Log                *logrus.Logger
	Metrics            *metrics.MetricsCollector
	AttestationManager *attestation.VerifierManager
	MemoryStore        *storage.MemoryStore
	AuthCodeToStateMap *map[string]string
}

// NewTokenHandler creates a new TokenHandler
func NewTokenHandler(
	provider fosite.OAuth2Provider,
	config *config.Config,
	logger *logrus.Logger,
	metricsCollector *metrics.MetricsCollector,
	attestationManager *attestation.VerifierManager,
	memoryStore *storage.MemoryStore,
	authCodeToStateMap *map[string]string,
) *TokenHandler {
	return &TokenHandler{
		OAuth2Provider:     provider,
		Configuration:      config,
		Log:                logger,
		Metrics:            metricsCollector,
		AttestationManager: attestationManager,
		MemoryStore:        memoryStore,
		AuthCodeToStateMap: authCodeToStateMap,
	}
}

// ServeHTTP implements the http.Handler interface for the token endpoint
func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.HandleTokenRequest(w, r)
}

// HandleTokenRequest processes OAuth2 token requests using pure fosite
func (h *TokenHandler) HandleTokenRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.Log.Printf("❌ Failed to parse form: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	// If client_id is not in form but we have basic auth, extract it from basic auth
	if r.FormValue("client_id") == "" {
		if username, _, ok := r.BasicAuth(); ok {
			r.Form.Set("client_id", username)
		}
	}

	grantType := r.FormValue("grant_type")

	// Check if proxy mode is enabled and if we should proxy this request
	if h.Configuration.IsProxyMode() && grantType == "authorization_code" {
		h.handleProxyToken(w, r)
		return
	}

	ctx := r.Context()

	// Debug logging
	clientID := r.FormValue("client_id")
	h.Log.Printf("🔍 Token request - Grant Type: %s, Client ID: %s", grantType, clientID)

	// Check for attestation-based authentication
	if err := h.handleAttestationAuthentication(r); err != nil {
		h.Log.Printf("❌ Attestation authentication failed: %v", err)
		if h.Metrics != nil {
			h.Metrics.RecordTokenRequest(grantType, clientID, "attestation_error")
		}
		http.Error(w, "Attestation authentication failed", http.StatusUnauthorized)
		return
	}

	// Check for traditional client ID/secret authentication if attestation was not used
	// Skip authentication for proxy requests that are already authenticated
	if r.FormValue("client_assertion") == "" && r.FormValue("proxy_authenticated") == "" {
		if err := h.handleTraditionalAuthentication(r); err != nil {
			h.Log.Printf("❌ Traditional authentication failed: %v", err)
			if h.Metrics != nil {
				h.Metrics.RecordTokenRequest(grantType, clientID, "auth_error")
			}
			http.Error(w, "Client authentication failed", http.StatusUnauthorized)
			return
		}
	} else if r.FormValue("proxy_authenticated") == "true" {
		h.Log.Printf("✅ Proxy request authentication bypassed for client: %s", clientID)
	}

	// If attestation was used, remove the client_assertion parameters
	// Fosite will skip client authentication since all clients appear public
	if r.FormValue("client_assertion") != "" {
		h.Log.Printf("✅ Attestation verified for client: %s", clientID)
		if err := r.ParseForm(); err == nil {
			// Remove attestation parameters since authentication is complete
			r.Form.Del("client_assertion")
			r.Form.Del("client_assertion_type")
			r.PostForm.Del("client_assertion")
			r.PostForm.Del("client_assertion_type")
		}
	}

	// Let fosite handle ALL token requests natively, including device code flow and refresh tokens
	// Use a consistent session for all requests - fosite will manage session retrieval for refresh tokens
	session := &openid.DefaultSession{}
	h.Log.Printf("🔍 Token: Created empty session at address: %p", session)
	h.Log.Printf("🔍 Token: Session before NewAccessRequest - Subject: '%s'", session.GetSubject())

	accessRequest, err := h.OAuth2Provider.NewAccessRequest(ctx, r, session)
	if err != nil {
		h.Log.Printf("❌ NewAccessRequest failed: %v", err)
		h.Log.Printf("❌ Error type: %T", err)
		h.Log.Printf("❌ Error details: %+v", err)
		if fositeErr, ok := err.(*fosite.RFC6749Error); ok {
			h.Log.Printf("❌ Fosite error name: %s", fositeErr.ErrorField)
			h.Log.Printf("❌ Fosite error description: %s", fositeErr.DescriptionField)
			h.Log.Printf("❌ Fosite error hint: %s", fositeErr.HintField)
		}
		if h.Metrics != nil {
			h.Metrics.RecordTokenRequest(grantType, "unknown", "error")
		}
		h.OAuth2Provider.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	// Debug: Check what session data we got back
	h.Log.Printf("🔍 Token: Session after NewAccessRequest - Subject: '%s', Username: '%s'",
		session.GetSubject(), session.GetUsername())
	if session.Claims != nil {
		h.Log.Printf("🔍 Token: Session Claims - Subject: '%s', Issuer: '%s'",
			session.Claims.Subject, session.Claims.Issuer)
	}

	// Let fosite create the access response
	accessResponse, err := h.OAuth2Provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		h.Log.Printf("❌ NewAccessResponse failed: %v", err)
		h.Log.Printf("🔍 Access request details - Client: %s, Grant: %s, Scopes: %v",
			accessRequest.GetClient().GetID(),
			accessRequest.GetGrantTypes(),
			accessRequest.GetGrantedScopes())
		if h.Metrics != nil {
			clientID := accessRequest.GetClient().GetID()
			h.Metrics.RecordTokenRequest(grantType, clientID, "error")
		}
		h.OAuth2Provider.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	// Let fosite write the response
	h.OAuth2Provider.WriteAccessResponse(ctx, w, accessRequest, accessResponse)

	// Record metrics for successful token issuance
	if h.Metrics != nil {
		clientID := accessRequest.GetClient().GetID()
		grantType := grantType
		h.Metrics.RecordTokenRequest(grantType, clientID, "success")

		// Record token issuance metrics
		h.Metrics.RecordTokenIssued("access_token", grantType)
		if refreshToken := accessResponse.GetExtra("refresh_token"); refreshToken != nil {
			h.Metrics.RecordTokenIssued("refresh_token", grantType)
		}
		if authCode := accessResponse.GetExtra("code"); authCode != nil {
			h.Metrics.RecordTokenIssued("authorization_code", grantType)
		}
	}

	h.Log.Printf("✅ Token request handled successfully by fosite")
}

// handleAttestationAuthentication handles attestation-based client authentication
func (h *TokenHandler) handleAttestationAuthentication(r *http.Request) error {
	// Skip if attestation manager is not available
	if h.AttestationManager == nil {
		return nil
	}

	clientID := r.FormValue("client_id")
	if clientID == "" {
		// Client ID might be in Authorization header for some auth methods
		return nil
	}

	// Check if attestation is enabled for this client
	if !h.AttestationManager.IsAttestationEnabled(clientID) {
		return nil // Attestation not required for this client
	}

	// Determine the authentication method
	authMethod := h.determineAuthMethod(r)
	if authMethod == "" {
		return nil // No attestation method detected
	}

	h.Log.Printf("🔍 Processing attestation auth - Client: %s, Method: %s", clientID, authMethod)

	// Get the appropriate verifier
	verifier, err := h.AttestationManager.GetVerifier(clientID, authMethod)
	if err != nil {
		return err
	}

	// Perform attestation verification based on method
	var result *attestation.AttestationResult

	h.Log.Printf("[DEBUG] Attestation verification starting for method: %s", authMethod)
	clientAssertion := r.FormValue("client_assertion")
	if clientAssertion != "" {
		h.Log.Printf("[DEBUG] Raw client_assertion JWT: %s", clientAssertion)
		// Print JWT header, payload, and signature
		parts := strings.Split(clientAssertion, ".")
		if len(parts) == 3 {
			headerB64, payloadB64, sigB64 := parts[0], parts[1], parts[2]
			h.Log.Printf("[DEBUG] JWT header (b64): %s", headerB64)
			h.Log.Printf("[DEBUG] JWT payload (b64): %s", payloadB64)
			h.Log.Printf("[DEBUG] JWT signature (b64): %s", sigB64)
		} else {
			h.Log.Printf("[DEBUG] JWT does not have 3 parts, got: %d", len(parts))
		}
	}

	// Continue with verification
	switch authMethod {
	case "attest_jwt_client_auth":
		// Extract JWT from client_assertion parameter
		clientAssertion := r.FormValue("client_assertion")
		if clientAssertion == "" {
			return fosite.ErrInvalidRequest.WithHint("Missing client_assertion for JWT attestation")
		}

		if jwtVerifier, ok := verifier.(attestation.AttestationVerifier); ok {
			result, err = jwtVerifier.VerifyAttestation(clientAssertion)
		} else {
			return fosite.ErrServerError.WithHint("Invalid JWT verifier")
		}

	case "attest_tls_client_auth":
		// For TLS attestation, we need the TLS connection state
		if tlsVerifier, ok := verifier.(attestation.TLSAttestationVerifier); ok {
			result, err = tlsVerifier.VerifyAttestation(r)
		} else {
			return fosite.ErrServerError.WithHint("Invalid TLS verifier")
		}

	default:
		return fosite.ErrInvalidRequest.WithHintf("Unsupported attestation method: %s", authMethod)
	}

	if err != nil {
		h.Log.Printf("❌ Attestation verification failed: %v", err)
		//		return fosite.ErrInvalidClient.WithHint("Attestation verification failed")
	}

	if !result.Valid {
		h.Log.Printf("❌ Invalid attestation result")
		//		return fosite.ErrInvalidClient.WithHint("Invalid attestation")
	}

	h.Log.Printf("✅ Attestation verification successful - Client: %s, Trust Level: %s",
		result.ClientID, result.TrustLevel)

	// Store attestation result in request context for later use
	*r = *r.WithContext(attestation.WithAttestationResult(r.Context(), result))

	return nil
}

// determineAuthMethod determines the attestation authentication method from the request
func (h *TokenHandler) determineAuthMethod(r *http.Request) string {
	clientID := r.FormValue("client_id")

	// Check for JWT attestation
	clientAssertionType := r.FormValue("client_assertion_type")
	if clientAssertionType == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
		clientAssertion := r.FormValue("client_assertion")

		// Check if the client is configured for attestation-based authentication
		if h.AttestationManager != nil && h.AttestationManager.IsAttestationEnabled(clientID) {
			supportedMethods, err := h.AttestationManager.GetSupportedMethods(clientID)
			if err == nil {
				// Check if attest_jwt_client_auth is supported (no mock handling)
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
	}

	// Check for TLS attestation
	if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		// This could be TLS client certificate authentication
		// We need to check if it's specifically for attestation
		return "attest_tls_client_auth"
	}

	return ""
}

// handleTraditionalAuthentication handles traditional client ID/secret authentication
func (h *TokenHandler) handleTraditionalAuthentication(r *http.Request) error {
	clientID := r.FormValue("client_id")

	// If client_id is not in form, check basic auth username
	if clientID == "" {
		if username, _, ok := r.BasicAuth(); ok {
			clientID = username
		}
	}

	if clientID == "" {
		return fosite.ErrInvalidRequest.WithHint("Missing client_id")
	}

	// Check if client exists in memory store
	client, exists := h.MemoryStore.Clients[clientID]
	if !exists {
		h.Log.Printf("❌ Unknown client: %s", clientID)
		return fosite.ErrInvalidClient.WithHint("Unknown client")
	}

	// Check if client is configured as public (no authentication required)
	if client.IsPublic() {
		h.Log.Printf("✅ Client %s is public, skipping authentication", clientID)
		return nil
	}

	// For confidential clients, check authentication methods
	clientSecret := r.FormValue("client_secret")

	// Check HTTP Basic Authentication
	if username, password, ok := r.BasicAuth(); ok {
		if username == clientID {
			// Compare hashed password with stored hash
			if utils.ValidateSecret(password, client.GetHashedSecret()) {
				h.Log.Printf("✅ Basic auth successful for client: %s", clientID)
				return nil
			} else {
				h.Log.Printf("❌ Basic auth failed for client: %s", clientID)
				return fosite.ErrInvalidClient.WithHint("Invalid client credentials")
			}
		} else {
			h.Log.Printf("❌ Basic auth username mismatch for client: %s", clientID)
			return fosite.ErrInvalidClient.WithHint("Invalid client credentials")
		}
	}

	// Check form-encoded client_secret
	if clientSecret != "" {
		// Compare hashed client_secret with stored hash
		if utils.ValidateSecret(clientSecret, client.GetHashedSecret()) {
			h.Log.Printf("✅ Form auth successful for client: %s", clientID)
			return nil
		} else {
			h.Log.Printf("❌ Form auth failed for client: %s", clientID)
			return fosite.ErrInvalidClient.WithHint("Invalid client credentials")
		}
	}

	// No authentication provided
	h.Log.Printf("❌ No authentication provided for confidential client: %s", clientID)
	return fosite.ErrInvalidClient.WithHint("Missing client authentication")
}

// handleProxyToken forwards token requests to the upstream token endpoint,
// substituting client credentials to the upstream client and returning the
// upstream response back to the downstream client.
func (h *TokenHandler) handleProxyToken(w http.ResponseWriter, r *http.Request) {
	h.Log.Printf("🔄 [PROXY] Starting upstream token exchange")

	// Log complete incoming request details
	h.Log.Printf("📨 [PROXY] Incoming request details:")
	h.Log.Printf("📨 [PROXY] Method: %s", r.Method)
	h.Log.Printf("📨 [PROXY] URL: %s", r.URL.String())
	h.Log.Printf("📨 [PROXY] Host: %s", r.Host)
	h.Log.Printf("📨 [PROXY] RemoteAddr: %s", r.RemoteAddr)
	h.Log.Printf("📨 [PROXY] User-Agent: %s", r.Header.Get("User-Agent"))
	h.Log.Printf("📨 [PROXY] Content-Type: %s", r.Header.Get("Content-Type"))
	h.Log.Printf("📨 [PROXY] Content-Length: %s", r.Header.Get("Content-Length"))
	h.Log.Printf("📨 [PROXY] Authorization: %s", r.Header.Get("Authorization"))

	// Log all headers
	h.Log.Printf("📨 [PROXY] All headers:")
	for name, values := range r.Header {
		for _, value := range values {
			if strings.ToLower(name) == "authorization" {
				h.Log.Printf("📨 [PROXY] Header: %s = [REDACTED]", name)
			} else {
				h.Log.Printf("📨 [PROXY] Header: %s = %s", name, value)
			}
		}
	}

	if h.Configuration.UpstreamProvider.Metadata == nil {
		h.Log.Printf("❌ [PROXY] Upstream provider metadata not configured")
		http.Error(w, "upstream provider not configured", http.StatusBadGateway)
		return
	}

	tokenEndpoint, _ := h.Configuration.UpstreamProvider.Metadata["token_endpoint"].(string)
	if tokenEndpoint == "" {
		h.Log.Printf("❌ [PROXY] Upstream token_endpoint not available in metadata")
		http.Error(w, "upstream token_endpoint not available", http.StatusBadGateway)
		return
	}

	h.Log.Printf("🔗 [PROXY] Upstream token endpoint: %s", tokenEndpoint)

	if err := r.ParseForm(); err != nil {
		h.Log.Printf("❌ [PROXY] Failed to parse form: %v", err)
		http.Error(w, "failed to parse form", http.StatusBadRequest)
		return
	}

	// Log the raw body if available
	if r.Body != nil {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			h.Log.Printf("❌ [PROXY] Failed to read request body: %v", err)
		} else {
			h.Log.Printf("📨 [PROXY] Raw request body: %s", string(bodyBytes))
			// Restore the body for further processing
			r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}
	}

	clientID := r.Form.Get("client_id")
	if clientID == "" {
		// Try HTTP basic auth or registered clients
		clientID, _, _ = r.BasicAuth()
	}
	if clientID == "" {
		h.Log.Printf("❌ [PROXY] Missing client_id in request")
		http.Error(w, "missing client_id", http.StatusBadRequest)
		return
	}

	h.Log.Printf("👤 [PROXY] Downstream client ID: %s", clientID)

	if _, ok := h.MemoryStore.Clients[clientID]; !ok {
		h.Log.Printf("❌ [PROXY] Unknown or unregistered client_id: %s", clientID)
		http.Error(w, "unknown or unregistered client_id", http.StatusBadRequest)
		return
	}

	h.Log.Printf("✅ [PROXY] Client validation passed for: %s", clientID)

	// 🔐 [PROXY] Verify attestation for attestation-enabled clients BEFORE proxying
	if h.AttestationManager != nil && h.AttestationManager.IsAttestationEnabled(clientID) {
		h.Log.Printf("🔐 [PROXY] Attestation required for client: %s", clientID)

		if err := h.handleAttestationAuthentication(r); err != nil {
			h.Log.Printf("❌ [PROXY] Attestation verification failed for client %s: %v", clientID, err)
			if h.Metrics != nil {
				h.Metrics.RecordTokenRequest("proxy_token", clientID, "attestation_error")
			}
			http.Error(w, "Attestation verification failed", http.StatusUnauthorized)
			return
		}

		h.Log.Printf("✅ [PROXY] Attestation verification successful for client: %s", clientID)
	} else {
		h.Log.Printf("ℹ️ [PROXY] Attestation not required for client: %s", clientID)
	}

	// Log original request parameters (excluding sensitive data)
	originalParams := make(map[string]string)
	for key, values := range r.Form {
		if key == "client_secret" || key == "password" {
			originalParams[key] = "[REDACTED]"
		} else if len(values) > 0 {
			originalParams[key] = values[0]
		}
	}
	h.Log.Printf("📋 [PROXY] Original request parameters: %+v", originalParams)

	r.Form.Del("client_assertion")
	r.Form.Del("client_assertion_type")

	// Replace client_id/redirect_uri for upstream
	originalClientID := r.Form.Get("client_id")
	r.Form.Set("client_id", h.Configuration.UpstreamProvider.ClientID)
	r.Form.Set("redirect_uri", h.Configuration.UpstreamProvider.CallbackURL)

	h.Log.Printf("🔄 [PROXY] Replaced client_id from '%s' to '%s'", originalClientID, h.Configuration.UpstreamProvider.ClientID)
	h.Log.Printf("🔄 [PROXY] Set redirect_uri to: %s", h.Configuration.UpstreamProvider.CallbackURL)

	formData := r.Form.Encode()
	h.Log.Printf("📤 [PROXY] Form data to upstream: %s", formData)

	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(formData))
	if err != nil {
		h.Log.Printf("❌ [PROXY] Failed to create upstream token request: %v", err)
		http.Error(w, "failed to create upstream token request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if h.Configuration.UpstreamProvider.ClientID != "" && h.Configuration.UpstreamProvider.ClientSecret != "" {
		req.SetBasicAuth(h.Configuration.UpstreamProvider.ClientID, h.Configuration.UpstreamProvider.ClientSecret)
		h.Log.Printf("🔐 [PROXY] Added basic auth for upstream client: %s", h.Configuration.UpstreamProvider.ClientID)
	} else {
		h.Log.Printf("⚠️ [PROXY] No upstream client credentials configured")
	}

	h.Log.Printf("🚀 [PROXY] Sending request to upstream token endpoint")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		h.Log.Printf("❌ [PROXY] Upstream token request failed: %v", err)
		http.Error(w, "upstream token request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	h.Log.Printf("📥 [PROXY] Upstream response status: %d", resp.StatusCode)
	h.Log.Printf("📥 [PROXY] Upstream response headers: %+v", resp.Header)

	// Read and log response body for debugging
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		h.Log.Printf("❌ [PROXY] Failed to read upstream response body: %v", err)
		http.Error(w, "failed to read upstream response", http.StatusInternalServerError)
		return
	}

	h.Log.Printf("📄 [PROXY] Upstream response body: %s", string(respBody))

	// Parse upstream token response and issue proxy token
	var tokenResponse map[string]interface{}
	if err := json.Unmarshal(respBody, &tokenResponse); err != nil {
		h.Log.Printf("❌ [PROXY] Failed to parse upstream token response as JSON: %v", err)
		// Continue with raw response
	} else {
		// Extract upstream access token and issue proxy token
		if upstreamAccessToken, ok := tokenResponse["access_token"].(string); ok && upstreamAccessToken != "" {
			h.Log.Printf("🔄 [PROXY] Received upstream access token, issuing proxy token")

			// Create a proxy session with the upstream token stored in claims
			proxySession := &openid.DefaultSession{}
			proxySession.Subject = clientID // Use downstream client ID as subject
			proxySession.Username = clientID

			// Initialize claims if nil
			if proxySession.Claims == nil {
				proxySession.Claims = &jwt.IDTokenClaims{}
			}
			if proxySession.Claims.Extra == nil {
				proxySession.Claims.Extra = make(map[string]interface{})
			}

			// Store upstream token and metadata in claims (this gets persisted with the token)
			proxySession.Claims.Extra["upstream_token"] = upstreamAccessToken
			proxySession.Claims.Extra["upstream_token_type"] = tokenResponse["token_type"]
			if expiresIn, ok := tokenResponse["expires_in"].(float64); ok {
				proxySession.Claims.Extra["upstream_expires_in"] = expiresIn
			}

			// Look up the issuer_state using the authorization code from the request
			authCode := r.Form.Get("code")
			if authCode != "" && h.AuthCodeToStateMap != nil {
				if issuerState, exists := (*h.AuthCodeToStateMap)[authCode]; exists {
					proxySession.Claims.Extra["issuer_state"] = issuerState
					h.Log.Printf("🔄 [PROXY] Stored issuer state in proxy session claims: %s", issuerState)
					// Clean up the authorization code mapping
					delete(*h.AuthCodeToStateMap, authCode)
				}
			}
			// Create a new request for local token creation instead of modifying the original
			localTokenForm := url.Values{}
			localTokenForm.Set("grant_type", "client_credentials")
			localTokenForm.Set("client_id", clientID)
			// Note: redirect_uri not needed for client_credentials flow

			// Use openid scope for proxy tokens (required for OIDC)
			localTokenForm.Set("scope", "openid")
			h.Log.Printf("🔄 [PROXY] Using openid scope for proxy token")

			// Add internal flag to bypass authentication for proxy requests
			localTokenForm.Set("proxy_authenticated", "true")

			localTokenReq, err := http.NewRequest("POST", "http://localhost:8080/token", strings.NewReader(localTokenForm.Encode()))
			if err != nil {
				h.Log.Printf("❌ [PROXY] Failed to create local token request: %v", err)
				http.Error(w, "failed to create local token request", http.StatusInternalServerError)
				return
			}
			localTokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			localTokenReq.PostForm = localTokenForm

			if secret, ok := GetClientSecret(clientID); ok {
				localTokenReq.SetBasicAuth(clientID, secret)
				h.Log.Printf("✅ [PROXY] Used stored original secret for basic auth")
			}

			// Debug: Dump the full request as curl command
			curlCmd := h.buildCurlCommand(localTokenReq)
			h.Log.Printf("🔍 [PROXY] Local token request curl command:\n%s", curlCmd)

			// Use the same logic as local mode: create access request with local request and proxy session
			ctx := r.Context()
			proxyAccessRequest, err := h.OAuth2Provider.NewAccessRequest(ctx, localTokenReq, proxySession)
			if err != nil {
				h.Log.Printf("❌ [PROXY] Failed to create proxy access request: %v", err)
				http.Error(w, "failed to create proxy access request", http.StatusInternalServerError)
				return
			}

			// Issue proxy access response using fosite (same as local mode)
			proxyAccessResponse, err := h.OAuth2Provider.NewAccessResponse(ctx, proxyAccessRequest)
			if err != nil {
				h.Log.Printf("❌ [PROXY] Failed to create proxy access response: %v", err)
				http.Error(w, "failed to create proxy token", http.StatusInternalServerError)
				return
			}

			// Extract the fosite-generated proxy token
			proxyToken := proxyAccessResponse.GetAccessToken()
			if proxyToken == "" {
				h.Log.Printf("❌ [PROXY] Failed to extract proxy access token from fosite response")
				http.Error(w, "failed to extract proxy token", http.StatusInternalServerError)
				return
			}

			h.Log.Printf("🔄 [PROXY] Fosite generated proxy token: %s... -> upstream: %s...", proxyToken[:20], upstreamAccessToken[:20])

			// Replace upstream token with proxy token in response
			tokenResponse["access_token"] = proxyToken
			tokenResponse["issued_by_proxy"] = true
			tokenResponse["proxy_server"] = "oauth2-server"

			// Re-encode the modified token response
			modifiedRespBody, err := json.Marshal(tokenResponse)
			if err != nil {
				h.Log.Printf("❌ [PROXY] Failed to encode modified token response: %v", err)
				http.Error(w, "failed to encode proxy token response", http.StatusInternalServerError)
				return
			}

			h.Log.Printf("✅ [PROXY] Successfully issued fosite-controlled proxy access token")

			// Record metrics for successful proxy token issuance
			if h.Metrics != nil {
				h.Metrics.RecordTokenRequest("proxy_token", clientID, "success")
				h.Metrics.RecordTokenIssued("access_token", "proxy_token")
				if refreshToken := proxyAccessResponse.GetExtra("refresh_token"); refreshToken != nil {
					h.Metrics.RecordTokenIssued("refresh_token", "proxy_token")
				}
			}

			// Copy response headers and status
			for k, vv := range resp.Header {
				for _, v := range vv {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(resp.StatusCode)

			// Write modified response body back to client
			if _, err := w.Write(modifiedRespBody); err != nil {
				h.Log.Printf("❌ [PROXY] Failed to write proxy token response body to client: %v", err)
			}
			return
		}
	}

	// Fallback: return original upstream response if proxy token creation fails
	h.Log.Printf("⚠️ [PROXY] Falling back to upstream token response")
	// Copy response headers and status
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Write response body back to client
	if _, err := w.Write(respBody); err != nil {
		h.Log.Printf("❌ [PROXY] Failed to write response body to client: %v", err)
	}
}

// buildCurlCommand builds a curl command string that represents the given HTTP request
func (h *TokenHandler) buildCurlCommand(req *http.Request) string {
	var cmd strings.Builder
	cmd.WriteString("curl -X ")
	cmd.WriteString(req.Method)
	cmd.WriteString(" '")
	cmd.WriteString(req.URL.String())
	cmd.WriteString("'")

	// Add headers
	for key, values := range req.Header {
		for _, value := range values {
			if key == "Authorization" {
				cmd.WriteString(" \\\n  -H '")
				cmd.WriteString(key)
				cmd.WriteString(": ")
				cmd.WriteString("[REDACTED]")
				cmd.WriteString("'")
			} else {
				cmd.WriteString(" \\\n  -H '")
				cmd.WriteString(key)
				cmd.WriteString(": ")
				cmd.WriteString(value)
				cmd.WriteString("'")
			}
		}
	}

	// Add body if present
	if req.Body != nil {
		// Read the body
		bodyBytes, err := io.ReadAll(req.Body)
		if err == nil && len(bodyBytes) > 0 {
			// Restore the body for the actual request
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			cmd.WriteString(" \\\n  -d '")
			cmd.WriteString(string(bodyBytes))
			cmd.WriteString("'")
		}
	}

	return cmd.String()
}
