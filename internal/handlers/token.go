package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"oauth2-server/internal/attestation"
	"oauth2-server/internal/metrics"
	"oauth2-server/internal/store"
	"oauth2-server/pkg/config"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"github.com/sirupsen/logrus"
)

// Context key type for Fosite client
type fositeClientKey string

const clientContextKey fositeClientKey = "client"
const proxyTokenContextKey = "proxy_token"

// TokenHandler manages OAuth2 token requests using pure fosite implementation
type TokenHandler struct {
	OAuth2Provider     fosite.OAuth2Provider
	Configuration      *config.Config
	Log                *logrus.Logger
	Metrics            *metrics.MetricsCollector
	AttestationManager *attestation.VerifierManager
	Storage            store.Storage
	SecretManager      *store.SecretManager
	AuthCodeToStateMap *map[string]string
}

// NewTokenHandler creates a new TokenHandler
func NewTokenHandler(
	provider fosite.OAuth2Provider,
	config *config.Config,
	logger *logrus.Logger,
	metricsCollector *metrics.MetricsCollector,
	attestationManager *attestation.VerifierManager,
	storage store.Storage,
	secretManager *store.SecretManager,
	authCodeToStateMap *map[string]string,
) *TokenHandler {
	return &TokenHandler{
		OAuth2Provider:     provider,
		Configuration:      config,
		Log:                logger,
		Metrics:            metricsCollector,
		AttestationManager: attestationManager,
		Storage:            storage,
		SecretManager:      secretManager,
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
		h.Log.Errorf("❌ Failed to parse form: %v", err)
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

	// WORKAROUND: Fosite incorrectly validates redirect_uri for device_code grant type
	// Add redirect_uri to the request for device_code grant type to work around the bug
	if grantType == "urn:ietf:params:oauth:grant-type:device_code" {
		if r.FormValue("redirect_uri") == "" {
			r.Form.Set("redirect_uri", "urn:ietf:wg:oauth:2.0:oob")
			h.Log.Debugf("🔄 WORKAROUND: Added redirect_uri for device_code grant type")
		}
	}

	// Check if proxy mode is enabled and if we should proxy this request
	if h.Configuration.IsProxyMode() && grantType == "authorization_code" {
		h.handleProxyToken(w, r)
		return
	}

	// Debug logging
	clientID := r.FormValue("client_id")
	h.Log.Debugf("🔍 Token request - Grant Type: %s, Client ID: %s", grantType, clientID)

	// Client authentication is now handled by our custom AuthenticateClient strategy
	// No pre-processing needed - Fosite will call our strategy during NewAccessRequest

	ctx := r.Context()

	// Let fosite handle ALL token requests natively, including device code flow and refresh tokens
	// Use a consistent session for all requests - fosite will manage session retrieval for refresh tokens
	session := &openid.DefaultSession{}
	h.Log.Debugf("🔍 Token: Grant type check - grantType='%s', is_auth_code=%t, is_device_code=%t", grantType, grantType == "authorization_code", grantType == "urn:ietf:params:oauth:grant-type:device_code")
	if grantType == "refresh_token" {
		session.Subject = clientID
		session.Username = clientID
		h.Log.Debugf("🔍 Token: Set session to client_id for grant type: %s", grantType)
	} else {
		h.Log.Debugf("🔍 Token: Left session empty for grant type: %s", grantType)
	}
	// Initialize session claims to prevent nil pointer issues
	if session.Claims == nil {
		session.Claims = &jwt.IDTokenClaims{}
	}
	if session.Claims.Extra == nil {
		session.Claims.Extra = make(map[string]interface{})
	}
	h.Log.Debugf("🔍 Token: Created empty session at address: %p", session)
	h.Log.Debugf("🔍 Token: Session before NewAccessRequest - Subject: '%s'", session.GetSubject())

	// Store attestation information in session claims if attestation was performed
	// Our AuthenticateClient strategy handles this automatically during authentication
	h.storeAttestationInSession(ctx, session)

	// Store issuer_state in session claims if available (for authorization code flow)
	h.storeIssuerStateInSession(r, session)

	// Debug: Log request details before NewAccessRequest
	h.Log.Debugf("🔍 [DEBUG] Request details before NewAccessRequest:")
	h.Log.Debugf("🔍 [DEBUG] Grant Type: %s", grantType)
	h.Log.Debugf("🔍 [DEBUG] Client ID: %s", clientID)
	h.Log.Debugf("🔍 [DEBUG] Session Subject: '%s', Username: '%s'", session.GetSubject(), session.GetUsername())

	accessRequest, err := h.OAuth2Provider.NewAccessRequest(ctx, r, session)
	if err != nil {
		h.Log.Errorf("❌ NewAccessRequest failed: %v", err)
		h.Log.Errorf("❌ Error type: %T", err)
		h.Log.Errorf("❌ Error details: %+v", err)
		if fositeErr, ok := err.(*fosite.RFC6749Error); ok {
			h.Log.Errorf("❌ Fosite error name: %s", fositeErr.ErrorField)
			h.Log.Errorf("❌ Fosite error description: %s", fositeErr.DescriptionField)
			h.Log.Errorf("❌ Fosite error hint: %s", fositeErr.HintField)
		}
		if h.Metrics != nil {
			h.Metrics.RecordTokenRequest(grantType, "unknown", "error")
		}
		h.OAuth2Provider.WriteAccessError(ctx, w, accessRequest, err)
		return
	}

	// For authorization_code flow, grant scopes that were retrieved from the auth code session
	if grantType == "authorization_code" {
		if accessRequest.GetSession() != nil {
			if ds, ok := accessRequest.GetSession().(*openid.DefaultSession); ok {
				if ds.Claims != nil && ds.Claims.Extra != nil {
					if grantedScopes, ok := ds.Claims.Extra["granted_scopes"].([]interface{}); ok {
						var scopeStrings []string
						for _, scope := range grantedScopes {
							if scopeStr, ok := scope.(string); ok {
								accessRequest.GrantScope(scopeStr)
								scopeStrings = append(scopeStrings, scopeStr)
							}
						}
						h.Log.Debugf("✅ Granted scopes for authorization_code from session: %v", scopeStrings)

						// Store granted scopes in the session for persistence
						if session.Claims == nil {
							session.Claims = &jwt.IDTokenClaims{}
						}
						if session.Claims.Extra == nil {
							session.Claims.Extra = make(map[string]interface{})
						}
						session.Claims.Extra["granted_scopes"] = scopeStrings
						h.Log.Debugf("✅ Stored granted scopes in session: %v", scopeStrings)
					}
				}
			}
		}
	}

	// Debug: Check what session data we got back
	h.Log.Debugf("🔍 Token: Session after NewAccessRequest - Subject: '%s', Username: '%s'",
		session.GetSubject(), session.GetUsername())
	if session.Claims != nil {
		h.Log.Debugf("🔍 Token: Session Claims - Subject: '%s', Issuer: '%s'",
			session.Claims.Subject, session.Claims.Issuer)
	}

	// For authorization_code flow, grant scopes that were stored in the session during authorization
	if grantType == "authorization_code" {
		authCode := r.FormValue("code")
		if authCode != "" {
			// Get the authorization code session to retrieve granted scopes
			requester, err := h.Storage.GetAuthorizeCodeSession(ctx, authCode, session)
			if err == nil && requester != nil {
				// Get granted scopes from the session's Extra field
				reqSession := requester.GetSession()
				if defaultSession, ok := reqSession.(*openid.DefaultSession); ok {
					if defaultSession.Claims != nil && defaultSession.Claims.Extra != nil {
						if scopes, ok := defaultSession.Claims.Extra["granted_scopes"].([]interface{}); ok {
							grantedScopes := make([]string, len(scopes))
							for i, s := range scopes {
								if str, ok := s.(string); ok {
									grantedScopes[i] = str
								}
							}
							h.Log.Debugf("🔍 Retrieved granted scopes from auth code session: %v", grantedScopes)
							// Grant the scopes to the access request
							for _, scope := range grantedScopes {
								accessRequest.GrantScope(scope)
							}
							h.Log.Debugf("✅ Granted scopes for authorization_code: %v", grantedScopes)

							// Store granted scopes in the session for persistence
							if session.Claims == nil {
								session.Claims = &jwt.IDTokenClaims{}
							}
							if session.Claims.Extra == nil {
								session.Claims.Extra = make(map[string]interface{})
							}
							session.Claims.Extra["granted_scopes"] = grantedScopes
							h.Log.Debugf("✅ Stored granted scopes in session: %v", grantedScopes)

							// Store for later use
							r = r.WithContext(context.WithValue(r.Context(), "granted_scopes", grantedScopes))
						}
					}
				}
			} else {
				h.Log.Errorf("❌ Failed to get auth code session: %v", err)
			}
		}
	}

	// For client_credentials flow, fosite doesn't automatically grant scopes or audiences
	// We need to set the granted scopes and audiences based on client configuration
	if grantType == "client_credentials" {
		client := accessRequest.GetClient()
		requestedScopes := accessRequest.GetRequestedScopes()
		clientScopes := client.GetScopes()
		requestedAudiences := accessRequest.GetRequestedAudience()
		clientAudiences := client.GetAudience()

		h.Log.Debugf("🔍 Client credentials scope and audience handling - Client: %s, Requested Scopes: %v, Client scopes: %v, Requested Audiences: %v, Client audiences: %v",
			client.GetID(), requestedScopes, clientScopes, requestedAudiences, clientAudiences)

		var grantedScopes []string
		var grantedAudiences []string

		if len(requestedScopes) == 0 {
			// If no scopes requested, grant all client scopes
			grantedScopes = clientScopes
			h.Log.Debugf("🔍 No scopes requested, granting all client scopes: %v", grantedScopes)
		} else {
			// Grant intersection of requested and client scopes
			for _, reqScope := range requestedScopes {
				for _, clientScope := range clientScopes {
					if reqScope == clientScope {
						grantedScopes = append(grantedScopes, reqScope)
						break
					}
				}
			}
			h.Log.Debugf("🔍 Granted intersection of scopes: %v", grantedScopes)
		}

		if len(requestedAudiences) == 0 {
			// If no audiences requested, grant all client audiences
			grantedAudiences = clientAudiences
			h.Log.Debugf("🔍 No audiences requested, granting all client audiences: %v", grantedAudiences)
		} else {
			// Grant intersection of requested and client audiences
			for _, reqAudience := range requestedAudiences {
				for _, clientAudience := range clientAudiences {
					if reqAudience == clientAudience {
						grantedAudiences = append(grantedAudiences, reqAudience)
						break
					}
				}
			}
			h.Log.Debugf("🔍 Granted intersection of audiences: %v", grantedAudiences)
		}

		// Set the granted scopes on the access request
		for _, scope := range grantedScopes {
			accessRequest.GrantScope(scope)
		}

		// Set the granted audiences on the access request
		for _, audience := range grantedAudiences {
			accessRequest.GrantAudience(audience)
		}

		h.Log.Debugf("✅ Set granted scopes for client_credentials: %v", grantedScopes)
		h.Log.Debugf("✅ Set granted audiences for client_credentials: %v", grantedAudiences)

		// Store granted scopes in the session for persistence
		if session.Claims == nil {
			session.Claims = &jwt.IDTokenClaims{}
		}
		if session.Claims.Extra == nil {
			session.Claims.Extra = make(map[string]interface{})
		}
		session.Claims.Extra["granted_scopes"] = grantedScopes
		h.Log.Debugf("✅ Stored granted scopes in session for client_credentials: %v", grantedScopes)
	}

	// Let fosite create the access response
	accessResponse, err := h.OAuth2Provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		h.Log.Errorf("❌ NewAccessResponse failed: %v", err)
		h.Log.Debugf("🔍 Access request details - Client: %s, Grant: %s, Scopes: %v",
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

	h.Log.Debugf("✅ Token request handled successfully by fosite")
}

// storeAttestationInSession stores attestation information in session claims if attestation was performed
func (h *TokenHandler) storeAttestationInSession(ctx context.Context, session *openid.DefaultSession) {
	// Check if attestation was performed and store the result in session claims
	if attestationResult, hasAttestation := attestation.GetAttestationResult(ctx); hasAttestation && attestationResult.Valid {
		h.Log.Debugf("🔍 Storing attestation result in session claims: hasAttestation=%t, valid=%t", hasAttestation, attestationResult.Valid)

		// Initialize claims if nil
		if session.Claims == nil {
			session.Claims = &jwt.IDTokenClaims{}
		}
		if session.Claims.Extra == nil {
			session.Claims.Extra = make(map[string]interface{})
		}

		// Store attestation information in session claims (this gets persisted with the token)
		attestationInfo := map[string]interface{}{
			"attestation_verified":    true,
			"attestation_trust_level": attestationResult.TrustLevel,
			"attestation_issued_at":   attestationResult.IssuedAt.Unix(),
			"attestation_expires_at":  attestationResult.ExpiresAt.Unix(),
		}

		// Extract additional attestation details from claims if available
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

		session.Claims.Extra["attestation"] = attestationInfo
		h.Log.Debugf("✅ Stored attestation info in session claims")
	} else {
		h.Log.Debugf("⚠️ Not storing attestation: hasAttestation=%t, valid=%t", hasAttestation, false)
	}
}

// storeIssuerStateInSession stores issuer_state in session claims if available
func (h *TokenHandler) storeIssuerStateInSession(r *http.Request, session *openid.DefaultSession) {
	// Store issuer_state in session claims if available (for authorization code flow)
	authCode := r.FormValue("code")
	if authCode != "" && h.AuthCodeToStateMap != nil {
		if issuerState, exists := (*h.AuthCodeToStateMap)[authCode]; exists {
			h.Log.Debugf("🔍 Storing issuer_state in session claims: %s", issuerState)

			// Initialize claims if nil
			if session.Claims == nil {
				session.Claims = &jwt.IDTokenClaims{}
			}
			if session.Claims.Extra == nil {
				session.Claims.Extra = make(map[string]interface{})
			}

			session.Claims.Extra["issuer_state"] = issuerState
			h.Log.Debugf("✅ Stored issuer_state in session claims")
			// Clean up the authorization code mapping
			delete(*h.AuthCodeToStateMap, authCode)
		}
	}
}

// handleProxyToken forwards token requests to the upstream token endpoint,
// substituting client credentials to the upstream client and returning the
// upstream response back to the downstream client.
func (h *TokenHandler) handleProxyToken(w http.ResponseWriter, r *http.Request) {
	h.Log.Debugf("🔄 [PROXY] Starting upstream token exchange")

	// Log complete incoming request details
	h.Log.Debugf("📨 [PROXY] Incoming request details:")
	h.Log.Debugf("📨 [PROXY] Method: %s", r.Method)
	h.Log.Debugf("📨 [PROXY] URL: %s", r.URL.String())
	h.Log.Debugf("📨 [PROXY] Host: %s", r.Host)
	h.Log.Debugf("📨 [PROXY] RemoteAddr: %s", r.RemoteAddr)
	h.Log.Debugf("📨 [PROXY] User-Agent: %s", r.Header.Get("User-Agent"))
	h.Log.Debugf("📨 [PROXY] Content-Type: %s", r.Header.Get("Content-Type"))
	h.Log.Debugf("📨 [PROXY] Content-Length: %s", r.Header.Get("Content-Length"))
	h.Log.Debugf("📨 [PROXY] Authorization: %s", r.Header.Get("Authorization"))

	// Log all headers
	h.Log.Debugf("📨 [PROXY] All headers:")
	for name, values := range r.Header {
		for _, value := range values {
			if strings.ToLower(name) == "authorization" {
				h.Log.Debugf("📨 [PROXY] Header: %s = [REDACTED]", name)
			} else {
				h.Log.Debugf("📨 [PROXY] Header: %s = %s", name, value)
			}
		}
	}

	if h.Configuration.UpstreamProvider.Metadata == nil {
		h.Log.Errorf("❌ [PROXY] Upstream provider metadata not configured")
		http.Error(w, "upstream provider not configured", http.StatusBadGateway)
		return
	}

	tokenEndpoint, _ := h.Configuration.UpstreamProvider.Metadata["token_endpoint"].(string)
	if tokenEndpoint == "" {
		h.Log.Errorf("❌ [PROXY] Upstream token_endpoint not available in metadata")
		http.Error(w, "upstream token_endpoint not available", http.StatusBadGateway)
		return
	}

	h.Log.Debugf("🔗 [PROXY] Upstream token endpoint: %s", tokenEndpoint)

	if err := r.ParseForm(); err != nil {
		h.Log.Errorf("❌ [PROXY] Failed to parse form: %v", err)
		http.Error(w, "failed to parse form", http.StatusBadRequest)
		return
	}

	// Log the raw body if available
	if r.Body != nil {
		bodyBytes, err := io.ReadAll(r.Body)
		if err != nil {
			h.Log.Errorf("❌ [PROXY] Failed to read request body: %v", err)
		} else {
			h.Log.Debugf("📨 [PROXY] Raw request body: %s", string(bodyBytes))
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
		h.Log.Errorf("❌ [PROXY] Missing client_id in request")
		http.Error(w, "missing client_id", http.StatusBadRequest)
		return
	}

	h.Log.Debugf("👤 [PROXY] Downstream client ID: %s", clientID)

	// Check if client exists in storage
	if _, err := h.Storage.GetClient(r.Context(), clientID); err != nil {
		h.Log.Errorf("❌ [PROXY] Unknown or unregistered client_id: %s", clientID)
		http.Error(w, "unknown or unregistered client_id", http.StatusBadRequest)
		return
	}

	h.Log.Debugf("✅ [PROXY] Client validation passed for: %s", clientID)

	// Log original request parameters (excluding sensitive data)
	originalParams := make(map[string]string)
	for key, values := range r.Form {
		if key == "client_secret" || key == "password" {
			originalParams[key] = "[REDACTED]"
		} else if len(values) > 0 {
			originalParams[key] = values[0]
		}
	}
	h.Log.Debugf("📋 [PROXY] Original request parameters: %+v", originalParams)

	r.Form.Del("client_assertion")
	r.Form.Del("client_assertion_type")

	// Replace client_id/redirect_uri for upstream
	originalClientID := r.Form.Get("client_id")
	r.Form.Set("client_id", h.Configuration.UpstreamProvider.ClientID)
	r.Form.Set("redirect_uri", h.Configuration.UpstreamProvider.CallbackURL)

	h.Log.Debugf("🔄 [PROXY] Replaced client_id from '%s' to '%s'", originalClientID, h.Configuration.UpstreamProvider.ClientID)
	h.Log.Debugf("🔄 [PROXY] Set redirect_uri to: %s", h.Configuration.UpstreamProvider.CallbackURL)

	formData := r.Form.Encode()
	h.Log.Debugf("📤 [PROXY] Form data to upstream: %s", formData)

	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(formData))
	if err != nil {
		h.Log.Errorf("❌ [PROXY] Failed to create upstream token request: %v", err)
		http.Error(w, "failed to create upstream token request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if h.Configuration.UpstreamProvider.ClientID != "" && h.Configuration.UpstreamProvider.ClientSecret != "" {
		req.SetBasicAuth(h.Configuration.UpstreamProvider.ClientID, h.Configuration.UpstreamProvider.ClientSecret)
		h.Log.Debugf("🔐 [PROXY] Added basic auth for upstream client: %s", h.Configuration.UpstreamProvider.ClientID)
	} else {
		h.Log.Debugf("⚠️ [PROXY] No upstream client credentials configured")
	}

	h.Log.Debugf("🚀 [PROXY] Sending request to upstream token endpoint")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		h.Log.Errorf("❌ [PROXY] Upstream token request failed: %v", err)
		http.Error(w, "upstream token request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	h.Log.Debugf("📥 [PROXY] Upstream response status: %d", resp.StatusCode)
	h.Log.Debugf("📥 [PROXY] Upstream response headers: %+v", resp.Header)

	// Read and log response body for debugging
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		h.Log.Errorf("❌ [PROXY] Failed to read upstream response body: %v", err)
		http.Error(w, "failed to read upstream response", http.StatusInternalServerError)
		return
	}

	h.Log.Debugf("📄 [PROXY] Upstream response body: %s", string(respBody))

	// For attestation-enabled clients, create proxy token (attestation verification happens in Fosite)
	// The attestation strategy will handle verification during NewAccessRequest
	var tokenResponse map[string]interface{}
	if err := json.Unmarshal(respBody, &tokenResponse); err != nil {
		h.Log.Errorf("❌ [PROXY] Failed to parse upstream token response as JSON: %v", err)
		// Continue with raw response
	} else {
		// Extract upstream access token and issue proxy token
		if upstreamAccessToken, ok := tokenResponse["access_token"].(string); ok && upstreamAccessToken != "" {
			h.Log.Debugf("🔄 [PROXY] Received upstream access token, issuing proxy token")

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

			// Store attestation information in proxy session claims if attestation was performed
			h.storeAttestationInSession(r.Context(), proxySession)

			// Store issuer_state in proxy session claims if available
			h.storeIssuerStateInSession(r, proxySession)

			// Get the downstream client for proxy token creation
			downstreamClient, err := h.Storage.GetClient(r.Context(), clientID)
			if err != nil {
				h.Log.Errorf("❌ [PROXY] Failed to get downstream client: %v", err)
				http.Error(w, "failed to get client", http.StatusInternalServerError)
				return
			}

			h.Log.Debugf("🔍 [PROXY] Downstream client found: %t, Public: %t, GrantTypes: %v", downstreamClient != nil, downstreamClient.IsPublic(), downstreamClient.GetGrantTypes())

			// Create proxy token request - attestation verification happens in Fosite strategy
			h.Log.Debugf("🔄 [PROXY] Using simplified proxy token creation (attestation handled by strategy)")
			proxyForm := make(url.Values)
			proxyForm.Set("grant_type", "client_credentials")
			proxyForm.Set("client_id", clientID)
			proxyForm.Set("scope", "openid")

			proxyReq, err := http.NewRequest("POST", "/token", strings.NewReader(proxyForm.Encode()))
			if err != nil {
				h.Log.Errorf("❌ [PROXY] Failed to create proxy request: %v", err)
				http.Error(w, "failed to create proxy request", http.StatusInternalServerError)
				return
			}
			proxyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			proxyReq = proxyReq.WithContext(r.Context())

			// Set proxy context and client for simplified authentication
			proxyCtx := context.WithValue(proxyReq.Context(), clientContextKey, downstreamClient)
			proxyCtx = context.WithValue(proxyCtx, proxyTokenContextKey, true)
			proxyReq = proxyReq.WithContext(proxyCtx)

			h.Log.Debugf("🔄 [PROXY] Creating proxy access request with client_credentials grant")

			// Create proxy access request using Fosite (attestation strategy handles authentication)
			proxyAccessRequest, err := h.OAuth2Provider.NewAccessRequest(proxyReq.Context(), proxyReq, proxySession)
			if err != nil {
				h.Log.Errorf("❌ [PROXY] Failed to create proxy access request: %v", err)
				h.Log.Errorf("❌ [PROXY] Error type: %T", err)
				h.Log.Errorf("❌ [PROXY] Error details: %+v", err)
				if fositeErr, ok := err.(*fosite.RFC6749Error); ok {
					h.Log.Errorf("❌ [PROXY] Fosite error name: %s", fositeErr.ErrorField)
					h.Log.Errorf("❌ [PROXY] Fosite error description: %s", fositeErr.DescriptionField)
					h.Log.Errorf("❌ [PROXY] Fosite error hint: %s", fositeErr.HintField)
				}
				http.Error(w, "failed to create proxy access request", http.StatusInternalServerError)
				return
			}

			// Issue proxy access response using Fosite
			proxyAccessResponse, err := h.OAuth2Provider.NewAccessResponse(proxyReq.Context(), proxyAccessRequest)
			if err != nil {
				h.Log.Errorf("❌ [PROXY] Failed to create proxy access response: %v", err)
				http.Error(w, "failed to create proxy token", http.StatusInternalServerError)
				return
			}

			// Extract the Fosite-generated proxy token
			proxyToken := proxyAccessResponse.GetAccessToken()
			if proxyToken == "" {
				h.Log.Errorf("❌ [PROXY] Failed to extract proxy access token from Fosite response")
				http.Error(w, "failed to extract proxy token", http.StatusInternalServerError)
				return
			}

			h.Log.Debugf("🔄 [PROXY] Fosite generated proxy token: %s... -> upstream: %s...", proxyToken[:20], upstreamAccessToken[:20])

			// Replace upstream token with proxy token in response
			tokenResponse["access_token"] = proxyToken
			tokenResponse["issued_by_proxy"] = true
			tokenResponse["proxy_server"] = "oauth2-server"

			// Re-encode the modified token response
			modifiedRespBody, err := json.Marshal(tokenResponse)
			if err != nil {
				h.Log.Errorf("❌ [PROXY] Failed to encode modified token response: %v", err)
				http.Error(w, "failed to encode proxy token response", http.StatusInternalServerError)
				return
			}

			h.Log.Debugf("✅ [PROXY] Successfully issued Fosite-controlled proxy access token")

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
				h.Log.Errorf("❌ [PROXY] Failed to write proxy token response body to client: %v", err)
			}
			return
		}
	}

	// For non-attestation clients or when proxy token creation fails, return upstream response directly
	h.Log.Debugf("ℹ️ [PROXY] Returning upstream response directly (non-attestation client or proxy creation failed)")
	// Copy response headers and status
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Write response body back to client
	if _, err := w.Write(respBody); err != nil {
		h.Log.Errorf("❌ [PROXY] Failed to write response body to client: %v", err)
	}
}
