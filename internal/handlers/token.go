package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"oauth2-server/internal/attestation"
	"oauth2-server/internal/auth"
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
	OAuth2Provider              fosite.OAuth2Provider
	Configuration               *config.Config
	Log                         *logrus.Logger
	Metrics                     *metrics.MetricsCollector
	AttestationManager          *attestation.VerifierManager
	Storage                     store.Storage
	SecretManager               *store.SecretManager
	AuthCodeToStateMap          *map[string]string
	DeviceCodeToUpstreamMap     *map[string]string
	AccessTokenToIssuerStateMap *map[string]string
	AccessTokenStrategy         interface{} // Will be oauth2.AccessTokenStrategy
	RefreshTokenStrategy        interface{} // Will be oauth2.RefreshTokenStrategy
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
	deviceCodeToUpstreamMap *map[string]string,
	accessTokenToIssuerStateMap *map[string]string,
	accessTokenStrategy interface{},
	refreshTokenStrategy interface{},
) *TokenHandler {
	return &TokenHandler{
		OAuth2Provider:              provider,
		Configuration:               config,
		Log:                         logger,
		Metrics:                     metricsCollector,
		AttestationManager:          attestationManager,
		Storage:                     storage,
		SecretManager:               secretManager,
		AuthCodeToStateMap:          authCodeToStateMap,
		DeviceCodeToUpstreamMap:     deviceCodeToUpstreamMap,
		AccessTokenToIssuerStateMap: accessTokenToIssuerStateMap,
		AccessTokenStrategy:         accessTokenStrategy,
		RefreshTokenStrategy:        refreshTokenStrategy,
	}
}

// ServeHTTP implements the http.Handler interface for the token endpoint
func (h *TokenHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.Log.Infof("🔍 [TOKEN] ServeHTTP called with method: %s, path: %s", r.Method, r.URL.Path)
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
	clientID := r.FormValue("client_id")

	h.Log.Infof("🔍 [TOKEN] HandleTokenRequest: grantType='%s', clientID='%s', IsProxyMode=%t", grantType, clientID, h.Configuration.IsProxyMode())

	// Check if proxy mode is enabled and if we should proxy this request
	h.Log.Debugf("🔍 Token: Checking proxy mode: IsProxyMode=%t, grantType='%s'", h.Configuration.IsProxyMode(), grantType)
	if h.Configuration.IsProxyMode() && (grantType == "authorization_code" || grantType == "urn:ietf:params:oauth:grant-type:device_code" || grantType == "urn:ietf:params:oauth:grant-type:token-exchange") {
		h.Log.Infof("🔄 [TOKEN] Entering proxy mode for grant_type: %s", grantType)
		if grantType == "authorization_code" {
			h.handleProxyAuthorizationCode(w, r)
			return
		} else if grantType == "urn:ietf:params:oauth:grant-type:device_code" {
			h.handleProxyDeviceCode(w, r)
			return
		} else if grantType == "urn:ietf:params:oauth:grant-type:token-exchange" {
			h.handleProxyTokenExchange(w, r)
			return
		}
	}

	// If client_id is not in form but we have basic auth, extract it from basic auth
	if r.FormValue("client_id") == "" {
		if username, _, ok := r.BasicAuth(); ok {
			r.Form.Set("client_id", username)
		}
	}

	// Debug logging
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
	h.Log.Printf("🔍 storeIssuerStateInSession called with authCode: %s", authCode)
	if authCode != "" && h.AuthCodeToStateMap != nil {
		h.Log.Printf("🔍 AuthCodeToStateMap has %d entries", len(*h.AuthCodeToStateMap))
		for k, v := range *h.AuthCodeToStateMap {
			h.Log.Printf("🔍 Map entry: %s -> %s", k[:10]+"...", v[:10]+"...")
		}
		if issuerState, exists := (*h.AuthCodeToStateMap)[authCode]; exists {
			h.Log.Printf("🔍 Found issuer_state in map: %s", issuerState)

			// Initialize claims if nil
			if session.Claims == nil {
				session.Claims = &jwt.IDTokenClaims{}
			}
			if session.Claims.Extra == nil {
				session.Claims.Extra = make(map[string]interface{})
			}

			session.Claims.Extra["issuer_state"] = issuerState
			h.Log.Printf("✅ Stored issuer_state in session claims")
			// Clean up the authorization code mapping
			delete(*h.AuthCodeToStateMap, authCode)
		} else {
			h.Log.Printf("⚠️ issuer_state not found in AuthCodeToStateMap for authCode: %s", authCode)
		}
	} else {
		h.Log.Printf("⚠️ No authCode or AuthCodeToStateMap is nil")
	}
}

// handleProxyAuthorizationCode handles authorization_code grant type in proxy mode
func (h *TokenHandler) handleProxyAuthorizationCode(w http.ResponseWriter, r *http.Request) {
	h.Log.Infof("🚀 [PROXY-AUTH-CODE] Starting proxy authorization code token exchange")

	// Get upstream configuration
	upstreamURL := h.Configuration.UpstreamProvider.ProviderURL
	upstreamClientID := h.Configuration.UpstreamProvider.ClientID
	upstreamClientSecret := h.Configuration.UpstreamProvider.ClientSecret

	h.Log.Infof("🔍 [PROXY-AUTH-CODE] Upstream config - URL: '%s', ClientID: '%s', ClientSecret length: %d", upstreamURL, upstreamClientID, len(upstreamClientSecret))

	if upstreamURL == "" || upstreamClientID == "" || upstreamClientSecret == "" {
		h.Log.Errorf("❌ [PROXY-AUTH-CODE] Upstream configuration incomplete")
		http.Error(w, "upstream configuration incomplete", http.StatusInternalServerError)
		return
	}

	// Build upstream token request
	var upstreamTokenURL string
	if h.Configuration.UpstreamProvider.Metadata != nil {
		if tokenEndpoint, ok := h.Configuration.UpstreamProvider.Metadata["token_endpoint"].(string); ok && tokenEndpoint != "" {
			upstreamTokenURL = tokenEndpoint
			h.Log.Debugf("🔍 [PROXY-AUTH-CODE] Using token_endpoint from discovery: %s", upstreamTokenURL)
		}
	}
	if upstreamTokenURL == "" {
		upstreamTokenURL = strings.TrimSuffix(upstreamURL, "/") + "/token"
		h.Log.Debugf("🔍 [PROXY-AUTH-CODE] Using constructed token URL: %s", upstreamTokenURL)
	}

	// Copy the form data
	upstreamForm := make(url.Values)
	for k, v := range r.Form {
		upstreamForm[k] = append([]string(nil), v...) // copy
	}

	// Replace client_id with upstream client_id
	upstreamForm.Set("client_id", upstreamClientID)
	upstreamForm.Set("client_secret", upstreamClientSecret)

	// For authorization_code grant, replace redirect_uri with proxy callback URL
	if grantType := r.Form.Get("grant_type"); grantType == "authorization_code" {
		proxyCallbackURL := h.Configuration.Server.BaseURL + "/callback"
		upstreamForm.Set("redirect_uri", proxyCallbackURL)
		h.Log.Debugf("🔄 [PROXY-AUTH-CODE] Replaced redirect_uri with proxy callback: %s", proxyCallbackURL)
	}

	// Make upstream token request
	h.Log.Debugf("🔄 [PROXY-AUTH-CODE] Making upstream token request to: %s", upstreamTokenURL)
	formData := upstreamForm.Encode()
	req, err := http.NewRequest("POST", upstreamTokenURL, strings.NewReader(formData))
	if err != nil {
		h.Log.Errorf("❌ [PROXY-AUTH-CODE] Failed to create upstream token request: %v", err)
		http.Error(w, "failed to create upstream token request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if upstreamClientID != "" && upstreamClientSecret != "" {
		req.SetBasicAuth(upstreamClientID, upstreamClientSecret)
		h.Log.Debugf("🔐 [PROXY-AUTH-CODE] Added basic auth for upstream client: %s", upstreamClientID)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		h.Log.Errorf("❌ [PROXY-AUTH-CODE] Upstream token request failed: %v", err)
		http.Error(w, "upstream token request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read upstream response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		h.Log.Errorf("❌ [PROXY-AUTH-CODE] Failed to read upstream response: %v", err)
		http.Error(w, "failed to read upstream response", http.StatusInternalServerError)
		return
	}

	h.Log.Debugf("🔄 [PROXY-AUTH-CODE] Upstream response status: %d", resp.StatusCode)

	// For successful responses, create proxy tokens instead of forwarding upstream
	if resp.StatusCode == http.StatusOK {
		var upstreamTokenResp map[string]interface{}
		if err := json.Unmarshal(respBody, &upstreamTokenResp); err != nil {
			h.Log.Errorf("❌ [PROXY-AUTH-CODE] Failed to parse upstream token response: %v", err)
			http.Error(w, "failed to parse upstream response", http.StatusInternalServerError)
			return
		}

		if upstreamAccessToken, ok := upstreamTokenResp["access_token"].(string); ok && upstreamAccessToken != "" {
			h.Log.Infof("✅ [PROXY-AUTH-CODE] Successfully received upstream access token (length: %d)", len(upstreamAccessToken))
			h.Log.Debugf("🔍 [PROXY-AUTH-CODE] Upstream token response: %+v", upstreamTokenResp)

			// Store upstream tokens for later use (refresh, etc.)
			upstreamTokens := map[string]interface{}{
				"access_token":  upstreamTokenResp["access_token"],
				"refresh_token": upstreamTokenResp["refresh_token"],
				"id_token":      upstreamTokenResp["id_token"],
				"token_type":    upstreamTokenResp["token_type"],
				"expires_in":    upstreamTokenResp["expires_in"],
				"scope":         upstreamTokenResp["scope"],
			}

			// Get client information
			clientID := r.Form.Get("client_id")
			h.Log.Debugf("🔍 [PROXY-AUTH-CODE] Using client_id: %s", clientID)

			// Create Fosite session
			ctx := r.Context()
			client, err := h.Storage.GetClient(ctx, clientID)
			if err != nil {
				h.Log.Errorf("❌ [PROXY-AUTH-CODE] Failed to get client %s: %v", clientID, err)
				http.Error(w, "client not found", http.StatusBadRequest)
				return
			}
			h.Log.Debugf("✅ [PROXY-AUTH-CODE] Found client: %s (public: %t)", client.GetID(), client.IsPublic())

			// For proxy token creation, ensure client_credentials is in grant types
			grantTypes := client.GetGrantTypes()
			hasClientCredentials := false
			for _, gt := range grantTypes {
				if gt == "client_credentials" {
					hasClientCredentials = true
					break
				}
			}
			if !hasClientCredentials {
				// Create a wrapper client with client_credentials added
				client = &auth.GrantTypeWrapper{
					Client:          client,
					ExtraGrantTypes: []string{"client_credentials"},
				}
				h.Log.Debugf("🔄 [PROXY-AUTH-CODE] Wrapped client with client_credentials grant type")
			}
			// For public clients, wrap to make them appear confidential for proxy tokens
			if client.IsPublic() {
				client = &auth.PublicClientWrapper{
					Client: client,
				}
				h.Log.Debugf("🔄 [PROXY-AUTH-CODE] Wrapped public client to appear confidential")
			}

			// Create Fosite session
			session := &openid.DefaultSession{}
			if session.Claims == nil {
				session.Claims = &jwt.IDTokenClaims{}
			}
			if session.Claims.Extra == nil {
				session.Claims.Extra = make(map[string]interface{})
			}

			// Set session subject to client_id for proxy tokens
			session.Subject = clientID
			session.Username = clientID

			// Extract upstream tokens for scope determination
			upstreamRefreshToken := ""
			if rt, ok := upstreamTokenResp["refresh_token"].(string); ok && rt != "" {
				upstreamRefreshToken = rt
			}

			// Create Fosite session for proxy token
			proxySession := &openid.DefaultSession{}
			if proxySession.Claims == nil {
				proxySession.Claims = &jwt.IDTokenClaims{}
			}
			if proxySession.Claims.Extra == nil {
				proxySession.Claims.Extra = make(map[string]interface{})
			}
			proxySession.Claims.Extra["upstream_tokens"] = upstreamTokens
			proxySession.Subject = clientID
			proxySession.Username = clientID

			// Store issuer_state in proxy session if available
			h.storeIssuerStateInSession(r, proxySession)

			// Create access request for proxy token generation
			// Set proxy token context for auth strategy
			ctx = context.WithValue(ctx, proxyTokenContextKey, true)

			h.Log.Debugf("🔍 [PROXY-AUTH-CODE] Creating proxy access request with client: %s, public: %v, grant_types: %v",
				client.GetID(), client.IsPublic(), client.GetGrantTypes())

			accessRequest := fosite.NewAccessRequest(proxySession)
			accessRequest.RequestedScope = fosite.Arguments{"openid", "profile", "email"}
			accessRequest.GrantedScope = fosite.Arguments{"openid", "profile", "email"}
			if upstreamRefreshToken != "" {
				accessRequest.GrantedScope = append(accessRequest.GrantedScope, "offline_access")
			}
			accessRequest.RequestedAudience = fosite.Arguments{}
			accessRequest.GrantedAudience = fosite.Arguments{}
			accessRequest.Client = client
			// Set grant type to client_credentials for proxy tokens (since auth strategy adds this)
			accessRequest.GrantTypes = fosite.Arguments{"client_credentials"}

			h.Log.Debugf("🔍 [PROXY-AUTH-CODE] Access request - client: %s, public: %v, grant_types: %v, requested_scopes: %v",
				accessRequest.GetClient().GetID(), accessRequest.GetClient().IsPublic(),
				accessRequest.GetClient().GetGrantTypes(), accessRequest.GetRequestedScopes())

			// Create access response using Fosite's normal flow
			accessResponse, err := h.OAuth2Provider.NewAccessResponse(ctx, accessRequest)
			if err != nil {
				h.Log.Errorf("❌ [PROXY-AUTH-CODE] Failed to create proxy access response: %v", err)
				http.Error(w, "failed to create proxy access response", http.StatusInternalServerError)
				return
			}

			// Extract the generated proxy tokens
			accessToken := accessResponse.GetAccessToken()
			if accessToken == "" {
				h.Log.Errorf("❌ [PROXY-AUTH-CODE] Failed to extract proxy access token from response")
				http.Error(w, "failed to extract access token", http.StatusInternalServerError)
				return
			}
			h.Log.Printf("✅ [PROXY-AUTH-CODE] Generated proxy access token: %s", accessToken[:20])

			// Extract refresh token if available
			var refreshToken string
			if rt := accessResponse.GetExtra("refresh_token"); rt != nil {
				if rtStr, ok := rt.(string); ok {
					refreshToken = rtStr
					h.Log.Printf("✅ [PROXY-AUTH-CODE] Generated proxy refresh token: %s", refreshToken[:20])
				}
			}

			// Extract ID token if available
			var idToken string
			if it := accessResponse.GetExtra("id_token"); it != nil {
				if itStr, ok := it.(string); ok {
					idToken = itStr
					h.Log.Printf("✅ [PROXY-AUTH-CODE] Generated proxy ID token: %s", idToken[:20])
				}
			}

			// Store mapping from proxy tokens to upstream tokens
			if h.AccessTokenToIssuerStateMap == nil {
				h.AccessTokenToIssuerStateMap = &map[string]string{}
			}

			mapping := map[string]interface{}{
				"client_id":       clientID,
				"upstream_tokens": upstreamTokens,
			}

			// Include issuer_state if available in the session
			if proxySession.Claims != nil && proxySession.Claims.Extra != nil {
				if issuerState, ok := proxySession.Claims.Extra["issuer_state"].(string); ok {
					mapping["issuer_state"] = issuerState
					h.Log.Printf("✅ [PROXY-AUTH-CODE] Included issuer_state in mapping: %s", issuerState)
				}
			}

			mappingJSON, err := json.Marshal(mapping)
			if err != nil {
				h.Log.Errorf("❌ [PROXY-AUTH-CODE] Failed to marshal token mapping: %v", err)
			} else {
				(*h.AccessTokenToIssuerStateMap)[accessToken] = string(mappingJSON)
				h.Log.Printf("✅ [PROXY-AUTH-CODE] Stored proxy token mapping: %s -> upstream tokens", accessToken[:20])
			}

			// Return proxy tokens to client
			proxyResponse := map[string]interface{}{
				"access_token": accessToken,
				"token_type":   "Bearer",
				"expires_in":   3600, // Use proxy token expiry
				"scope":        accessResponse.GetExtra("scope"),
			}

			if refreshToken != "" {
				proxyResponse["refresh_token"] = refreshToken
			}

			if idToken != "" {
				proxyResponse["id_token"] = idToken
			}

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")

			if err := json.NewEncoder(w).Encode(proxyResponse); err != nil {
				h.Log.Errorf("❌ [PROXY-AUTH-CODE] Failed to encode proxy response: %v", err)
			}

			h.Log.Infof("✅ [PROXY-AUTH-CODE] Successfully created proxy tokens for client %s", clientID)
			return
		}
	}

	// For non-successful upstream responses, return error
	h.Log.Errorf("❌ [PROXY-AUTH-CODE] Upstream token request failed with status: %d", resp.StatusCode)
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// handleProxyDeviceCode handles device_code grant type in proxy mode
func (h *TokenHandler) handleProxyDeviceCode(w http.ResponseWriter, r *http.Request) {
	// Get upstream configuration
	upstreamURL := h.Configuration.UpstreamProvider.ProviderURL
	upstreamClientID := h.Configuration.UpstreamProvider.ClientID
	upstreamClientSecret := h.Configuration.UpstreamProvider.ClientSecret

	if upstreamURL == "" || upstreamClientID == "" || upstreamClientSecret == "" {
		h.Log.Errorf("❌ [PROXY-DEVICE] Upstream configuration incomplete")
		http.Error(w, "upstream configuration incomplete", http.StatusInternalServerError)
		return
	}

	// Build upstream token request
	var tokenEndpoint string
	if h.Configuration.UpstreamProvider.Metadata != nil {
		if te, ok := h.Configuration.UpstreamProvider.Metadata["token_endpoint"].(string); ok && te != "" {
			tokenEndpoint = te
			h.Log.Debugf("🔍 [PROXY-DEVICE] Using token_endpoint from discovery: %s", tokenEndpoint)
		}
	}
	if tokenEndpoint == "" {
		tokenEndpoint = strings.TrimSuffix(upstreamURL, "/") + "/token"
		h.Log.Debugf("🔍 [PROXY-DEVICE] Using constructed token URL: %s", tokenEndpoint)
	}

	proxyDeviceCode := r.Form.Get("device_code")
	h.Log.Debugf("🔍 [PROXY-DEVICE] Received proxy device code: %s", proxyDeviceCode)

	if proxyDeviceCode != "" && h.DeviceCodeToUpstreamMap != nil {
		if upstreamDeviceCode, exists := (*h.DeviceCodeToUpstreamMap)[proxyDeviceCode]; exists {
			r.Form.Set("device_code", upstreamDeviceCode)
			h.Log.Infof("🔄 [PROXY-DEVICE] Successfully mapped proxy device code '%s' to upstream device code '%s'", proxyDeviceCode, upstreamDeviceCode)
		} else {
			h.Log.Errorf("❌ [PROXY-DEVICE] No upstream mapping found for proxy device code: %s", proxyDeviceCode)
			h.Log.Debugf("🔍 [PROXY-DEVICE] Available mappings: %+v", *h.DeviceCodeToUpstreamMap)
			http.Error(w, "invalid device code", http.StatusBadRequest)
			return
		}
	}

	// Store original client_id before replacing for upstream
	originalClientID := r.Form.Get("client_id")

	// Replace client_id for upstream
	r.Form.Set("client_id", h.Configuration.UpstreamProvider.ClientID)
	h.Log.Debugf("🔄 [PROXY-DEVICE] Replaced client_id from '%s' to '%s'", originalClientID, h.Configuration.UpstreamProvider.ClientID)

	formData := r.Form.Encode()
	h.Log.Debugf("📤 [PROXY-DEVICE] Form data to upstream: %s", formData)

	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(formData))
	if err != nil {
		h.Log.Errorf("❌ [PROXY-DEVICE] Failed to create upstream token request: %v", err)
		http.Error(w, "failed to create upstream token request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if upstreamClientID != "" && upstreamClientSecret != "" {
		req.SetBasicAuth(upstreamClientID, upstreamClientSecret)
		h.Log.Debugf("🔐 [PROXY-DEVICE] Added basic auth for upstream client: %s", upstreamClientID)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		h.Log.Errorf("❌ [PROXY-DEVICE] Upstream device code token request failed: %v", err)
		http.Error(w, "upstream token request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	h.Log.Infof("📥 [PROXY-DEVICE] Upstream device code response status: %d", resp.StatusCode)

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		h.Log.Errorf("❌ [PROXY-DEVICE] Failed to read upstream device code response: %v", err)
		http.Error(w, "failed to read upstream response", http.StatusInternalServerError)
		return
	}

	h.Log.Debugf("📄 [PROXY-DEVICE] Upstream device code response body: %s", string(respBody))

	// Parse and process token details if successful
	if resp.StatusCode == http.StatusOK {
		var upstreamTokenResp map[string]interface{}
		if err := json.Unmarshal(respBody, &upstreamTokenResp); err == nil {
			h.createProxyTokensForDeviceCode(w, r, upstreamTokenResp, originalClientID)
			return
		}
	}

	// Return upstream response directly for error cases
	h.Log.Debugf("ℹ️ [PROXY-DEVICE] Returning upstream error response directly")
	// Copy response headers and status (excluding Content-Length to avoid mismatch)
	for k, vv := range resp.Header {
		if strings.ToLower(k) == "content-length" {
			continue // Skip Content-Length to let HTTP library calculate it
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Write response body back to client
	if _, err := w.Write(respBody); err != nil {
		h.Log.Errorf("❌ [PROXY-DEVICE] Failed to write response body to client: %v", err)
	}
}

// createProxyTokensForDeviceCode creates proxy tokens for device code flow
func (h *TokenHandler) createProxyTokensForDeviceCode(w http.ResponseWriter, r *http.Request, upstreamTokenResp map[string]interface{}, clientID string) {
	// Extract upstream tokens
	upstreamAccessToken, _ := upstreamTokenResp["access_token"].(string)
	upstreamRefreshToken, _ := upstreamTokenResp["refresh_token"].(string)
	upstreamIDToken, _ := upstreamTokenResp["id_token"].(string)
	upstreamExpiresIn, _ := upstreamTokenResp["expires_in"].(float64)
	upstreamScope, _ := upstreamTokenResp["scope"].(string)
	upstreamTokenType, _ := upstreamTokenResp["token_type"].(string)

	if upstreamAccessToken == "" {
		h.Log.Errorf("❌ [PROXY-DEVICE] No access token in upstream response")
		http.Error(w, "no access token in upstream response", http.StatusBadGateway)
		return
	}

	h.Log.Infof("✅ [PROXY-DEVICE] Successfully received upstream access token (length: %d)", len(upstreamAccessToken))

	// Store upstream token mapping
	upstreamTokens := map[string]interface{}{
		"access_token":  upstreamAccessToken,
		"refresh_token": upstreamRefreshToken,
		"id_token":      upstreamIDToken,
		"expires_in":    upstreamExpiresIn,
		"scope":         upstreamScope,
		"token_type":    upstreamTokenType,
	}

	// Get client
	ctx := r.Context()
	client, err := h.Storage.GetClient(ctx, clientID)
	if err != nil {
		h.Log.Errorf("❌ [PROXY-DEVICE] Failed to get client %s: %v", clientID, err)
		http.Error(w, "client not found", http.StatusBadRequest)
		return
	}

	// For proxy token creation, ensure client_credentials is in grant types
	grantTypes := client.GetGrantTypes()
	hasClientCredentials := false
	for _, gt := range grantTypes {
		if gt == "client_credentials" {
			hasClientCredentials = true
			break
		}
	}
	if !hasClientCredentials {
		// Create a wrapper client with client_credentials added
		client = &auth.GrantTypeWrapper{
			Client:          client,
			ExtraGrantTypes: []string{"client_credentials"},
		}
		h.Log.Debugf("🔄 [PROXY-DEVICE] Wrapped client with client_credentials grant type")
	}
	// For public clients, wrap to make them appear confidential for proxy tokens
	if client.IsPublic() {
		client = &auth.PublicClientWrapper{
			Client: client,
		}
		h.Log.Debugf("🔄 [PROXY-DEVICE] Wrapped public client to appear confidential")
	}

	// Extract upstream tokens for scope determination
	upstreamRefreshTokenStr := ""
	if rt, ok := upstreamTokenResp["refresh_token"].(string); ok && rt != "" {
		upstreamRefreshTokenStr = rt
	}

	// Create Fosite session for proxy token
	proxySession := &openid.DefaultSession{}
	if proxySession.Claims == nil {
		proxySession.Claims = &jwt.IDTokenClaims{}
	}
	if proxySession.Claims.Extra == nil {
		proxySession.Claims.Extra = make(map[string]interface{})
	}
	proxySession.Claims.Extra["upstream_tokens"] = upstreamTokens
	proxySession.Subject = clientID
	proxySession.Username = clientID

	// Create access request for proxy token generation
	// Set proxy token context for auth strategy
	ctx = context.WithValue(ctx, proxyTokenContextKey, true)

	accessRequest := fosite.NewAccessRequest(proxySession)
	accessRequest.RequestedScope = fosite.Arguments{"openid", "profile", "email"}
	accessRequest.GrantedScope = fosite.Arguments{"openid", "profile", "email"}
	if upstreamRefreshTokenStr != "" {
		accessRequest.GrantedScope = append(accessRequest.GrantedScope, "offline_access")
	}
	accessRequest.RequestedAudience = fosite.Arguments{}
	accessRequest.GrantedAudience = fosite.Arguments{}
	accessRequest.Client = client
	// Set grant type to client_credentials for proxy tokens
	accessRequest.GrantTypes = fosite.Arguments{"client_credentials"}

	// Create access response using Fosite's normal flow
	accessResponse, err := h.OAuth2Provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		h.Log.Errorf("❌ [PROXY-DEVICE] Failed to create proxy access response: %v", err)
		http.Error(w, "failed to create proxy access response", http.StatusInternalServerError)
		return
	}

	// Extract the generated proxy tokens
	accessToken := accessResponse.GetAccessToken()
	if accessToken == "" {
		h.Log.Errorf("❌ [PROXY-DEVICE] Failed to extract proxy access token from response")
		http.Error(w, "failed to extract access token", http.StatusInternalServerError)
		return
	}
	h.Log.Printf("✅ [PROXY-DEVICE] Generated proxy access token: %s", accessToken[:20])

	// Extract refresh token if available
	var refreshToken string
	if rt := accessResponse.GetExtra("refresh_token"); rt != nil {
		if rtStr, ok := rt.(string); ok {
			refreshToken = rtStr
			h.Log.Printf("✅ [PROXY-DEVICE] Generated proxy refresh token: %s", refreshToken[:20])
		}
	}

	// Store mapping from proxy tokens to upstream tokens
	if h.AccessTokenToIssuerStateMap == nil {
		h.AccessTokenToIssuerStateMap = &map[string]string{}
	}

	mapping := map[string]interface{}{
		"client_id":       clientID,
		"upstream_tokens": upstreamTokens,
	}

	mappingJSON, err := json.Marshal(mapping)
	if err != nil {
		h.Log.Errorf("❌ [PROXY-DEVICE] Failed to marshal token mapping: %v", err)
	} else {
		(*h.AccessTokenToIssuerStateMap)[accessToken] = string(mappingJSON)
		h.Log.Printf("✅ [PROXY-DEVICE] Stored proxy token mapping: %s -> upstream tokens", accessToken[:20])
	}

	// Return proxy tokens to client
	proxyResponse := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600, // Use proxy token expiry
		"scope":        accessResponse.GetExtra("scope"),
	}

	if refreshToken != "" {
		proxyResponse["refresh_token"] = refreshToken
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if err := json.NewEncoder(w).Encode(proxyResponse); err != nil {
		h.Log.Errorf("❌ [PROXY-DEVICE] Failed to encode proxy response: %v", err)
	}

	h.Log.Infof("✅ [PROXY-DEVICE] Successfully created proxy tokens for client %s", clientID)
}

// handleProxyTokenExchange handles token_exchange grant type in proxy mode
func (h *TokenHandler) handleProxyTokenExchange(w http.ResponseWriter, r *http.Request) {
	// Get upstream configuration
	upstreamURL := h.Configuration.UpstreamProvider.ProviderURL
	upstreamClientID := h.Configuration.UpstreamProvider.ClientID
	upstreamClientSecret := h.Configuration.UpstreamProvider.ClientSecret

	if upstreamURL == "" || upstreamClientID == "" || upstreamClientSecret == "" {
		h.Log.Errorf("❌ [PROXY-TOKEN-EXCHANGE] Upstream configuration incomplete")
		http.Error(w, "upstream configuration incomplete", http.StatusInternalServerError)
		return
	}

	// Build upstream token request
	var upstreamTokenURL string
	if h.Configuration.UpstreamProvider.Metadata != nil {
		if tokenEndpoint, ok := h.Configuration.UpstreamProvider.Metadata["token_endpoint"].(string); ok && tokenEndpoint != "" {
			upstreamTokenURL = tokenEndpoint
			h.Log.Debugf("🔍 [PROXY-TOKEN-EXCHANGE] Using token_endpoint from discovery: %s", upstreamTokenURL)
		}
	}
	if upstreamTokenURL == "" {
		upstreamTokenURL = strings.TrimSuffix(upstreamURL, "/") + "/token"
		h.Log.Debugf("🔍 [PROXY-TOKEN-EXCHANGE] Using constructed token URL: %s", upstreamTokenURL)
	}

	// Copy the form data
	upstreamForm := make(url.Values)
	for k, v := range r.Form {
		upstreamForm[k] = append([]string(nil), v...) // copy
	}

	// For token exchange, we may need to map the subject_token if it's a proxy token
	subjectToken := r.Form.Get("subject_token")
	subjectTokenType := r.Form.Get("subject_token_type")
	if subjectToken != "" {
		// Check if this is a proxy token that needs mapping back to upstream
		upstreamSubjectToken, err := h.getUpstreamTokenFromProxyToken(subjectToken, subjectTokenType)
		if err != nil {
			h.Log.Errorf("❌ [PROXY-TOKEN-EXCHANGE] Failed to translate proxy subject token: %v", err)
			http.Error(w, "failed to translate proxy subject token", http.StatusInternalServerError)
			return
		}
		if upstreamSubjectToken != subjectToken {
			h.Log.Debugf("🔄 [PROXY-TOKEN-EXCHANGE] Translated proxy subject token to upstream token")
			upstreamForm.Set("subject_token", upstreamSubjectToken)
		} else {
			h.Log.Debugf("🔍 [PROXY-TOKEN-EXCHANGE] Subject token is already an upstream token")
		}
	}

	// Replace client_id with upstream client_id
	upstreamForm.Set("client_id", upstreamClientID)
	upstreamForm.Set("client_secret", upstreamClientSecret)

	// Make upstream token request
	h.Log.Debugf("🔄 [PROXY-TOKEN-EXCHANGE] Making upstream token exchange request to: %s", upstreamTokenURL)
	formData := upstreamForm.Encode()
	req, err := http.NewRequest("POST", upstreamTokenURL, strings.NewReader(formData))
	if err != nil {
		h.Log.Errorf("❌ [PROXY-TOKEN-EXCHANGE] Failed to create upstream token exchange request: %v", err)
		http.Error(w, "failed to create upstream token exchange request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if upstreamClientID != "" && upstreamClientSecret != "" {
		req.SetBasicAuth(upstreamClientID, upstreamClientSecret)
		h.Log.Debugf("🔐 [PROXY-TOKEN-EXCHANGE] Added basic auth for upstream client: %s", upstreamClientID)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		h.Log.Errorf("❌ [PROXY-TOKEN-EXCHANGE] Upstream token exchange request failed: %v", err)
		http.Error(w, "upstream token exchange request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read upstream response
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		h.Log.Errorf("❌ [PROXY-TOKEN-EXCHANGE] Failed to read upstream response: %v", err)
		http.Error(w, "failed to read upstream response", http.StatusInternalServerError)
		return
	}

	h.Log.Debugf("🔄 [PROXY-TOKEN-EXCHANGE] Upstream response status: %d", resp.StatusCode)

	// For successful responses, create proxy tokens
	if resp.StatusCode == http.StatusOK {
		var upstreamTokenResp map[string]interface{}
		if err := json.Unmarshal(respBody, &upstreamTokenResp); err == nil {
			clientID := r.Form.Get("client_id")
			h.createProxyTokensForTokenExchange(w, r, upstreamTokenResp, clientID)
			return
		}
	}

	// Return upstream response directly for error cases
	h.Log.Debugf("ℹ️ [PROXY-TOKEN-EXCHANGE] Returning upstream error response directly")
	// Copy response headers and status (excluding Content-Length to avoid mismatch)
	for k, vv := range resp.Header {
		if strings.ToLower(k) == "content-length" {
			continue // Skip Content-Length to let HTTP library calculate it
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Write response body back to client
	if _, err := w.Write(respBody); err != nil {
		h.Log.Errorf("❌ [PROXY-TOKEN-EXCHANGE] Failed to write response body to client: %v", err)
	}
}

// createProxyTokensForTokenExchange creates proxy tokens for token exchange flow
func (h *TokenHandler) createProxyTokensForTokenExchange(w http.ResponseWriter, r *http.Request, upstreamTokenResp map[string]interface{}, clientID string) {
	// Extract upstream tokens
	upstreamAccessToken, _ := upstreamTokenResp["access_token"].(string)
	upstreamRefreshToken, _ := upstreamTokenResp["refresh_token"].(string)
	upstreamIDToken, _ := upstreamTokenResp["id_token"].(string)
	upstreamExpiresIn, _ := upstreamTokenResp["expires_in"].(float64)
	upstreamScope, _ := upstreamTokenResp["scope"].(string)
	upstreamTokenType, _ := upstreamTokenResp["token_type"].(string)
	upstreamIssuedTokenType, _ := upstreamTokenResp["issued_token_type"].(string)

	// Check if we have at least one token to proxy
	if upstreamAccessToken == "" && upstreamRefreshToken == "" {
		h.Log.Errorf("❌ [PROXY-TOKEN-EXCHANGE] No access token or refresh token in upstream response")
		http.Error(w, "no token in upstream response", http.StatusBadGateway)
		return
	}

	// For refresh token responses, we still need to create a proxy access token to hold the mapping
	if upstreamAccessToken == "" && upstreamRefreshToken != "" {
		h.Log.Infof("✅ [PROXY-TOKEN-EXCHANGE] Upstream returned only refresh token, will create proxy access token to represent it")
	}

	if upstreamAccessToken != "" {
		h.Log.Infof("✅ [PROXY-TOKEN-EXCHANGE] Successfully received upstream access token (length: %d)", len(upstreamAccessToken))
	}
	if upstreamRefreshToken != "" {
		h.Log.Infof("✅ [PROXY-TOKEN-EXCHANGE] Successfully received upstream refresh token (length: %d)", len(upstreamRefreshToken))
	}

	// Store upstream token mapping
	upstreamTokens := map[string]interface{}{
		"access_token":      upstreamAccessToken,
		"refresh_token":     upstreamRefreshToken,
		"id_token":          upstreamIDToken,
		"expires_in":        upstreamExpiresIn,
		"scope":             upstreamScope,
		"token_type":        upstreamTokenType,
		"issued_token_type": upstreamIssuedTokenType,
	}

	// Get client
	ctx := r.Context()
	client, err := h.Storage.GetClient(ctx, clientID)
	if err != nil {
		h.Log.Errorf("❌ [PROXY-TOKEN-EXCHANGE] Failed to get client %s: %v", clientID, err)
		http.Error(w, "client not found", http.StatusBadRequest)
		return
	}

	// For proxy token creation, ensure client_credentials is in grant types
	grantTypes := client.GetGrantTypes()
	hasClientCredentials := false
	for _, gt := range grantTypes {
		if gt == "client_credentials" {
			hasClientCredentials = true
			break
		}
	}
	if !hasClientCredentials {
		// Create a wrapper client with client_credentials added
		client = &auth.GrantTypeWrapper{
			Client:          client,
			ExtraGrantTypes: []string{"client_credentials"},
		}
		h.Log.Debugf("🔄 [PROXY-TOKEN-EXCHANGE] Wrapped client with client_credentials grant type")
	}
	// For public clients, wrap to make them appear confidential for proxy tokens
	if client.IsPublic() {
		client = &auth.PublicClientWrapper{
			Client: client,
		}
		h.Log.Debugf("🔄 [PROXY-TOKEN-EXCHANGE] Wrapped public client to appear confidential")
	}

	// Extract upstream tokens for scope determination
	upstreamRefreshTokenStr := ""
	if rt, ok := upstreamTokenResp["refresh_token"].(string); ok && rt != "" {
		upstreamRefreshTokenStr = rt
	}

	// Create Fosite session for proxy token
	proxySession := &openid.DefaultSession{}
	if proxySession.Claims == nil {
		proxySession.Claims = &jwt.IDTokenClaims{}
	}
	if proxySession.Claims.Extra == nil {
		proxySession.Claims.Extra = make(map[string]interface{})
	}
	proxySession.Claims.Extra["upstream_tokens"] = upstreamTokens
	proxySession.Subject = clientID
	proxySession.Username = clientID

	// Create access request for proxy token generation
	// Set proxy token context for auth strategy
	ctx = context.WithValue(ctx, proxyTokenContextKey, true)

	accessRequest := fosite.NewAccessRequest(proxySession)
	accessRequest.RequestedScope = fosite.Arguments{"openid", "profile", "email"}
	accessRequest.GrantedScope = fosite.Arguments{"openid", "profile", "email"}
	if upstreamRefreshTokenStr != "" {
		accessRequest.GrantedScope = append(accessRequest.GrantedScope, "offline_access")
	}
	accessRequest.RequestedAudience = fosite.Arguments{}
	accessRequest.GrantedAudience = fosite.Arguments{}
	accessRequest.Client = client
	// Set grant type to client_credentials for proxy tokens
	accessRequest.GrantTypes = fosite.Arguments{"client_credentials"}

	// Create access response using Fosite's normal flow
	accessResponse, err := h.OAuth2Provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		h.Log.Errorf("❌ [PROXY-TOKEN-EXCHANGE] Failed to create proxy access response: %v", err)
		http.Error(w, "failed to create proxy access response", http.StatusInternalServerError)
		return
	}

	// Extract the generated proxy tokens
	accessToken := accessResponse.GetAccessToken()
	if accessToken == "" {
		h.Log.Errorf("❌ [PROXY-TOKEN-EXCHANGE] Failed to extract proxy access token from response")
		http.Error(w, "failed to extract access token", http.StatusInternalServerError)
		return
	}
	h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Generated proxy access token: %s", accessToken[:20])

	// Extract refresh token if available
	var refreshToken string
	if rt := accessResponse.GetExtra("refresh_token"); rt != nil {
		if rtStr, ok := rt.(string); ok {
			refreshToken = rtStr
			h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Generated proxy refresh token: %s", refreshToken[:20])
		}
	}

	// Store mapping from proxy tokens to upstream tokens
	if h.AccessTokenToIssuerStateMap == nil {
		h.AccessTokenToIssuerStateMap = &map[string]string{}
	}

	mapping := map[string]interface{}{
		"client_id":       clientID,
		"upstream_tokens": upstreamTokens,
	}

	mappingJSON, err := json.Marshal(mapping)
	if err != nil {
		h.Log.Errorf("❌ [PROXY-TOKEN-EXCHANGE] Failed to marshal token mapping: %v", err)
	} else {
		// Store mapping for access token
		if accessToken != "" {
			(*h.AccessTokenToIssuerStateMap)[accessToken] = string(mappingJSON)
			h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Stored proxy access token mapping: %s -> upstream tokens", accessToken[:20])
		}
		// Store mapping for refresh token
		if refreshToken != "" {
			(*h.AccessTokenToIssuerStateMap)[refreshToken] = string(mappingJSON)
			h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Stored proxy refresh token mapping: %s -> upstream tokens", refreshToken[:20])
		}
	}

	// Return proxy tokens to client based on issued_token_type
	proxyResponse := map[string]interface{}{
		"token_type":      "Bearer",
		"expires_in":      3600, // Use proxy token expiry
		"scope":           accessResponse.GetExtra("scope"),
		"proxy_processed": true,
		"proxy_server":    "oauth2-server",
	}

	// Set the appropriate token based on issued_token_type
	if upstreamIssuedTokenType == "urn:ietf:params:oauth:token-type:refresh_token" {
		// For refresh token requests, return the proxy access token as a refresh token
		if accessToken != "" {
			proxyResponse["refresh_token"] = accessToken // Use access token as refresh token
			proxyResponse["issued_token_type"] = "urn:ietf:params:oauth:token-type:refresh_token"
		} else {
			h.Log.Errorf("❌ [PROXY-TOKEN-EXCHANGE] Expected proxy access token but none generated")
			http.Error(w, "failed to generate proxy token", http.StatusInternalServerError)
			return
		}
	} else {
		// Return access token (default behavior)
		if accessToken != "" {
			proxyResponse["access_token"] = accessToken
			proxyResponse["issued_token_type"] = "urn:ietf:params:oauth:token-type:access_token"
		}
		if refreshToken != "" {
			proxyResponse["refresh_token"] = refreshToken
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if err := json.NewEncoder(w).Encode(proxyResponse); err != nil {
		h.Log.Errorf("❌ [PROXY-TOKEN-EXCHANGE] Failed to encode proxy response: %v", err)
	}

	h.Log.Infof("✅ [PROXY-TOKEN-EXCHANGE] Successfully created proxy tokens for client %s", clientID)
}

// getUpstreamTokenFromProxyToken translates a proxy token to its upstream equivalent
func (h *TokenHandler) getUpstreamTokenFromProxyToken(proxyToken string, subjectTokenType string) (string, error) {
	h.Log.Printf("🔄 [PROXY-TOKEN-EXCHANGE] Translating proxy token to upstream token (type: %s)", subjectTokenType)

	// First, try to get upstream token mapping from AccessTokenToIssuerStateMap
	if h.AccessTokenToIssuerStateMap != nil {
		if mappingJSON, exists := (*h.AccessTokenToIssuerStateMap)[proxyToken]; exists {
			h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Found mapping in AccessTokenToIssuerStateMap")
			var mapping map[string]interface{}
			if err := json.Unmarshal([]byte(mappingJSON), &mapping); err != nil {
				h.Log.Printf("⚠️ [PROXY-TOKEN-EXCHANGE] Failed to unmarshal mapping JSON: %v", err)
			} else {
				if upstreamTokens, ok := mapping["upstream_tokens"].(map[string]interface{}); ok {
					// Return the appropriate upstream token based on subject_token_type
					var upstreamToken string
					var tokenType string

					if subjectTokenType == "urn:ietf:params:oauth:token-type:refresh_token" {
						if refreshToken, ok := upstreamTokens["refresh_token"].(string); ok && refreshToken != "" {
							upstreamToken = refreshToken
							tokenType = "refresh_token"
						}
					} else {
						// Default to access_token
						if accessToken, ok := upstreamTokens["access_token"].(string); ok && accessToken != "" {
							upstreamToken = accessToken
							tokenType = "access_token"
						}
					}

					if upstreamToken != "" {
						previewLen := len(upstreamToken)
						if previewLen > 20 {
							previewLen = 20
						}
						h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Found upstream %s in AccessTokenToIssuerStateMap: %s...", tokenType, upstreamToken[:previewLen])
						return upstreamToken, nil
					}
				}
			}
		}
	}

	// Fallback: Try persistent storage
	upstreamAccessToken, _, _, _, err := h.Storage.GetUpstreamTokenMapping(nil, proxyToken)
	if err == nil && upstreamAccessToken != "" {
		h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Found upstream token in persistent storage: %s...", upstreamAccessToken[:20])
		return upstreamAccessToken, nil
	}
	h.Log.Printf("⚠️ [PROXY-TOKEN-EXCHANGE] No upstream token mapping found in storage (%v), trying session claims", err)

	// Fallback: Use fosite's introspection to validate the proxy token and get session data
	ctx := context.Background()
	_, requester, err := h.OAuth2Provider.IntrospectToken(ctx, proxyToken, fosite.AccessToken, &openid.DefaultSession{})
	if err != nil {
		h.Log.Printf("⚠️ [PROXY-TOKEN-EXCHANGE] Token introspection failed (%v), assuming direct upstream token (device flow)", err)
		// For device flow, the token itself is the upstream token
		return proxyToken, nil
	}
	h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Token introspection successful")

	// Try to extract upstream token from session claims
	if requester != nil {
		if session, ok := requester.GetSession().(*openid.DefaultSession); ok {
			if session.Claims != nil && session.Claims.Extra != nil {
				if upstreamTokens, ok := session.Claims.Extra["upstream_tokens"].(map[string]interface{}); ok {
					// Return the appropriate upstream token based on subject_token_type
					var upstreamToken string
					var tokenType string

					if subjectTokenType == "urn:ietf:params:oauth:token-type:refresh_token" {
						if refreshToken, ok := upstreamTokens["refresh_token"].(string); ok && refreshToken != "" {
							upstreamToken = refreshToken
							tokenType = "refresh_token"
						}
					} else {
						// Default to access_token
						if accessToken, ok := upstreamTokens["access_token"].(string); ok && accessToken != "" {
							upstreamToken = accessToken
							tokenType = "access_token"
						}
					}

					if upstreamToken != "" {
						h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Found upstream %s in session claims: %s...", tokenType, upstreamToken[:20])
						return upstreamToken, nil
					}
				}
			}
		}
	}

	h.Log.Printf("⚠️ [PROXY-TOKEN-EXCHANGE] Could not find upstream token mapping, using proxy token as-is")
	return proxyToken, nil
}
