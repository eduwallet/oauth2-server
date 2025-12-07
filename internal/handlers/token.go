package handlers

import (
	"net/http"
	"oauth2-server/internal/attestation"
	"oauth2-server/internal/metrics"
	"oauth2-server/internal/store"
	"oauth2-server/pkg/config"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/handler/rfc8693"
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
	DeviceCodeToUpstreamMap     *map[string]DeviceCodeMapping
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
	deviceCodeToUpstreamMap *map[string]DeviceCodeMapping,
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
	defer func() {
		if err := recover(); err != nil {
			h.Log.Errorf("❌ [TOKEN] Panic in ServeHTTP: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}()
	h.Log.Infof("🔍 [TOKEN] ServeHTTP called with method: %s, path: %s", r.Method, r.URL.Path)
	h.HandleTokenRequest(w, r)
}

// HandleTokenRequest processes OAuth2 token requests using pure fosite
func (h *TokenHandler) HandleTokenRequest(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if err := recover(); err != nil {
			h.Log.Errorf("❌ [TOKEN] Panic in HandleTokenRequest: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}()
	h.Log.Infof("🔍 [TOKEN] HandleTokenRequest called - REQUEST RECEIVED")
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.Log.Errorf("❌ Failed to parse form: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	h.Log.Debugf("🔍 [TOKEN] Form parsed successfully, form values: %v", r.Form)

	grantType := r.FormValue("grant_type")
	h.Log.Infof("🔍 [TOKEN] Extracted grant_type: '%s'", grantType)
	h.Log.Infof("🔍 [TOKEN] Processing grant_type: %s, IsProxyMode: %t", grantType, h.Configuration.IsProxyMode())

	// If client_id is not in form but we have basic auth, extract it from basic auth
	if r.FormValue("client_id") == "" {
		if username, _, ok := r.BasicAuth(); ok {
			r.Form.Set("client_id", username)
		}
	}

	clientID := r.FormValue("client_id")

	h.Log.Infof("🔍 [TOKEN] HandleTokenRequest: grantType='%s', clientID='%s', IsProxyMode=%t", grantType, clientID, h.Configuration.IsProxyMode())

	// Check if proxy mode is enabled and if we should proxy this request
	// Token exchange is handled by our proxy path so we can fall back when the upstream does not support RFC 8693.
	h.Log.Debugf("🔍 Token: Checking proxy mode: IsProxyMode=%t, grantType='%s'", h.Configuration.IsProxyMode(), grantType)
	if h.Configuration.IsProxyMode() && (grantType == "authorization_code" || grantType == "urn:ietf:params:oauth:grant-type:device_code" || grantType == "refresh_token" || grantType == "urn:ietf:params:oauth:grant-type:token-exchange") {
		h.Log.Infof("🔄 [TOKEN] Entering proxy mode for grant_type: %s", grantType)
		if grantType == "authorization_code" {
			h.handleProxyAuthorizationCode(w, r)
			return
		} else if grantType == "urn:ietf:params:oauth:grant-type:device_code" {
			h.handleProxyDeviceCode(w, r)
			return
		} else if grantType == "refresh_token" {
			h.handleProxyRefreshToken(w, r)
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
	// Choose session type per grant to satisfy handler expectations (token exchange requires its own session type)
	var session fosite.Session
	var oidcSession *openid.DefaultSession
	h.Log.Debugf("🔍 Token: Grant type check - grantType='%s', is_auth_code=%t, is_device_code=%t", grantType, grantType == "authorization_code", grantType == "urn:ietf:params:oauth:grant-type:device_code")
	if grantType == "urn:ietf:params:oauth:grant-type:token-exchange" {
		// RFC 8693 handler sets the concrete session later; initialize maps to avoid nil deref inside handler
		session = &rfc8693.TokenExchangeSession{
			ExpiresAt: make(map[fosite.TokenType]time.Time),
			Extra:     make(map[string]interface{}),
		}
		h.Log.Debugf("🔍 Token: Using TokenExchangeSession for token exchange grant")
	} else {
		oidcSession = &openid.DefaultSession{}
		if grantType == "refresh_token" {
			oidcSession.Subject = clientID
			oidcSession.Username = clientID
			h.Log.Debugf("🔍 Token: Set session to client_id for grant type: %s", grantType)
		} else {
			h.Log.Debugf("🔍 Token: Left session empty for grant type: %s", grantType)
		}
		// Initialize session claims to prevent nil pointer issues
		if oidcSession.Claims == nil {
			oidcSession.Claims = &jwt.IDTokenClaims{}
		}
		if oidcSession.Claims.Extra == nil {
			oidcSession.Claims.Extra = make(map[string]interface{})
		}
		h.Log.Debugf("🔍 Token: Created empty session at address: %p", oidcSession)
		h.Log.Debugf("🔍 Token: Session before NewAccessRequest - Subject: '%s'", oidcSession.GetSubject())

		// Store attestation information in session claims if attestation was performed
		// Our AuthenticateClient strategy handles this automatically during authentication
		h.storeAttestationInSession(ctx, oidcSession)

		// Store issuer_state in session claims if available (for authorization code flow)
		h.storeIssuerStateInSession(r, oidcSession)

		session = oidcSession
	}

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

						// Store granted scopes in the session for persistence (only for OIDC sessions)
						if oidcSession != nil {
							if oidcSession.Claims == nil {
								oidcSession.Claims = &jwt.IDTokenClaims{}
							}
							if oidcSession.Claims.Extra == nil {
								oidcSession.Claims.Extra = make(map[string]interface{})
							}
							oidcSession.Claims.Extra["granted_scopes"] = scopeStrings
							h.Log.Debugf("✅ Stored granted scopes in session: %v", scopeStrings)
						}
					}
				}
			}
		}
	}

	// Debug: Check what session data we got back
	h.Log.Debugf("🔍 Token: Session after NewAccessRequest - Subject: '%s', Username: '%s'",
		session.GetSubject(), session.GetUsername())
	if ds, ok := session.(*openid.DefaultSession); ok && ds.Claims != nil {
		h.Log.Debugf("🔍 Token: Session Claims - Subject: '%s', Issuer: '%s'",
			ds.Claims.Subject, ds.Claims.Issuer)
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
							if oidcSession != nil {
								if oidcSession.Claims == nil {
									oidcSession.Claims = &jwt.IDTokenClaims{}
								}
								if oidcSession.Claims.Extra == nil {
									oidcSession.Claims.Extra = make(map[string]interface{})
								}
								oidcSession.Claims.Extra["granted_scopes"] = grantedScopes
								h.Log.Debugf("✅ Stored granted scopes in session: %v", grantedScopes)
							}
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
		if oidcSession != nil {
			if oidcSession.Claims == nil {
				oidcSession.Claims = &jwt.IDTokenClaims{}
			}
			if oidcSession.Claims.Extra == nil {
				oidcSession.Claims.Extra = make(map[string]interface{})
			}
			oidcSession.Claims.Extra["granted_scopes"] = grantedScopes
			h.Log.Debugf("✅ Stored granted scopes in session for client_credentials: %v", grantedScopes)
		}
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
