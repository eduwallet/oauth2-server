package handlers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"oauth2-server/internal/auth"
	"oauth2-server/internal/utils"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// handleProxyTokenExchange handles token_exchange grant type in proxy mode (RFC 8693)
// This exchanges tokens with an upstream provider and creates proxy tokens
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
		upstreamSubjectToken, err := h.getUpstreamTokenFromProxyToken(r.Context(), subjectToken, subjectTokenType)
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

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Do(req)
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

	// If upstream token exchange failed, attempt local proxy handling
	clientID := r.Form.Get("client_id")
	if fallbackTokens := h.recoverUpstreamTokensForProxySubject(r.Context(), subjectToken, subjectTokenType); fallbackTokens != nil {
		h.Log.Infof("ℹ️ [PROXY-TOKEN-EXCHANGE] Upstream exchange failed (status %d); issuing proxy tokens locally using mapped upstream tokens", resp.StatusCode)
		h.createProxyTokensForTokenExchange(w, r, fallbackTokens, clientID)
		return
	}

	// Return upstream response directly for error cases when no fallback is possible
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

// recoverUpstreamTokensForProxySubject attempts to reconstruct upstream tokens for a proxy-issued subject token
// so that we can issue new proxy tokens locally when the upstream provider does not support token exchange.
func (h *TokenHandler) recoverUpstreamTokensForProxySubject(ctx context.Context, proxyToken string, subjectTokenType string) map[string]interface{} {
	if proxyToken == "" {
		return nil
	}

	// Derive signature and signature-part keys for lookups
	sigPart := ""
	if lastDot := strings.LastIndex(proxyToken, "."); lastDot != -1 && lastDot+1 < len(proxyToken) {
		sigPart = proxyToken[lastDot+1:]
	}

	computeSig := func(token string) string {
		switch subjectTokenType {
		case "urn:ietf:params:oauth:token-type:refresh_token":
			if strat, ok := h.RefreshTokenStrategy.(interface {
				RefreshTokenSignature(context.Context, string) string
			}); ok {
				return strat.RefreshTokenSignature(ctx, token)
			}
		case "urn:ietf:params:oauth:token-type:access_token", "":
			if strat, ok := h.AccessTokenStrategy.(interface {
				AccessTokenSignature(context.Context, string) string
			}); ok {
				return strat.AccessTokenSignature(ctx, token)
			}
		}
		return ""
	}

	sig := computeSig(proxyToken)

	extractFromJSON := func(raw string) map[string]interface{} {
		var mapping map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &mapping); err == nil {
			if ut, ok := mapping["upstream_tokens"].(map[string]interface{}); ok {
				return ut
			}
		}
		return nil
	}

	// In-memory map lookups
	if h.AccessTokenToIssuerStateMap != nil {
		if ut := extractFromJSON((*h.AccessTokenToIssuerStateMap)[proxyToken]); ut != nil {
			h.Log.Debugf("🔍 [PROXY-TOKEN-EXCHANGE] Recovered upstream tokens from in-memory map using full token")
			return ut
		}
		if sig != "" {
			if ut := extractFromJSON((*h.AccessTokenToIssuerStateMap)[sig]); ut != nil {
				h.Log.Debugf("🔍 [PROXY-TOKEN-EXCHANGE] Recovered upstream tokens from in-memory map using signature")
				return ut
			}
		}
		if sigPart != "" {
			if ut := extractFromJSON((*h.AccessTokenToIssuerStateMap)[sigPart]); ut != nil {
				h.Log.Debugf("🔍 [PROXY-TOKEN-EXCHANGE] Recovered upstream tokens from in-memory map using signature part")
				return ut
			}
		}
	}

	// Persistent storage lookups
	lookupStorage := func(key string, label string) map[string]interface{} {
		if key == "" {
			return nil
		}
		upAccess, upRefresh, upType, upExp, err := h.Storage.GetUpstreamTokenMapping(ctx, key)
		if err != nil {
			h.Log.Debugf("ℹ️ [PROXY-TOKEN-EXCHANGE] Persistent mapping lookup failed for %s: %v", label, err)
			return nil
		}
		h.Log.Debugf("ℹ️ [PROXY-TOKEN-EXCHANGE] Persistent mapping (%s) returned access=%q refresh=%q type=%q exp=%d", label, upAccess, upRefresh, upType, upExp)
		if upAccess == "" && upRefresh == "" {
			return nil
		}
		if upType == "" {
			upType = "Bearer"
		}
		if upExp == 0 {
			upExp = 3600
		}
		return map[string]interface{}{
			"access_token":  upAccess,
			"refresh_token": upRefresh,
			"token_type":    upType,
			"expires_in":    upExp,
		}
	}

	if ut := lookupStorage(proxyToken, "full token"); ut != nil {
		return ut
	}
	if ut := lookupStorage(sig, "signature"); ut != nil {
		return ut
	}
	if ut := lookupStorage(sigPart, "signature part"); ut != nil {
		return ut
	}

	return nil
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

	// Determine if we should issue refresh token
	requestedTokenType := r.Form.Get("requested_token_type")
	issueRefreshToken := requestedTokenType == "urn:ietf:params:oauth:token-type:refresh_token"

	// For mapping, use upstream refresh_token if available, otherwise use access_token if issuing refresh
	upstreamRefreshTokenForMapping := upstreamRefreshToken
	if upstreamRefreshTokenForMapping == "" && issueRefreshToken {
		upstreamRefreshTokenForMapping = upstreamAccessToken
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
	// For token exchange proxy tokens, set grant type to client_credentials
	// Try to add refresh_token if we need to issue one
	fositeGrantTypes := fosite.Arguments{"client_credentials"}
	if issueRefreshToken {
		fositeGrantTypes = append(fositeGrantTypes, "refresh_token")
	}
	accessRequest.GrantTypes = fositeGrantTypes

	// Create access response using Fosite's normal flow
	accessResponse, err := h.OAuth2Provider.NewAccessResponse(ctx, accessRequest)
	if err != nil && issueRefreshToken {
		// If it failed with refresh_token, try without it
		h.Log.Debugf("⚠️ [PROXY-TOKEN-EXCHANGE] Failed to create access response with refresh_token grant type, trying without: %v", err)
		fositeGrantTypes = fosite.Arguments{"client_credentials"}
		accessRequest.GrantTypes = fositeGrantTypes
		accessResponse, err = h.OAuth2Provider.NewAccessResponse(ctx, accessRequest)
	}
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

	// Extract refresh token if available from Fosite
	var refreshToken string
	if rt := accessResponse.GetExtra("refresh_token"); rt != nil {
		if rtStr, ok := rt.(string); ok {
			refreshToken = rtStr
			h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Generated proxy refresh token: %s", refreshToken[:20])
		}
	}

	// Check if client requested a refresh token
	requestedTokenType = r.Form.Get("requested_token_type")
	issueRefreshToken = requestedTokenType == "urn:ietf:params:oauth:token-type:refresh_token" || upstreamRefreshTokenStr != ""

	// If we need to issue a refresh token but Fosite didn't generate one, create it manually
	if issueRefreshToken && refreshToken == "" {
		// Use Fosite's refresh token strategy to generate a proper refresh token
		if genStrategy, ok := h.RefreshTokenStrategy.(interface {
			Generate(context.Context) (string, string, error)
		}); ok {
			var refreshSignature string
			refreshToken, refreshSignature, err = genStrategy.Generate(ctx)
			if err != nil {
				h.Log.Errorf("❌ [PROXY-TOKEN-EXCHANGE] Failed to generate refresh token: %v", err)
				http.Error(w, "failed to generate refresh token", http.StatusInternalServerError)
				return
			}
			h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Generated proxy refresh token: %s", refreshToken[:20])

			// Store refresh token in Fosite storage
			accessSignature := h.AccessTokenStrategy.(interface {
				AccessTokenSignature(context.Context, string) string
			}).AccessTokenSignature(ctx, accessToken)
			err = h.Storage.CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, accessRequest)
			if err != nil {
				h.Log.Errorf("❌ [PROXY-TOKEN-EXCHANGE] Failed to store refresh token session: %v", err)
			} else {
				h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Stored refresh token session for signature: %s", refreshSignature[:20])
			}
		} else {
			// Fallback to manual generation
			refreshToken, err = utils.GenerateRandomString(32)
			if err != nil {
				h.Log.Errorf("❌ [PROXY-TOKEN-EXCHANGE] Failed to generate refresh token: %v", err)
				http.Error(w, "failed to generate refresh token", http.StatusInternalServerError)
				return
			}

			// Compute signature manually using HMAC-SHA256 with JWTSecret
			mac := hmac.New(sha256.New, []byte(h.Configuration.Security.JWTSecret))
			mac.Write([]byte(refreshToken))
			refreshSignature := base64.URLEncoding.EncodeToString(mac.Sum(nil))

			// Create full refresh token as token.signature
			refreshToken = refreshToken + "." + refreshSignature

			h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Manually generated proxy refresh token: %s", refreshToken[:20])

			// Store refresh token in Fosite storage
			accessSignature := h.AccessTokenStrategy.(interface {
				AccessTokenSignature(context.Context, string) string
			}).AccessTokenSignature(ctx, accessToken)
			err = h.Storage.CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, accessRequest)
			if err != nil {
				h.Log.Errorf("❌ [PROXY-TOKEN-EXCHANGE] Failed to store refresh token session: %v", err)
			} else {
				h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Stored refresh token session for signature: %s", refreshSignature[:20])
			}
		}
	}

	// Prepare ID token if available
	var idToken string
	if upstreamIDToken != "" {
		rewritten, err := h.rewriteUpstreamIDToken(ctx, upstreamIDToken, accessRequest, accessToken, "")
		if err != nil {
			h.Log.Errorf("❌ [PROXY-TOKEN-EXCHANGE] Failed to rewrite upstream id_token: %v", err)
			http.Error(w, "failed to rewrite upstream id_token", http.StatusBadGateway)
			return
		}
		idToken = rewritten
		h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Reissued upstream ID token with local signer")
	} else if it := accessResponse.GetExtra("id_token"); it != nil {
		if itStr, ok := it.(string); ok {
			idToken = itStr
			h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Generated proxy ID token")
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

			// Also store in persistent storage
			err = h.Storage.StoreUpstreamTokenMapping(ctx, accessToken, upstreamAccessToken, upstreamRefreshTokenForMapping, upstreamTokenType, int64(upstreamExpiresIn))
			if err != nil {
				h.Log.Warnf("⚠️ [PROXY-TOKEN-EXCHANGE] Failed to store upstream access token mapping in persistent storage: %v", err)
			} else {
				h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Stored upstream access token mapping in persistent storage for proxy token %s", accessToken[:20])
			}
		}
		// Store mapping for refresh token
		if refreshToken != "" {
			refreshTokenKey := refreshToken
			(*h.AccessTokenToIssuerStateMap)[refreshTokenKey] = string(mappingJSON)
			h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Stored proxy refresh token mapping: %s -> upstream tokens", refreshTokenKey[:20])

			// Also store in persistent storage (full token, signature, and signature-part)
			err = h.Storage.StoreUpstreamTokenMapping(ctx, refreshTokenKey, upstreamAccessToken, upstreamRefreshTokenForMapping, upstreamTokenType, int64(upstreamExpiresIn))
			if err != nil {
				h.Log.Warnf("⚠️ [PROXY-TOKEN-EXCHANGE] Failed to store upstream refresh token mapping in persistent storage: %v", err)
			} else {
				h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Stored upstream refresh token mapping in persistent storage for proxy token %s", refreshTokenKey[:20])
			}

			var refreshSignature string
			if refreshStrategy, ok := h.RefreshTokenStrategy.(interface {
				RefreshTokenSignature(context.Context, string) string
			}); ok {
				refreshSignature = refreshStrategy.RefreshTokenSignature(ctx, refreshTokenKey)
				if err := h.Storage.StoreUpstreamTokenMapping(ctx, refreshSignature, upstreamAccessToken, upstreamRefreshTokenForMapping, upstreamTokenType, int64(upstreamExpiresIn)); err != nil {
					h.Log.Warnf("⚠️ [PROXY-TOKEN-EXCHANGE] Failed to store upstream refresh token mapping (signature) in persistent storage: %v", err)
				} else {
					h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Stored upstream refresh token mapping in persistent storage for signature %s", refreshSignature[:20])
				}
			}

			if lastDot := strings.LastIndex(refreshTokenKey, "."); lastDot != -1 && lastDot+1 < len(refreshTokenKey) {
				sigPart := refreshTokenKey[lastDot+1:]
				if err := h.Storage.StoreUpstreamTokenMapping(ctx, sigPart, upstreamAccessToken, upstreamRefreshTokenForMapping, upstreamTokenType, int64(upstreamExpiresIn)); err != nil {
					h.Log.Warnf("⚠️ [PROXY-TOKEN-EXCHANGE] Failed to store upstream refresh token mapping (sig part) in persistent storage: %v", err)
				} else {
					h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Stored upstream refresh token mapping in persistent storage for sig part %s", sigPart[:20])
				}

				// Also keep in-memory mapping under sig part for quick lookup
				(*h.AccessTokenToIssuerStateMap)[sigPart] = string(mappingJSON)
				h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Stored proxy refresh token mapping under sig part: %s -> upstream tokens", sigPart[:20])
			}
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

	// Set the appropriate token based on requested_token_type
	if requestedTokenType == "urn:ietf:params:oauth:token-type:refresh_token" {
		// For refresh token requests, return the proxy refresh token
		if refreshToken != "" {
			proxyResponse["refresh_token"] = refreshToken
			proxyResponse["issued_token_type"] = "urn:ietf:params:oauth:token-type:refresh_token"
		} else {
			h.Log.Errorf("❌ [PROXY-TOKEN-EXCHANGE] Requested refresh token but none available")
			http.Error(w, "refresh token not available", http.StatusBadRequest)
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
		if idToken != "" {
			proxyResponse["id_token"] = idToken
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
func (h *TokenHandler) getUpstreamTokenFromProxyToken(ctx context.Context, proxyToken string, subjectTokenType string) (string, error) {
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
	upstreamAccessFromStorage, upstreamRefreshFromStorage, _, _, storageErr := h.Storage.GetUpstreamTokenMapping(ctx, proxyToken)
	if storageErr == nil {
		if subjectTokenType == "urn:ietf:params:oauth:token-type:refresh_token" && upstreamRefreshFromStorage != "" {
			h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Found upstream refresh token in persistent storage: %s...", upstreamRefreshFromStorage[:20])
			return upstreamRefreshFromStorage, nil
		} else if upstreamAccessFromStorage != "" {
			h.Log.Printf("✅ [PROXY-TOKEN-EXCHANGE] Found upstream access token in persistent storage: %s...", upstreamAccessFromStorage[:20])
			return upstreamAccessFromStorage, nil
		}
	}
	h.Log.Printf("⚠️ [PROXY-TOKEN-EXCHANGE] No upstream token mapping found in storage (%v), trying session claims", storageErr)

	// Fallback: Use fosite's introspection to validate the proxy token and get session data
	h.Log.Printf("🔍 [PROXY-TOKEN-EXCHANGE] About to call IntrospectToken, provider: %v, proxyToken: %s", h.OAuth2Provider, proxyToken)
	if h.OAuth2Provider == nil {
		h.Log.Errorf("❌ [PROXY-TOKEN-EXCHANGE] OAuth2Provider is nil")
		return proxyToken, fmt.Errorf("OAuth2Provider is nil")
	}
	if proxyToken == "" {
		h.Log.Errorf("❌ [PROXY-TOKEN-EXCHANGE] proxyToken is empty")
		return proxyToken, fmt.Errorf("proxyToken is empty")
	}

	// For token exchange, if we can't find a mapping, assume the proxy token is the upstream token
	// This handles cases where the token was issued by a different proxy instance or the mapping was lost
	h.Log.Printf("ℹ️ [PROXY-TOKEN-EXCHANGE] No upstream token mapping found, using proxy token as upstream token")
	return proxyToken, nil
}
