package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// handleProxyDeviceCode handles device_code grant type in proxy mode
// This exchanges a downstream device code for tokens from an upstream provider
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

	var deviceCodeMapping DeviceCodeMapping
	if proxyDeviceCode != "" && h.DeviceCodeToUpstreamMap != nil {
		if mapping, exists := (*h.DeviceCodeToUpstreamMap)[proxyDeviceCode]; exists {
			r.Form.Set("device_code", mapping.UpstreamDeviceCode)
			h.Log.Infof("🔄 [PROXY-DEVICE] Successfully mapped proxy device code '%s' to upstream device code '%s'", proxyDeviceCode, mapping.UpstreamDeviceCode)
			// Store the mapping for later use
			deviceCodeMapping = mapping
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

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Do(req)
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
			scope := deviceCodeMapping.Scope
			if scope == "" {
				scope = r.Form.Get("scope") // Fallback
			}
			h.Log.Infof("🔍 [PROXY-DEVICE] Retrieved scope from mapping: '%s', fallback scope: '%s'", deviceCodeMapping.Scope, r.Form.Get("scope"))
			h.createProxyTokensForDeviceCode(w, r, upstreamTokenResp, originalClientID, scope)
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
func (h *TokenHandler) createProxyTokensForDeviceCode(w http.ResponseWriter, r *http.Request, upstreamTokenResp map[string]interface{}, clientID string, scope string) {
	// Extract upstream tokens
	upstreamAccessToken, _ := upstreamTokenResp["access_token"].(string)

	if upstreamAccessToken == "" {
		h.Log.Errorf("❌ [PROXY-DEVICE] No access token in upstream response")
		http.Error(w, "no access token in upstream response", http.StatusBadGateway)
		return
	}

	h.Log.Infof("✅ [PROXY-DEVICE] Successfully received upstream access token (length: %d)", len(upstreamAccessToken))

	// Determine if we should issue refresh token
	issueRefreshToken := strings.Contains(scope, "offline_access")
	h.Log.Infof("🔍 [PROXY-DEVICE] Scope: %s, issueRefreshToken: %t", scope, issueRefreshToken)

	// Get client
	ctx := r.Context()
	client, err := h.Storage.GetClient(ctx, clientID)
	if err != nil {
		h.Log.Errorf("❌ [PROXY-DEVICE] Failed to get client %s: %v", clientID, err)
		http.Error(w, "client not found", http.StatusBadRequest)
		return
	}

	// Create Fosite session for proxy token
	proxySession := &openid.DefaultSession{}
	if proxySession.Claims == nil {
		proxySession.Claims = &jwt.IDTokenClaims{}
	}
	if proxySession.Claims.Extra == nil {
		proxySession.Claims.Extra = make(map[string]interface{})
	}

	// Store upstream token mapping in session
	upstreamTokens := map[string]interface{}{
		"access_token":  upstreamAccessToken,
		"refresh_token": "", // Will be set if available from upstream
		"id_token":      "",
		"expires_in":    3600,
		"scope":         scope,
		"token_type":    "Bearer",
	}
	if rt, ok := upstreamTokenResp["refresh_token"].(string); ok && rt != "" {
		upstreamTokens["refresh_token"] = rt
	}
	proxySession.Claims.Extra["upstream_tokens"] = upstreamTokens

	proxySession.Subject = clientID
	proxySession.Username = clientID

	// Create access request for proxy token generation
	accessRequest := fosite.NewAccessRequest(proxySession)
	// Use the actual scope from device authorization request
	var scopeArgs fosite.Arguments
	if scope != "" {
		scopeArgs = fosite.Arguments(strings.Split(scope, " "))
	} else {
		scopeArgs = fosite.Arguments{"openid", "profile", "email"}
	}
	accessRequest.RequestedScope = scopeArgs
	accessRequest.GrantedScope = scopeArgs
	accessRequest.RequestedAudience = fosite.Arguments{}
	accessRequest.GrantedAudience = fosite.Arguments{}
	accessRequest.Client = client
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

	// Extract refresh token if available from Fosite
	var refreshToken string
	if rt := accessResponse.GetExtra("refresh_token"); rt != nil {
		if rtStr, ok := rt.(string); ok {
			refreshToken = rtStr
			h.Log.Printf("✅ [PROXY-DEVICE] Fosite generated proxy refresh token: %s", refreshToken[:20])
		}
	}

	// If we need a refresh token but Fosite didn't generate one, generate it manually
	if refreshToken == "" && issueRefreshToken {
		// Generate a proper Fosite refresh token
		strategy := h.RefreshTokenStrategy.(oauth2.RefreshTokenStrategy)
		rt, _, err := strategy.GenerateRefreshToken(ctx, accessRequest)
		if err != nil {
			h.Log.Errorf("❌ [PROXY-DEVICE] Failed to generate refresh token: %v", err)
			http.Error(w, "failed to generate refresh token", http.StatusInternalServerError)
			return
		}
		refreshToken = rt
		h.Log.Printf("✅ [PROXY-DEVICE] Manually generated Fosite refresh token: %s", refreshToken[:20])

		// Store the refresh token in Fosite storage
		if refreshStrategy, ok := h.RefreshTokenStrategy.(interface {
			RefreshTokenSignature(context.Context, string) string
		}); ok {
			refreshSignature := refreshStrategy.RefreshTokenSignature(ctx, refreshToken)
			h.Log.Debugf("🔍 [PROXY-DEVICE] Storing refresh token with signature: %s", refreshSignature)
			h.Log.Debugf("🔍 [PROXY-DEVICE] Full refresh token being stored: %s", refreshToken)
			if accessStrategy, ok := h.AccessTokenStrategy.(interface {
				AccessTokenSignature(context.Context, string) string
			}); ok {
				accessSignature := accessStrategy.AccessTokenSignature(ctx, accessToken)
				h.Log.Debugf("🔍 [PROXY-DEVICE] Access token signature: %s", accessSignature)
				err = h.Storage.CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, accessRequest)
				if err != nil {
					h.Log.Errorf("❌ [PROXY-DEVICE] Failed to store refresh token session: %v", err)
				} else {
					h.Log.Printf("✅ [PROXY-DEVICE] Stored refresh token session for signature: %s", refreshSignature)
				}
			} else {
				h.Log.Errorf("❌ [PROXY-DEVICE] AccessTokenStrategy does not have Signature method")
			}
		} else {
			h.Log.Errorf("❌ [PROXY-DEVICE] RefreshTokenStrategy does not have Signature method")
		}
	} else if refreshToken != "" {
		h.Log.Infof("✅ [PROXY-DEVICE] Using Fosite-generated refresh token")
	} else {
		h.Log.Infof("ℹ️ [PROXY-DEVICE] Not issuing refresh token")
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
		h.Log.Printf("✅ [PROXY-DEVICE] Stored proxy access token mapping: %s -> upstream tokens", accessToken[:20])

		// Also store mapping for refresh token if it exists
		if refreshToken != "" {
			(*h.AccessTokenToIssuerStateMap)[refreshToken] = string(mappingJSON)
			h.Log.Printf("✅ [PROXY-DEVICE] Stored proxy refresh token mapping: %s -> upstream tokens", refreshToken[:20])
		}
	}

	// Return proxy tokens to client
	proxyResponse := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        scope,
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
