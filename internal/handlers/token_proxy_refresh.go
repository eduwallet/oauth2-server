package handlers

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// handleProxyRefreshToken handles refresh_token grant type in proxy mode
// This exchanges a downstream refresh token for new tokens from an upstream provider
func (h *TokenHandler) handleProxyRefreshToken(w http.ResponseWriter, r *http.Request) {
	h.Log.Infof("🔍 [PROXY-REFRESH] handleProxyRefreshToken called - REQUEST STARTED")
	h.Log.Infof("🔍 [PROXY-REFRESH] handleProxyRefreshToken called, RefreshTokenStrategy type: %T", h.RefreshTokenStrategy)

	// Get the refresh token from the request
	proxyRefreshToken := r.Form.Get("refresh_token")
	if proxyRefreshToken == "" {
		h.Log.Errorf("❌ [PROXY-REFRESH] No refresh token provided")
		http.Error(w, "refresh_token required", http.StatusBadRequest)
		return
	}

	h.Log.Debugf("🔍 [PROXY-REFRESH] Received proxy refresh token: %s", proxyRefreshToken[:20])

	// Get upstream configuration
	upstreamURL := h.Configuration.UpstreamProvider.ProviderURL
	upstreamClientID := h.Configuration.UpstreamProvider.ClientID
	upstreamClientSecret := h.Configuration.UpstreamProvider.ClientSecret

	if upstreamURL == "" || upstreamClientID == "" || upstreamClientSecret == "" {
		h.Log.Errorf("❌ [PROXY-REFRESH] Upstream configuration incomplete")
		http.Error(w, "upstream configuration incomplete", http.StatusInternalServerError)
		return
	}

	// Compute the refresh token signature
	ctx := r.Context()
	refreshStrategy, ok := h.RefreshTokenStrategy.(interface {
		RefreshTokenSignature(context.Context, string) string
	})
	if !ok {
		h.Log.Errorf("❌ [PROXY-REFRESH] RefreshTokenStrategy does NOT implement RefreshTokenSignature interface, type: %T", h.RefreshTokenStrategy)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}

	refreshSignature := refreshStrategy.RefreshTokenSignature(ctx, proxyRefreshToken)
	h.Log.Debugf("🔍 [PROXY-REFRESH] Computed refresh signature: %s", refreshSignature)
	h.Log.Debugf("🔍 [PROXY-REFRESH] Full refresh token: %s", proxyRefreshToken)

	// Get the refresh token session
	h.Log.Debugf("🔍 [PROXY-REFRESH] Attempting to get refresh token session for signature: %s", refreshSignature)
	refreshSession, err := h.Storage.GetRefreshTokenSession(ctx, refreshSignature, nil)
	if err != nil {
		h.Log.Errorf("❌ [PROXY-REFRESH] Failed to get refresh token session: %v", err)
		h.Log.Errorf("❌ [PROXY-REFRESH] This means the refresh token was never stored or the signature is wrong")
		h.Log.Errorf("❌ [PROXY-REFRESH] Refresh token: %s", proxyRefreshToken)
		h.Log.Errorf("❌ [PROXY-REFRESH] Computed signature: %s", refreshSignature)
		// Let's also check what refresh tokens are actually stored
		h.Log.Errorf("❌ [PROXY-REFRESH] Checking if storage has any refresh tokens...")
		// This is a debug check - in production we'd remove this
		http.Error(w, "invalid refresh token", http.StatusBadRequest)
		return
	}

	h.Log.Debugf("✅ [PROXY-REFRESH] Found refresh token session")

	// Extract upstream tokens from refresh session claims
	var upstreamTokens map[string]interface{}
	if session := refreshSession.GetSession(); session != nil {
		if ds, ok := session.(*openid.DefaultSession); ok {
			if ds.Claims != nil && ds.Claims.Extra != nil {
				if ut, ok := ds.Claims.Extra["upstream_tokens"].(map[string]interface{}); ok {
					upstreamTokens = ut
				}
			}
		}
	}

	if upstreamTokens == nil {
		h.Log.Errorf("❌ [PROXY-REFRESH] No upstream tokens in session")
		http.Error(w, "invalid refresh token", http.StatusBadRequest)
		return
	}

	upstreamRefreshToken, _ := upstreamTokens["refresh_token"].(string)
	if upstreamRefreshToken == "" {
		h.Log.Errorf("❌ [PROXY-REFRESH] No upstream refresh token in session")
		http.Error(w, "invalid refresh token", http.StatusBadRequest)
		return
	}

	h.Log.Debugf("✅ [PROXY-REFRESH] Found upstream refresh token: %s", upstreamRefreshToken[:20])

	// Build upstream token request
	var tokenEndpoint string
	if h.Configuration.UpstreamProvider.Metadata != nil {
		if te, ok := h.Configuration.UpstreamProvider.Metadata["token_endpoint"].(string); ok && te != "" {
			tokenEndpoint = te
		}
	}
	if tokenEndpoint == "" {
		tokenEndpoint = strings.TrimSuffix(upstreamURL, "/") + "/token"
	}

	// Create upstream request
	upstreamForm := url.Values{}
	upstreamForm.Set("grant_type", "refresh_token")
	upstreamForm.Set("refresh_token", upstreamRefreshToken)
	upstreamForm.Set("client_id", upstreamClientID)
	upstreamForm.Set("client_secret", upstreamClientSecret)

	req, err := http.NewRequest("POST", tokenEndpoint, strings.NewReader(upstreamForm.Encode()))
	if err != nil {
		h.Log.Errorf("❌ [PROXY-REFRESH] Failed to create upstream request: %v", err)
		http.Error(w, "failed to create upstream request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Do(req)
	if err != nil {
		h.Log.Errorf("❌ [PROXY-REFRESH] Upstream refresh request failed: %v", err)
		http.Error(w, "upstream refresh request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	h.Log.Infof("📥 [PROXY-REFRESH] Upstream refresh response status: %d", resp.StatusCode)

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		h.Log.Errorf("❌ [PROXY-REFRESH] Failed to read upstream response: %v", err)
		http.Error(w, "failed to read upstream response", http.StatusInternalServerError)
		return
	}

	if resp.StatusCode != http.StatusOK {
		h.Log.Errorf("❌ [PROXY-REFRESH] Upstream refresh failed with status %d: %s", resp.StatusCode, string(respBody))
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
		return
	}

	var upstreamTokenResp map[string]interface{}
	if err := json.Unmarshal(respBody, &upstreamTokenResp); err != nil {
		h.Log.Errorf("❌ [PROXY-REFRESH] Failed to parse upstream response: %v", err)
		http.Error(w, "failed to parse upstream response", http.StatusInternalServerError)
		return
	}

	h.Log.Debugf("📄 [PROXY-REFRESH] Upstream refresh response: %s", string(respBody))

	// Get client
	clientID := r.Form.Get("client_id")
	fositeClient, err := h.Storage.GetClient(ctx, clientID)
	if err != nil {
		h.Log.Errorf("❌ [PROXY-REFRESH] Failed to get client %s: %v", clientID, err)
		http.Error(w, "client not found", http.StatusBadRequest)
		return
	}

	// Create new proxy tokens from upstream response
	h.createProxyTokensForRefresh(w, r, upstreamTokenResp, clientID, fositeClient)
}

// createProxyTokensForRefresh creates proxy tokens for refresh token flow
func (h *TokenHandler) createProxyTokensForRefresh(w http.ResponseWriter, r *http.Request, upstreamTokenResp map[string]interface{}, clientID string, client fosite.Client) {
	ctx := r.Context()
	// Extract upstream tokens
	upstreamAccessToken, _ := upstreamTokenResp["access_token"].(string)

	if upstreamAccessToken == "" {
		h.Log.Errorf("❌ [PROXY-REFRESH] No access token in upstream response")
		http.Error(w, "no access token in upstream response", http.StatusBadGateway)
		return
	}

	h.Log.Infof("✅ [PROXY-REFRESH] Successfully received upstream access token (length: %d)", len(upstreamAccessToken))

	// Determine if we should issue refresh token
	issueRefreshToken := true // For refresh, always issue new refresh token if upstream provided

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
		"refresh_token": "", // Will be set if generated
		"id_token":      "",
		"expires_in":    3600,
		"scope":         upstreamTokenResp["scope"],
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
	var scopeArgs fosite.Arguments
	if scope, ok := upstreamTokenResp["scope"].(string); ok && scope != "" {
		scopeArgs = fosite.Arguments(strings.Split(scope, " "))
	} else {
		scopeArgs = fosite.Arguments{"openid", "profile", "email"}
	}
	accessRequest.RequestedScope = scopeArgs
	accessRequest.GrantedScope = scopeArgs
	accessRequest.RequestedAudience = fosite.Arguments{}
	accessRequest.GrantedAudience = fosite.Arguments{}
	accessRequest.Client = client
	accessRequest.GrantTypes = fosite.Arguments{"refresh_token"}

	// Create access response using Fosite's normal flow
	accessResponse, err := h.OAuth2Provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		h.Log.Errorf("❌ [PROXY-REFRESH] Failed to create proxy access response: %v", err)
		http.Error(w, "failed to create proxy access response", http.StatusInternalServerError)
		return
	}

	// Extract the generated proxy tokens
	accessToken := accessResponse.GetAccessToken()
	if accessToken == "" {
		h.Log.Errorf("❌ [PROXY-REFRESH] Failed to extract proxy access token from response")
		http.Error(w, "failed to extract access token", http.StatusInternalServerError)
		return
	}
	h.Log.Printf("✅ [PROXY-REFRESH] Generated proxy access token: %s", accessToken[:20])

	// Extract refresh token if available from Fosite
	var refreshToken string
	if rt := accessResponse.GetExtra("refresh_token"); rt != nil {
		if rtStr, ok := rt.(string); ok {
			refreshToken = rtStr
			h.Log.Printf("✅ [PROXY-REFRESH] Fosite generated proxy refresh token: %s", refreshToken[:20])
		}
	}

	// If we need a refresh token but Fosite didn't generate one, generate it manually
	if refreshToken == "" && issueRefreshToken {
		// Generate a proper Fosite refresh token
		if rts, ok := h.RefreshTokenStrategy.(oauth2.RefreshTokenStrategy); ok {
			rt, _, err := rts.GenerateRefreshToken(ctx, accessRequest)
			if err != nil {
				h.Log.Errorf("❌ [PROXY-REFRESH] Failed to generate refresh token: %v", err)
				http.Error(w, "failed to generate refresh token", http.StatusInternalServerError)
				return
			}
			refreshToken = rt
			h.Log.Printf("✅ [PROXY-REFRESH] Manually generated Fosite refresh token: %s", refreshToken[:20])
		} else {
			h.Log.Errorf("❌ [PROXY-REFRESH] RefreshTokenStrategy does not implement oauth2.RefreshTokenStrategy")
			http.Error(w, "invalid refresh token strategy", http.StatusInternalServerError)
			return
		}

		// Store the refresh token in Fosite storage
		if refreshStrategy, ok := h.RefreshTokenStrategy.(interface {
			RefreshTokenSignature(context.Context, string) string
		}); ok {
			refreshSignature := refreshStrategy.RefreshTokenSignature(ctx, refreshToken)
			if accessStrategy, ok := h.AccessTokenStrategy.(interface {
				AccessTokenSignature(context.Context, string) string
			}); ok {
				accessSignature := accessStrategy.AccessTokenSignature(ctx, accessToken)
				err = h.Storage.CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, accessRequest)
				if err != nil {
					h.Log.Errorf("❌ [PROXY-REFRESH] Failed to store refresh token session: %v", err)
				} else {
					h.Log.Printf("✅ [PROXY-REFRESH] Stored refresh token session for signature: %s", refreshSignature[:20])
				}
			} else {
				h.Log.Errorf("❌ [PROXY-REFRESH] AccessTokenStrategy does not have Signature method")
			}
		} else {
			h.Log.Errorf("❌ [PROXY-REFRESH] RefreshTokenStrategy does not have Signature method")
		}
	} else if refreshToken != "" {
		h.Log.Infof("✅ [PROXY-REFRESH] Using Fosite-generated refresh token")
	} else {
		h.Log.Infof("ℹ️ [PROXY-REFRESH] Not issuing refresh token")
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
		h.Log.Errorf("❌ [PROXY-REFRESH] Failed to marshal token mapping: %v", err)
	} else {
		// Store mapping for access token
		(*h.AccessTokenToIssuerStateMap)[accessToken] = string(mappingJSON)
		h.Log.Printf("✅ [PROXY-REFRESH] Stored proxy access token mapping: %s -> upstream tokens", accessToken[:20])

		// Store mapping for refresh token if available
		if refreshToken != "" {
			(*h.AccessTokenToIssuerStateMap)[refreshToken] = string(mappingJSON)
			h.Log.Printf("✅ [PROXY-REFRESH] Stored proxy refresh token mapping: %s -> upstream tokens", refreshToken[:20])
		}
	}

	// Return proxy tokens to client
	proxyResponse := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        upstreamTokenResp["scope"],
	}

	if refreshToken != "" {
		proxyResponse["refresh_token"] = refreshToken
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	if err := json.NewEncoder(w).Encode(proxyResponse); err != nil {
		h.Log.Errorf("❌ [PROXY-REFRESH] Failed to encode proxy response: %v", err)
	}

	h.Log.Infof("✅ [PROXY-REFRESH] Successfully created proxy tokens for client %s", clientID)
}
