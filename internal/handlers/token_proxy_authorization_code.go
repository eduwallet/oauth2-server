package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"oauth2-server/internal/auth"
	"oauth2-server/internal/utils"
	"strings"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// handleProxyAuthorizationCode handles authorization_code grant type in proxy mode
// This exchanges a downstream authorization code for tokens from an upstream provider
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
		proxyCallbackURL := h.Configuration.PublicBaseURL + "/callback"
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

	httpClient := &http.Client{Timeout: 30 * time.Second}
	resp, err := httpClient.Do(req)
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
	if resp.StatusCode != http.StatusOK {
		h.Log.Errorf("❌ [PROXY-AUTH-CODE] Upstream token request failed with status: %d", resp.StatusCode)
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
		return
	}

	var upstreamTokenResp map[string]interface{}
	if err := json.Unmarshal(respBody, &upstreamTokenResp); err != nil {
		h.Log.Errorf("❌ [PROXY-AUTH-CODE] Failed to parse upstream token response: %v", err)
		http.Error(w, "failed to parse upstream response", http.StatusInternalServerError)
		return
	}

	upstreamAccessToken, ok := upstreamTokenResp["access_token"].(string)
	if !ok || upstreamAccessToken == "" {
		h.Log.Errorf("❌ [PROXY-AUTH-CODE] No access token in upstream response")
		http.Error(w, "no access token in upstream response", http.StatusBadGateway)
		return
	}

	h.Log.Infof("✅ [PROXY-AUTH-CODE] Successfully received upstream access token (length: %d)", len(upstreamAccessToken))
	h.Log.Debugf("🔍 [PROXY-AUTH-CODE] Upstream token response: %+v", upstreamTokenResp)

	// Extract upstream tokens
	upstreamRefreshToken := ""
	if rt, ok := upstreamTokenResp["refresh_token"].(string); ok && rt != "" {
		upstreamRefreshToken = rt
	}
	upstreamIDToken, _ := upstreamTokenResp["id_token"].(string)

	// Store upstream tokens for later use (refresh, etc.)
	upstreamTokens := map[string]interface{}{
		"access_token":  upstreamAccessToken,
		"refresh_token": upstreamRefreshToken,
		"id_token":      upstreamIDToken,
		"token_type":    upstreamTokenResp["token_type"],
		"expires_in":    upstreamTokenResp["expires_in"],
		"scope":         upstreamTokenResp["scope"],
	}

	// Determine if we should issue refresh token
	issueRefreshToken := upstreamRefreshToken != ""
	h.Log.Infof("🔍 [PROXY-AUTH-CODE] Upstream refresh token present: %t, issueRefreshToken: %t", upstreamRefreshToken != "", issueRefreshToken)

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

	// Manually create access request for client_credentials flow
	accessRequest := fosite.NewAccessRequest(proxySession)
	accessRequest.RequestedScope = fosite.Arguments{"openid", "profile", "email"}
	accessRequest.GrantedScope = fosite.Arguments{"openid", "profile", "email"}
	if upstreamRefreshToken != "" {
		accessRequest.GrantedScope = append(accessRequest.GrantedScope, "offline_access")
	}
	accessRequest.RequestedAudience = fosite.Arguments{}
	accessRequest.GrantedAudience = fosite.Arguments{}
	accessRequest.Client = client
	accessRequest.GrantTypes = fosite.Arguments{"client_credentials"}

	h.Log.Debugf("🔍 [PROXY-AUTH-CODE] Manually created access request - Client: %s, GrantTypes: %v, GrantedScopes: %v",
		accessRequest.GetClient().GetID(), accessRequest.GetGrantTypes(), accessRequest.GetGrantedScopes())

	// Create access response using Fosite's normal flow
	h.Log.Debugf("🔍 [PROXY-AUTH-CODE] About to call NewAccessResponse")
	accessResponse, err := h.OAuth2Provider.NewAccessResponse(ctx, accessRequest)
	h.Log.Debugf("🔍 [PROXY-AUTH-CODE] NewAccessResponse returned, err=%v", err)

	if err != nil {
		h.Log.Errorf("❌ [PROXY-AUTH-CODE] Failed to create proxy access response: %v", err)

		// For proxy mode, manually generate tokens when Fosite fails
		h.Log.Infof("🔄 [PROXY-AUTH-CODE] Manually generating proxy tokens due to Fosite error")

		// Generate access token manually
		accessToken, err := utils.GenerateRandomString(32)
		if err != nil {
			h.Log.Errorf("❌ [PROXY-AUTH-CODE] Failed to generate access token: %v", err)
			http.Error(w, "failed to generate access token", http.StatusInternalServerError)
			return
		}
		h.Log.Printf("✅ [PROXY-AUTH-CODE] Manually generated proxy access token: %s", accessToken)

		// Generate refresh token if upstream had one
		var refreshToken string
		if upstreamRefreshToken != "" {
			refreshToken, err = utils.GenerateRandomString(32)
			if err != nil {
				h.Log.Errorf("❌ [PROXY-AUTH-CODE] Failed to generate refresh token: %v", err)
				http.Error(w, "failed to generate refresh token", http.StatusInternalServerError)
				return
			}
			h.Log.Printf("✅ [PROXY-AUTH-CODE] Manually generated proxy refresh token: %s", refreshToken)

			// Store refresh token in Fosite storage
			refreshSignature := h.RefreshTokenStrategy.(interface {
				RefreshTokenSignature(context.Context, string) string
			}).RefreshTokenSignature(ctx, refreshToken)
			accessSignature := h.AccessTokenStrategy.(interface {
				AccessTokenSignature(context.Context, string) string
			}).AccessTokenSignature(ctx, accessToken)
			err = h.Storage.CreateRefreshTokenSession(ctx, refreshSignature, accessSignature, accessRequest)
			if err != nil {
				h.Log.Errorf("❌ [PROXY-AUTH-CODE] Failed to store refresh token session: %v", err)
			} else {
				h.Log.Printf("✅ [PROXY-AUTH-CODE] Stored refresh token session")
			}
		}

		// Create access response manually
		accessResponse = &fosite.AccessResponse{}
		accessResponse.SetAccessToken(accessToken)
		accessResponse.SetTokenType("Bearer")
		if refreshToken != "" {
			accessResponse.SetExtra("refresh_token", refreshToken)
		}
		accessResponse.SetExtra("scope", strings.Join(accessRequest.GetGrantedScopes(), " "))
		accessResponse.SetExtra("expires_in", 3600)
	}

	// Extract the generated proxy tokens
	accessToken := accessResponse.GetAccessToken()
	if accessToken == "" {
		h.Log.Errorf("❌ [PROXY-AUTH-CODE] Failed to extract proxy access token from response")
		http.Error(w, "failed to extract access token", http.StatusInternalServerError)
		return
	}
	h.Log.Printf("✅ [PROXY-AUTH-CODE] Generated proxy access token: %s", accessToken)

	// Extract refresh token if available
	var refreshToken string
	if rt := accessResponse.GetExtra("refresh_token"); rt != nil {
		if rtStr, ok := rt.(string); ok {
			refreshToken = rtStr
			h.Log.Printf("✅ [PROXY-AUTH-CODE] Generated proxy refresh token: %s", refreshToken)
		}
	}

	// Extract ID token if available
	var idToken string
	if it := accessResponse.GetExtra("id_token"); it != nil {
		if itStr, ok := it.(string); ok {
			idToken = itStr
			h.Log.Printf("✅ [PROXY-AUTH-CODE] Generated proxy ID token")
		}
	}

	// If fosite did not generate an ID token but upstream returned one, forward it
	if idToken == "" && upstreamIDToken != "" {
		idToken = upstreamIDToken
		h.Log.Printf("ℹ️ [PROXY-AUTH-CODE] Forwarding upstream ID token as proxy id_token")
	}

	// If OpenID was requested but we still have no ID token, return an error
	wantsIDToken := accessRequest.GetGrantedScopes().Has("openid")
	if wantsIDToken && idToken == "" {
		if h.Configuration.Security.AllowSyntheticIDToken {
			synth, err := h.buildSyntheticIDToken(ctx, accessRequest, upstreamAccessToken)
			if err != nil {
				h.Log.Errorf("❌ [PROXY-AUTH-CODE] Failed to build synthetic id_token: %v", err)
				http.Error(w, "failed to build id_token", http.StatusBadGateway)
				return
			}
			idToken = synth
			h.Log.Printf("ℹ️ [PROXY-AUTH-CODE] Issued synthetic id_token because upstream omitted it")
		} else {
			h.Log.Errorf("❌ [PROXY-AUTH-CODE] Upstream did not return id_token while openid was requested")
			http.Error(w, "upstream did not return id_token", http.StatusBadGateway)
			return
		}
	}

	// If we need a refresh token but Fosite didn't generate one, generate it manually
	if refreshToken == "" && issueRefreshToken {
		// Generate a proper Fosite refresh token
		strategy := h.RefreshTokenStrategy.(oauth2.RefreshTokenStrategy)
		rt, _, err := strategy.GenerateRefreshToken(ctx, accessRequest)
		if err != nil {
			h.Log.Errorf("❌ [PROXY-AUTH-CODE] Failed to generate refresh token: %v", err)
			http.Error(w, "failed to generate refresh token", http.StatusInternalServerError)
			return
		}
		refreshToken = rt
		h.Log.Printf("✅ [PROXY-AUTH-CODE] Manually generated Fosite refresh token")

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
					h.Log.Errorf("❌ [PROXY-AUTH-CODE] Failed to store refresh token session: %v", err)
				} else {
					h.Log.Printf("✅ [PROXY-AUTH-CODE] Stored refresh token session")
				}
			}
		}

		// Add to response
		accessResponse.SetExtra("refresh_token", refreshToken)
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
			h.Log.Printf("✅ [PROXY-AUTH-CODE] Included issuer_state in mapping")
		}
	}

	mappingJSON, err := json.Marshal(mapping)
	if err != nil {
		h.Log.Errorf("❌ [PROXY-AUTH-CODE] Failed to marshal token mapping: %v", err)
	} else {
		// Store mapping for access token
		(*h.AccessTokenToIssuerStateMap)[accessToken] = string(mappingJSON)
		h.Log.Printf("✅ [PROXY-AUTH-CODE] Stored proxy access token mapping: %s -> upstream tokens", accessToken[:20])

		// Store mapping for refresh token if available
		if refreshToken != "" {
			(*h.AccessTokenToIssuerStateMap)[refreshToken] = string(mappingJSON)
			h.Log.Printf("✅ [PROXY-AUTH-CODE] Stored proxy refresh token mapping: %s -> upstream tokens", refreshToken[:20])
		}
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
}

// buildSyntheticIDToken constructs and signs an ID token when upstream omitted it.
// It fetches user info from the upstream userinfo endpoint to anchor the subject.
func (h *TokenHandler) buildSyntheticIDToken(ctx context.Context, accessRequest fosite.AccessRequester, upstreamAccessToken string) (string, error) {
	if h.Configuration.UpstreamProvider.Metadata == nil {
		return "", fmt.Errorf("no upstream metadata available for synthetic id_token")
	}

	userinfoEndpoint, _ := h.Configuration.UpstreamProvider.Metadata["userinfo_endpoint"].(string)
	if userinfoEndpoint == "" {
		return "", fmt.Errorf("no upstream userinfo_endpoint available for synthetic id_token")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, userinfoEndpoint, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+upstreamAccessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("userinfo request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return "", fmt.Errorf("userinfo request returned %d: %s", resp.StatusCode, string(body))
	}

	var ui map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&ui); err != nil {
		return "", fmt.Errorf("failed to decode userinfo: %w", err)
	}

	sub, _ := ui["sub"].(string)
	if sub == "" {
		return "", fmt.Errorf("userinfo missing sub")
	}

	now := time.Now().UTC()
	expSeconds := h.Configuration.Security.TokenExpirySeconds
	if expSeconds <= 0 {
		expSeconds = 3600
	}

	claims := gjwt.MapClaims{
		"iss":       h.Configuration.PublicBaseURL,
		"sub":       sub,
		"aud":       accessRequest.GetClient().GetID(),
		"iat":       now.Unix(),
		"exp":       now.Add(time.Duration(expSeconds) * time.Second).Unix(),
		"auth_time": now.Unix(),
	}

	// Propagate nonce if present in session claims
	if sess, ok := accessRequest.GetSession().(*openid.DefaultSession); ok {
		if sess != nil && sess.Claims != nil && sess.Claims.Extra != nil {
			if nonce, ok := sess.Claims.Extra["nonce"].(string); ok && nonce != "" {
				claims["nonce"] = nonce
			}
		}
	}

	// Include common profile/email hints if available
	if email, ok := ui["email"].(string); ok && email != "" {
		claims["email"] = email
	}
	if name, ok := ui["name"].(string); ok && name != "" {
		claims["name"] = name
	}

	// Sign ID token using RS256 and the server's RSA private key (more secure than HS256)
	token := gjwt.NewWithClaims(gjwt.SigningMethodRS256, claims)
	if h.Signer == nil || h.Signer.GetPrivateKey == nil {
		return "", fmt.Errorf("no signer available to sign id_token with RS256")
	}
	priv, err := h.Signer.GetPrivateKey(context.Background())
	if err != nil {
		return "", fmt.Errorf("failed to get private key for signing id_token: %w", err)
	}

	// Compute kid using shared helper
	if kid, err := utils.ComputeKIDFromKey(priv); err == nil && kid != "" {
		token.Header["kid"] = kid
	}

	signed, err := token.SignedString(priv)
	if err != nil {
		return "", fmt.Errorf("failed to sign synthetic id_token: %w", err)
	}

	return signed, nil
}
