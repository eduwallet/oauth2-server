package handlers

import (
	"encoding/json"
	"io"
	"net/http"
	"oauth2-server/internal/metrics"
	"oauth2-server/internal/store"
	"oauth2-server/pkg/config"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/sirupsen/logrus"
)

type UserInfoHandler struct {
	OAuth2Provider fosite.OAuth2Provider
	Configuration  *config.Config
	Metrics        *metrics.MetricsCollector
	Log            *logrus.Logger
	Storage        store.Storage
}

// NewUserInfoHandler creates a new userinfo handler
func NewUserInfoHandler(config *config.Config, oauth2Provider fosite.OAuth2Provider, metrics *metrics.MetricsCollector, log *logrus.Logger, storage store.Storage) *UserInfoHandler {
	return &UserInfoHandler{
		Configuration:  config,
		OAuth2Provider: oauth2Provider,
		Metrics:        metrics,
		Log:            log,
		Storage:        storage,
	}
}

// Enhanced userinfo handler with proper user lookup
func (h *UserInfoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Check if proxy mode is enabled
	if h.Configuration.IsProxyMode() {
		h.handleProxyUserinfo(w, r)
		return
	}

	// Extract bearer token
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		if h.Metrics != nil {
			h.Metrics.RecordUserinfoRequest("error", "missing_auth_header")
		}
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "Missing authorization header", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		if h.Metrics != nil {
			h.Metrics.RecordUserinfoRequest("error", "invalid_auth_header")
		}
		w.Header().Set("WWW-Authenticate", "Bearer")
		http.Error(w, "Invalid authorization header format", http.StatusUnauthorized)
		return
	}

	token := parts[1]

	// Use fosite's introspection to validate the token
	ctx := r.Context()
	_, requester, err := h.OAuth2Provider.IntrospectToken(ctx, token, fosite.AccessToken, &openid.DefaultSession{})
	if err != nil {
		h.Log.Errorf("❌ UserInfo: Token introspection failed: %v", err)
		if h.Metrics != nil {
			h.Metrics.RecordUserinfoRequest("error", "invalid_token")
		}

		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="The access token is invalid or has expired."`)
		http.Error(w, "Invalid access token", http.StatusUnauthorized)
		return
	}

	h.Log.Printf("✅ UserInfo: Token validated successfully")

	// Get user info from token claims (the subject)
	session := requester.GetSession()
	if session == nil {
		h.Log.Errorf("❌ UserInfo: No session found in token")
		if h.Metrics != nil {
			h.Metrics.RecordUserinfoRequest("error", "no_session")
		}
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="No session found in token."`)
		http.Error(w, "Invalid token session", http.StatusUnauthorized)
		return
	}

	subject := session.GetSubject()
	username := session.GetUsername()

	h.Log.Printf("🔍 UserInfo: Token subject='%s', username='%s'", subject, username)

	// Check if this is a client credentials flow (no user context)
	// For client credentials tokens, fosite sets subject/username to the client ID
	if subject != "" {
		// Check if the subject matches a known client ID
		if _, exists := h.Configuration.GetClientByID(subject); exists {
			h.Log.Errorf("❌ UserInfo: Client credentials token - subject '%s' is a client ID, no user context available", subject)
			if h.Metrics != nil {
				h.Metrics.RecordUserinfoRequest("error", "no_user_context")
			}
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="UserInfo endpoint requires user-authenticated tokens."`)
			http.Error(w, "UserInfo requires user authentication", http.StatusUnauthorized)
			return
		}
	}

	if subject == "" && username == "" {
		h.Log.Errorf("❌ UserInfo: Client credentials token - no user context available")
		if h.Metrics != nil {
			h.Metrics.RecordUserinfoRequest("error", "no_user_context")
		}
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="UserInfo endpoint requires user-authenticated tokens."`)
		http.Error(w, "UserInfo requires user authentication", http.StatusUnauthorized)
		return
	}

	// Try to find user by subject first, then by username
	var userInfo map[string]interface{}
	var user *config.UserConfig
	var found bool

	if subject != "" {
		user, found = h.Configuration.GetUserByID(subject)
		if !found {
			user, found = h.Configuration.GetUserByUsername(subject)
		}
	}

	if !found && username != "" {
		user, found = h.Configuration.GetUserByUsername(username)
		if !found {
			user, found = h.Configuration.GetUserByID(username)
		}
	}

	if found {
		h.Log.Printf("✅ UserInfo: Found user: %s (%s)", user.Username, user.Name)
		userInfo = map[string]interface{}{
			"sub":      user.ID,
			"name":     user.Name,
			"email":    user.Email,
			"username": user.Username,
		}

		// Add the issuer state from the authorization request if available in the session
		if defaultSession, ok := session.(*openid.DefaultSession); ok && defaultSession.Headers != nil && defaultSession.Headers.Extra != nil {
			if issuerState, ok := defaultSession.Headers.Extra["issuer_state"].(string); ok && issuerState != "" {
				// issuer_state moved to introspection endpoint - no longer included in userinfo
				h.Log.Printf("ℹ️ UserInfo: issuer_state available but moved to introspection endpoint: %s", issuerState)
			}
		}
	} else {
		h.Log.Errorf("❌ UserInfo: User not found for subject='%s', username='%s'", subject, username)
		if h.Metrics != nil {
			h.Metrics.RecordUserinfoRequest("error", "user_not_found")
		}
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="User not found."`)
		http.Error(w, "User associated with token not found", http.StatusUnauthorized)
		return
	}

	if h.Metrics != nil {
		h.Metrics.RecordUserinfoRequest("success", "")
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(userInfo)
}

// handleProxyUserinfo forwards userinfo requests to the upstream userinfo endpoint,
// using the mapped upstream access token instead of the proxy token.
func (h *UserInfoHandler) handleProxyUserinfo(w http.ResponseWriter, r *http.Request) {
	h.Log.Printf("🔄 [PROXY] Starting upstream userinfo request")

	// Extract the proxy access token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		h.Log.Errorf("❌ [PROXY] Missing authorization header in userinfo request")
		http.Error(w, "authorization required", http.StatusUnauthorized)
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		h.Log.Errorf("❌ [PROXY] Invalid authorization header format")
		http.Error(w, "invalid authorization header", http.StatusUnauthorized)
		return
	}

	proxyToken := parts[1]
	h.Log.Printf("🔑 [PROXY] Received proxy token: %s...", proxyToken[:20]+"...")

	// Check if this is a proxy token by looking up upstream token mapping
	var upstreamToken string
	var issuerState string

	// First, try to get upstream token mapping from persistent storage
	upstreamAccessToken, _, _, _, err := h.Storage.GetUpstreamTokenMapping(r.Context(), proxyToken)
	if err == nil && upstreamAccessToken != "" {
		h.Log.Printf("✅ [PROXY] Found upstream token in persistent storage: %s...", upstreamAccessToken[:20])
		upstreamToken = upstreamAccessToken
	} else {
		h.Log.Printf("⚠️ [PROXY] No upstream token mapping found in storage (%v), trying session claims", err)

		// Fallback: Use fosite's introspection to validate the proxy token and get session data
		ctx := r.Context()
		_, requester, err := h.OAuth2Provider.IntrospectToken(ctx, proxyToken, fosite.AccessToken, &openid.DefaultSession{})
		if err != nil {
			h.Log.Printf("⚠️ [PROXY] Token introspection failed (%v), assuming direct upstream token (device flow)", err)
			// For device flow, the token itself is the upstream token
			upstreamToken = proxyToken
		} else {
			h.Log.Printf("✅ [PROXY] Token introspection successful")

			session := requester.GetSession()
			if session == nil {
				h.Log.Errorf("❌ [PROXY] No session found in proxy token")
				http.Error(w, "invalid proxy token session", http.StatusUnauthorized)
				return
			}

			// Extract upstream token and metadata from session claims
			if defaultSession, ok := session.(*openid.DefaultSession); ok && defaultSession.Claims != nil && defaultSession.Claims.Extra != nil {
				if token, ok := defaultSession.Claims.Extra["upstream_token"].(string); ok {
					upstreamToken = token
					h.Log.Printf("✅ [PROXY] Found upstream token in session claims: %s...", upstreamToken[:20])
				}
				if state, ok := defaultSession.Claims.Extra["issuer_state"].(string); ok {
					issuerState = state
					h.Log.Printf("✅ [PROXY] Found issuer state in session claims: %s", issuerState)
				}
			}

			// For device flow proxy tokens, the access token itself is the upstream token
			// (device flow returns upstream tokens directly without creating proxy tokens)
			if upstreamToken == "" {
				h.Log.Printf("ℹ️ [PROXY] No upstream token in session claims, using proxy token directly (likely device flow)")
				upstreamToken = proxyToken
			}
		}
	}

	if upstreamToken == "" {
		h.Log.Errorf("❌ [PROXY] No upstream token available")
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}

	if h.Configuration.UpstreamProvider.Metadata == nil {
		h.Log.Errorf("❌ [PROXY] Upstream provider metadata not configured")
		http.Error(w, "upstream provider not configured", http.StatusBadGateway)
		return
	}

	userinfoEndpoint, _ := h.Configuration.UpstreamProvider.Metadata["userinfo_endpoint"].(string)
	if userinfoEndpoint == "" {
		h.Log.Errorf("❌ [PROXY] Upstream userinfo_endpoint not available in metadata")
		http.Error(w, "upstream userinfo_endpoint not available", http.StatusBadGateway)
		return
	}

	h.Log.Printf("🔗 [PROXY] Upstream userinfo endpoint: %s", userinfoEndpoint)

	// Create upstream request with the mapped upstream token
	upstreamAuthHeader := "Bearer " + upstreamToken
	h.Log.Printf("🔐 [PROXY] Using upstream authorization header: %s...", upstreamAuthHeader[:20]+"...")

	req, err := http.NewRequest("GET", userinfoEndpoint, nil)
	if err != nil {
		h.Log.Errorf("❌ [PROXY] Failed to create upstream userinfo request: %v", err)
		http.Error(w, "failed to create upstream userinfo request", http.StatusInternalServerError)
		return
	}

	req.Header.Set("Authorization", upstreamAuthHeader)
	req.Header.Set("User-Agent", "OAuth2-Proxy/1.0")

	h.Log.Printf("🚀 [PROXY] Sending userinfo request to upstream endpoint")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		h.Log.Errorf("❌ [PROXY] Upstream userinfo request failed: %v", err)
		http.Error(w, "upstream userinfo request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	h.Log.Printf("📥 [PROXY] Upstream userinfo response status: %d", resp.StatusCode)
	h.Log.Printf("📥 [PROXY] Upstream userinfo response headers: %+v", resp.Header)

	// Read and log response body for debugging
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		h.Log.Errorf("❌ [PROXY] Failed to read upstream userinfo response body: %v", err)
		http.Error(w, "failed to read upstream response", http.StatusInternalServerError)
		return
	}

	h.Log.Printf("📄 [PROXY] Upstream userinfo response body: %s", string(respBody))

	// Parse the upstream userinfo response to add proxy claim
	var userinfo map[string]interface{}
	if err := json.Unmarshal(respBody, &userinfo); err != nil {
		h.Log.Errorf("❌ [PROXY] Failed to parse upstream userinfo response as JSON: %v", err)
		h.Log.Printf("📄 [PROXY] Returning raw upstream response due to parse error")
		// Fall back to returning the raw response if JSON parsing fails
		w.WriteHeader(resp.StatusCode)
		if _, err := w.Write(respBody); err != nil {
			h.Log.Errorf("❌ [PROXY] Failed to write userinfo response body to client: %v", err)
		}
		return
	}

	// Add proxy claim attribute to indicate this response was processed by the proxy
	userinfo["proxy_processed"] = true
	userinfo["proxy_server"] = "oauth2-server"
	userinfo["proxy_timestamp"] = time.Now().UTC().Format(time.RFC3339)

	// Add the issuer_state if available from the proxy token mapping
	if issuerState != "" {
		// issuer_state moved to introspection endpoint - no longer included in userinfo
		h.Log.Printf("ℹ️ [PROXY] issuer_state available but moved to introspection endpoint: %s", issuerState)
	}

	h.Log.Printf("✅ [PROXY] Added proxy claims to userinfo response")

	// Re-encode the modified userinfo response
	modifiedRespBody, err := json.Marshal(userinfo)
	if err != nil {
		h.Log.Errorf("❌ [PROXY] Failed to encode modified userinfo response: %v", err)
		h.Log.Printf("📄 [PROXY] Returning original upstream response due to encode error")
		// Fall back to returning the original response if encoding fails
		w.WriteHeader(resp.StatusCode)
		if _, err := w.Write(respBody); err != nil {
			h.Log.Errorf("❌ [PROXY] Failed to write userinfo response body to client: %v", err)
		}
		return
	}

	h.Log.Printf("📄 [PROXY] Modified userinfo response body: %s", string(modifiedRespBody))

	// Copy response headers and status, but remove Content-Length since we're modifying the body
	for k, vv := range resp.Header {
		if strings.ToLower(k) == "content-length" {
			// Skip Content-Length header since we're modifying the response body
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Write modified response body back to client
	if _, err := w.Write(modifiedRespBody); err != nil {
		h.Log.Errorf("❌ [PROXY] Failed to write modified userinfo response body to client: %v", err)
	}
}
