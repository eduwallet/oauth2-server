package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"oauth2-server/internal/store"
	"oauth2-server/internal/store/types"
	"oauth2-server/pkg/config"
	"strings"

	"github.com/sirupsen/logrus"
)

// CallbackHandler manages OAuth2 callback requests for both proxy and local modes
type CallbackHandler struct {
	Configuration      *config.Config
	Log                *logrus.Logger
	UpstreamSessionMap *map[string]UpstreamSessionData
	AuthCodeToStateMap *map[string]string
	ClaimsHandler      *ClaimsHandler
	Storage            store.Storage
}

// NewCallbackHandler creates a new callback handler
func NewCallbackHandler(configuration *config.Config, log *logrus.Logger, upstreamSessionMap *map[string]UpstreamSessionData, authCodeToStateMap *map[string]string, claimsHandler *ClaimsHandler, storage store.Storage) *CallbackHandler {
	return &CallbackHandler{
		Configuration:      configuration,
		Log:                log,
		UpstreamSessionMap: upstreamSessionMap,
		AuthCodeToStateMap: authCodeToStateMap,
		ClaimsHandler:      claimsHandler,
		Storage:            storage,
	}
}

// ServeHTTP handles callback requests based on identity provider mode
func (h *CallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Configuration.IsProxyMode() {
		// In proxy mode, check if this is an upstream callback or client callback
		state := r.URL.Query().Get("state")
		if state != "" {
			// Try to find upstream session - if it exists, this is an upstream provider callback
			if _, ok := (*h.UpstreamSessionMap)[state]; ok {
				h.handleProxyCallback(w, r)
				return
			}
		}
		// Fall through to client callback handling
	}

	// Handle as regular client callback (local mode or proxy mode client callback)
	h.ClaimsHandler.HandleCallback(w, r)
} // handleProxyCallback receives the upstream callback and forwards the code
// and state back to the original client's redirect URI, restoring original state.
func (h *CallbackHandler) handleProxyCallback(w http.ResponseWriter, r *http.Request) {
	if !h.Configuration.IsProxyMode() {
		http.Error(w, "proxy mode not enabled", http.StatusForbidden)
		return
	}

	proxyState := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	errorParam := r.URL.Query().Get("error")

	// Check for OAuth2 error response
	if errorParam != "" {
		h.Log.Errorf("❌ [PROXY-CALLBACK] Upstream provider returned error: %s", errorParam)
		http.Error(w, fmt.Sprintf("upstream error: %s", errorParam), http.StatusBadRequest)
		return
	}

	sess, ok := (*h.UpstreamSessionMap)[proxyState]
	if !ok {
		h.Log.Errorf("❌ [PROXY] Unknown state: %s - not found in session map", proxyState)
		http.Error(w, "unknown state", http.StatusBadRequest)
		return
	}

	// Store the mapping from authorization code to original state for later retrieval during token exchange
	if code != "" && sess.OriginalIssuerState != "" {
		(*h.AuthCodeToStateMap)[code] = sess.OriginalIssuerState
		h.Log.Printf("🔄 [PROXY] Stored authorization code -> original issuer state mapping: %s -> %s", code[:20]+"...", sess.OriginalIssuerState)
	}

	// Check if client requires forced consent
	if sess.ClientID != "" {
		client, err := h.Storage.GetClient(r.Context(), sess.ClientID)
		if err == nil {
			if customClient, ok := client.(*types.CustomClient); ok && customClient.ForceConsent {
				h.Log.Printf("🔐 [PROXY-CALLBACK] Client %s requires forced consent, showing consent screen", sess.ClientID)
				h.showProxyConsentScreen(w, r, sess, code)
				return
			}
		} else {
			h.Log.Warnf("⚠️ [PROXY-CALLBACK] Could not retrieve client %s for consent check: %v", sess.ClientID, err)
		}
	}

	// No forced consent required, proceed with normal redirect
	h.completeProxyAuthorization(w, r, sess, code)
}

// completeProxyAuthorization completes the proxy authorization by redirecting to the client
func (h *CallbackHandler) completeProxyAuthorization(w http.ResponseWriter, r *http.Request, sess UpstreamSessionData, code string) {
	// Build redirect to original client redirect URI
	redirect := sess.OriginalRedirectURI
	// Preserve original state
	sep := "?"
	if strings.Contains(redirect, "?") {
		sep = "&"
	}
	redirectURL := fmt.Sprintf("%s%scode=%s&state=%s", redirect, sep, url.QueryEscape(code), url.QueryEscape(sess.OriginalState))

	h.Log.Printf("✅ [PROXY-CALLBACK] Completing authorization, redirecting to: %s", redirectURL)
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// showProxyConsentScreen displays the consent screen for proxy mode
func (h *CallbackHandler) showProxyConsentScreen(w http.ResponseWriter, r *http.Request, sess UpstreamSessionData, code string) {
	h.Log.Printf("🔐 [PROXY-CONSENT] Showing consent screen for client %s", sess.ClientID)

	// Get client information
	client, err := h.Storage.GetClient(r.Context(), sess.ClientID)
	if err != nil {
		h.Log.Errorf("❌ [PROXY-CONSENT] Failed to get client: %v", err)
		http.Error(w, "Failed to load client information", http.StatusInternalServerError)
		return
	}

	var clientName string
	var scopes []string
	if customClient, ok := client.(*types.CustomClient); ok {
		clientName = customClient.DefaultClient.GetID() // Use ID as fallback name
		// Parse scope from session or use default
		if sess.Scope != "" {
			scopes = strings.Fields(sess.Scope)
		} else {
			scopes = []string{"openid", "profile", "email"} // Default scopes
		}
	} else {
		clientName = sess.ClientID
		scopes = []string{"openid"}
	}

	// Prepare template data (currently unused, HTML is hardcoded)
	_ = struct {
		ClientID    string
		ClientName  string
		RedirectURI string
		State       string
		Scopes      []string
		Code        string
		ProxyState  string
	}{
		ClientID:    sess.ClientID,
		ClientName:  clientName,
		RedirectURI: sess.OriginalRedirectURI,
		State:       sess.OriginalState,
		Scopes:      scopes,
		Code:        code,
		ProxyState:  sess.ProxyState,
	}

	// For now, use a simple HTML response. In a full implementation, you'd load the consent.html template
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <title>Authorization Consent</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 600px; margin: 50px auto; padding: 20px; }
        .consent-form { background: #f9f9f9; padding: 20px; border-radius: 8px; }
        .scope { margin: 10px 0; padding: 10px; background: white; border-radius: 4px; }
        .buttons { margin-top: 20px; text-align: center; }
        button { padding: 10px 20px; margin: 0 10px; border: none; border-radius: 4px; cursor: pointer; }
        .allow { background: #28a745; color: white; }
        .deny { background: #dc3545; color: white; }
    </style>
</head>
<body>
    <div class="consent-form">
        <h2>Authorization Request</h2>
        <p><strong>%s</strong> wants to access your account.</p>
        
        <h3>Requested Permissions:</h3>
        %s
        
        <form method="post" action="/auth/consent">
            <input type="hidden" name="client_id" value="%s">
            <input type="hidden" name="code" value="%s">
            <input type="hidden" name="proxy_state" value="%s">
            <input type="hidden" name="state" value="%s">
            
            <div class="buttons">
                <button type="submit" name="action" value="allow" class="allow">Allow</button>
                <button type="submit" name="action" value="deny" class="deny">Deny</button>
            </div>
        </form>
    </div>
</body>
</html>`, clientName, strings.Join(scopes, " "), sess.ClientID, code, sess.ProxyState, sess.OriginalState)

	w.Write([]byte(html))
}

// HandleProxyConsent processes the user's consent decision for proxy mode
func (h *CallbackHandler) HandleProxyConsent(w http.ResponseWriter, r *http.Request) {
	h.Log.Printf("🔐 [PROXY-CONSENT] Processing consent decision")

	if err := r.ParseForm(); err != nil {
		h.Log.Errorf("❌ [PROXY-CONSENT] Failed to parse form: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	action := r.Form.Get("action")
	clientID := r.Form.Get("client_id")
	code := r.Form.Get("code")
	proxyState := r.Form.Get("proxy_state")
	// originalState := r.Form.Get("state") // Not used in current implementation

	h.Log.Printf("🔍 [PROXY-CONSENT] Action: %s, ClientID: %s, Code: %s", action, clientID, proxyState)

	if action != "allow" {
		h.Log.Printf("❌ [PROXY-CONSENT] User denied consent for client %s", clientID)

		// Get the session data to redirect with error
		sess, ok := (*h.UpstreamSessionMap)[proxyState]
		if !ok {
			h.Log.Errorf("❌ [PROXY-CONSENT] Unknown proxy state for denial: %s", proxyState)
			http.Error(w, "Invalid session", http.StatusBadRequest)
			return
		}

		// Redirect to client with access_denied error
		errorURL := fmt.Sprintf("%s?error=access_denied&state=%s", sess.OriginalRedirectURI, sess.OriginalState)
		h.Log.Printf("🔄 [PROXY-CONSENT] Redirecting to client with error: %s", errorURL)
		http.Redirect(w, r, errorURL, http.StatusFound)
		return
	}

	// Get the session data
	sess, ok := (*h.UpstreamSessionMap)[proxyState]
	if !ok {
		h.Log.Errorf("❌ [PROXY-CONSENT] Unknown proxy state: %s", proxyState)
		http.Error(w, "Invalid session", http.StatusBadRequest)
		return
	}

	h.Log.Printf("✅ [PROXY-CONSENT] User granted consent for client %s", clientID)

	// Complete the authorization
	h.completeProxyAuthorization(w, r, sess, code)
}
