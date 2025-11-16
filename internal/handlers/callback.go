package handlers

import (
	"fmt"
	"net/http"
	"net/url"
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
}

// NewCallbackHandler creates a new callback handler
func NewCallbackHandler(configuration *config.Config, log *logrus.Logger, upstreamSessionMap *map[string]UpstreamSessionData, authCodeToStateMap *map[string]string, claimsHandler *ClaimsHandler) *CallbackHandler {
	return &CallbackHandler{
		Configuration:      configuration,
		Log:                log,
		UpstreamSessionMap: upstreamSessionMap,
		AuthCodeToStateMap: authCodeToStateMap,
		ClaimsHandler:      claimsHandler,
	}
}

// ServeHTTP handles callback requests based on identity provider mode
func (h *CallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Configuration.IsProxyMode() {
		// Proxy mode: handle upstream callback and forward to original client
		h.handleProxyCallback(w, r)
	} else {
		// Local mode: handle callback and redirect to claims display
		h.ClaimsHandler.HandleCallback(w, r)
	}
}

// handleProxyCallback receives the upstream callback and forwards the code
// and state back to the original client's redirect URI, restoring original state.
func (h *CallbackHandler) handleProxyCallback(w http.ResponseWriter, r *http.Request) {
	if !h.Configuration.IsProxyMode() {
		http.Error(w, "proxy mode not enabled", http.StatusForbidden)
		return
	}

	proxyState := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")

	sess, ok := (*h.UpstreamSessionMap)[proxyState]
	if !ok {
		h.Log.Printf("❌ [PROXY] Unknown state: %s - not found in session map", proxyState)
		http.Error(w, "unknown state", http.StatusBadRequest)
		return
	}

	// Store the mapping from authorization code to original state for later retrieval during token exchange
	if code != "" && sess.OriginalIssuerState != "" {
		(*h.AuthCodeToStateMap)[code] = sess.OriginalIssuerState
		h.Log.Printf("🔄 [PROXY] Stored authorization code -> original issuer state mapping: %s -> %s", code[:20]+"...", sess.OriginalIssuerState)
	}

	// Build redirect to original client redirect URI
	redirect := sess.OriginalRedirectURI
	// Preserve original state
	sep := "?"
	if strings.Contains(redirect, "?") {
		sep = "&"
	}
	redirectURL := fmt.Sprintf("%s%scode=%s&state=%s", redirect, sep, url.QueryEscape(code), url.QueryEscape(sess.OriginalState))

	// Remove session
	delete(*h.UpstreamSessionMap, proxyState)

	http.Redirect(w, r, redirectURL, http.StatusFound)
}
