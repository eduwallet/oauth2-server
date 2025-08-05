package handlers

import (
	"net/http"
	"oauth2-server/internal/storage"
	"strings"
)

// HandleAuthorize handles OAuth2 authorization endpoint
func (h *Handlers) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		h.writeError(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse authorization request
	req := &AuthorizeRequest{
		ClientID:            r.URL.Query().Get("client_id"),
		ResponseType:        r.URL.Query().Get("response_type"),
		RedirectURI:         r.URL.Query().Get("redirect_uri"),
		Scopes:              strings.Split(r.URL.Query().Get("scope"), " "),
		State:               r.URL.Query().Get("state"),
		CodeChallenge:       r.URL.Query().Get("code_challenge"),
		CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
	}

	// Basic validation
	if req.ClientID == "" || req.ResponseType == "" {
		h.writeError(w, "invalid_request", "Missing required parameters", http.StatusBadRequest)
		return
	}

	// Validate client
	client := h.findClient(req.ClientID)
	if client == nil {
		h.writeError(w, "invalid_client", "Unknown client", http.StatusBadRequest)
		return
	}

	// Check if user is authenticated
	if !h.isUserAuthenticated(r) {
		h.showLoginForm(w, r, req)
		return
	}

	// Get the authenticated user from the session
	userID := h.getCurrentUserID(r)

	// Create a new AuthorizeRequest with UserID
	authReq := &storage.AuthorizeRequest{
		ClientID:            req.ClientID,
		ResponseType:        req.ResponseType,
		RedirectURI:         req.RedirectURI,
		Scopes:              req.Scopes,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		UserID:              userID,
	}

	// Generate authorization code
	code := generateRandomString(32)
	if err := h.Storage.StoreAuthCode(code, authReq); err != nil {
		h.Logger.WithError(err).Error("Failed to store authorization code")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Redirect with authorization code
	redirectURI := req.RedirectURI + "?code=" + code
	if req.State != "" {
		redirectURI += "&state=" + req.State
	}

	http.Redirect(w, r, redirectURI, http.StatusFound)
}

// HandleConsent handles the consent page
func (h *Handlers) HandleConsent(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		clientID := r.URL.Query().Get("client_id")
		scope := r.URL.Query().Get("scope")

		data := map[string]interface{}{
			"ClientID": clientID,
			"Scope":    scope,
		}

		if err := h.Templates.ExecuteTemplate(w, "consent.html", data); err != nil {
			h.Logger.WithError(err).Error("Failed to render consent template")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

func (h *Handlers) showLoginForm(w http.ResponseWriter, r *http.Request, authReq *AuthorizeRequest) {
	data := map[string]interface{}{
		"ClientID":    authReq.ClientID,
		"Scope":       authReq.Scopes,
		"RedirectURL": r.URL.String(),
	}

	if err := h.Templates.ExecuteTemplate(w, "login.html", data); err != nil {
		h.Logger.WithError(err).Error("Failed to render login template")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
