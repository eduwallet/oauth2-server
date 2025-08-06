package handlers

import (
	"context"
	"net/http"
	"strings"

	"github.com/ory/fosite"
)

// HandleAuthorize handles OAuth2 authorization endpoint using Fosite
func (h *Handlers) HandleAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := context.Background()

	// Let Fosite parse and validate the request
	authRequest, err := h.OAuth2Provider.NewAuthorizeRequest(ctx, r)
	if err != nil {
		h.Logger.WithError(err).Error("Invalid authorization request")
		h.OAuth2Provider.WriteAuthorizeError(ctx, w, authRequest, err)
		return
	}

	// Check if user is authenticated
	if !h.isUserAuthenticated(r) {
		// Store the request for when the user returns after login
		// This depends on your session mechanism
		h.storeAuthRequestInSession(w, r, authRequest)

		// Show login form with client info from the request
		h.showLoginForm(w, r, &AuthorizeRequest{
			ClientID:     authRequest.GetClient().GetID(),
			RedirectURI:  authRequest.GetRedirectURI(),
			Scopes:       authRequest.GetRequestedScopes(),
			State:        authRequest.GetState(),
			ResponseType: authRequest.GetResponseTypes()[0],
		})
		return
	}

	// Get user ID from the session
	userID := h.getCurrentUserID(r)

	// Create a session that Fosite understands
	session := &UserSession{
		Subject: userID,
		// Add other user information if needed
	}

	// Let Fosite handle the response (generate auth code, handle redirect, etc.)
	h.OAuth2Provider.WriteAuthorizeResponse(ctx, w, authRequest, session)
}

// UserSession implements fosite.Session
type UserSession struct {
	Subject string
	// Add other fields as needed
}

// GetSubject returns the subject (user ID)
func (s *UserSession) GetSubject() string {
	return s.Subject
}

// Clone creates a deep copy of the session
func (s *UserSession) Clone() fosite.Session {
	return &UserSession{
		Subject: s.Subject,
	}
}

// storeAuthRequestInSession stores the auth request in the user's session
func (h *Handlers) storeAuthRequestInSession(w http.ResponseWriter, r *http.Request, authRequest fosite.AuthorizeRequester) {
	// This depends on your session mechanism
	// For example, if using Gorilla sessions:
	session, _ := h.SessionStore.Get(r, "auth-session")

	// Store the minimal info needed to reconstruct the request
	session.Values["auth_request_client_id"] = authRequest.GetClient().GetID()
	session.Values["auth_request_redirect_uri"] = authRequest.GetRedirectURI()
	session.Values["auth_request_scopes"] = strings.Join(authRequest.GetRequestedScopes(), " ")
	session.Values["auth_request_state"] = authRequest.GetState()
	session.Values["auth_request_response_type"] = authRequest.GetResponseTypes()[0]

	session.Save(r, w)
}

// getCurrentUserID gets the user ID from the session
func (h *Handlers) getCurrentUserID(r *http.Request) string {
	// This depends on your session mechanism
	// For example, if using Gorilla sessions:
	session, _ := h.SessionStore.Get(r, "auth-session")
	if userID, ok := session.Values["user_id"].(string); ok {
		return userID
	}
	return ""
}

// isUserAuthenticated checks if the user is authenticated
func (h *Handlers) isUserAuthenticated(r *http.Request) bool {
	// This depends on your session mechanism
	// For example, if using Gorilla sessions:
	session, _ := h.SessionStore.Get(r, "auth-session")
	_, ok := session.Values["user_id"].(string)
	return ok
}
