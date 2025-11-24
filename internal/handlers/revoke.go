package handlers

import (
	"net/http"

	"github.com/ory/fosite"
	"github.com/sirupsen/logrus"
)

// RevokeHandler manages OAuth2 token revocation requests
type RevokeHandler struct {
	OAuth2Provider fosite.OAuth2Provider
	Log            *logrus.Logger
}

// NewRevokeHandler creates a new revoke handler
func NewRevokeHandler(oauth2Provider fosite.OAuth2Provider, log *logrus.Logger) *RevokeHandler {
	return &RevokeHandler{
		OAuth2Provider: oauth2Provider,
		Log:            log,
	}
}

// ServeHTTP handles token revocation requests (RFC 7009)
func (h *RevokeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	err := h.OAuth2Provider.NewRevocationRequest(ctx, r)
	if err != nil {
		h.Log.Errorf("❌ Error revoking token: %v", err)
		h.OAuth2Provider.WriteRevocationResponse(ctx, w, err)
		return
	}
	h.OAuth2Provider.WriteRevocationResponse(ctx, w, nil)
}
