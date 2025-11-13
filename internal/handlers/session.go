package handlers

import (
	"time"

	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
)

// UpstreamSessionData represents the session data for proxying OAuth2 flows
type UpstreamSessionData struct {
	OriginalIssuerState   string
	OriginalState         string
	OriginalNonce         string
	OriginalRedirectURI   string
	OriginalCodeChallenge string
	ProxyState            string
	ProxyNonce            string
	ProxyCodeChallenge    string
}

func userSession(issuer, user string, audience []string) *openid.DefaultSession {
	return &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:      issuer,
			Subject:     user,
			Audience:    audience,
			ExpiresAt:   time.Now().Add(time.Hour * 6),
			IssuedAt:    time.Now(),
			RequestedAt: time.Now(),
			AuthTime:    time.Now(),
		},
		Headers: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
		// CRITICAL: Set Subject and Username at the session level
		// fosite uses these fields for GetSubject() and GetUsername()
		Subject:  user,
		Username: user,
	}
}

func newSession() *openid.DefaultSession {
	return userSession("", "", []string{})
}
