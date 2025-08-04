package store

import (
	"context"
	"log"
	"time"

	"github.com/ory/fosite"
	"github.com/go-jose/go-jose/v3"
)

// CompositeStore implements all Fosite storage interfaces by delegating to sub-stores.
type CompositeStore struct {
	ClientStore *ClientStore
	TokenStore  *TokenStore
}

// Authentication and JWT
func (c *CompositeStore) Authenticate(ctx context.Context, name string, secret string) (string, error) {
	log.Printf("[DEBUG] CompositeStore.Authenticate called with name=%s, secret=****", name)
	return c.ClientStore.Authenticate(ctx, name, secret)
}
func (c *CompositeStore) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	log.Printf("[DEBUG] CompositeStore.ClientAssertionJWTValid called with jti=%s", jti)
	return c.TokenStore.ClientAssertionJWTValid(ctx, jti)
}
func (c *CompositeStore) IsJWTUsed(ctx context.Context, jti string) (bool, error) {
	log.Printf("[DEBUG] CompositeStore.IsJWTUsed called with jti=%s", jti)
	return c.TokenStore.IsJWTUsed(ctx, jti)
}
func (c *CompositeStore) MarkJWTUsedForTime(ctx context.Context, jti string, exp time.Time) error {
	log.Printf("[DEBUG] CompositeStore.MarkJWTUsedForTime called with jti=%s, exp=%v", jti, exp)
	return c.TokenStore.MarkJWTUsedForTime(ctx, jti, exp)
}
func (c *CompositeStore) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	log.Printf("[DEBUG] CompositeStore.SetClientAssertionJWT called with jti=%s, exp=%v", jti, exp)
	return c.TokenStore.SetClientAssertionJWT(ctx, jti, exp)
}

// Access Token
func (c *CompositeStore) CreateAccessTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	log.Printf("[DEBUG] CompositeStore.CreateAccessTokenSession called with signature=%s", signature)
	return c.TokenStore.CreateAccessTokenSession(ctx, signature, req)
}
func (c *CompositeStore) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	log.Printf("[DEBUG] CompositeStore.GetAccessTokenSession called with signature=%s", signature)
	return c.TokenStore.GetAccessTokenSession(ctx, signature, session)
}
func (c *CompositeStore) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	log.Printf("[DEBUG] CompositeStore.DeleteAccessTokenSession called with signature=%s", signature)
	return c.TokenStore.DeleteAccessTokenSession(ctx, signature)
}
func (c *CompositeStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	log.Printf("[DEBUG] CompositeStore.RevokeAccessToken called with requestID=%s", requestID)
	return c.TokenStore.RevokeAccessToken(ctx, requestID)
}

// Authorize Code
func (c *CompositeStore) CreateAuthorizeCodeSession(ctx context.Context, code string, req fosite.Requester) error {
	log.Printf("[DEBUG] CompositeStore.CreateAuthorizeCodeSession called with code=%s", code)
	return c.TokenStore.CreateAuthorizeCodeSession(ctx, code, req)
}
func (c *CompositeStore) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	log.Printf("[DEBUG] CompositeStore.GetAuthorizeCodeSession called with code=%s", code)
	return c.TokenStore.GetAuthorizeCodeSession(ctx, code, session)
}
func (c *CompositeStore) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	log.Printf("[DEBUG] CompositeStore.InvalidateAuthorizeCodeSession called with code=%s", code)
	return c.TokenStore.InvalidateAuthorizeCodeSession(ctx, code)
}

// OpenID Connect
func (c *CompositeStore) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) error {
	log.Printf("[DEBUG] CompositeStore.CreateOpenIDConnectSession called with authorizeCode=%s", authorizeCode)
	return c.TokenStore.CreateOpenIDConnectSession(ctx, authorizeCode, requester)
}
func (s *CompositeStore) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	log.Printf("[DEBUG] CompositeStore.GetOpenIDConnectSession called with authorizeCode=%s", authorizeCode)
	return s.TokenStore.GetOpenIDConnectSession(ctx, authorizeCode, requester)
}
func (c *CompositeStore) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	log.Printf("[DEBUG] CompositeStore.DeleteOpenIDConnectSession called with authorizeCode=%s", authorizeCode)
	return c.TokenStore.DeleteOpenIDConnectSession(ctx, authorizeCode)
}

// PAR
func (c *CompositeStore) CreatePARSession(ctx context.Context, requestURI string, request fosite.AuthorizeRequester) error {
	log.Printf("[DEBUG] CompositeStore.CreatePARSession called with requestURI=%s", requestURI)
	return c.TokenStore.CreatePARSession(ctx, requestURI, request)
}
func (c *CompositeStore) GetPARSession(ctx context.Context, requestURI string) (fosite.AuthorizeRequester, error) {
	log.Printf("[DEBUG] CompositeStore.GetPARSession called with requestURI=%s", requestURI)
	return c.TokenStore.GetPARSession(ctx, requestURI)
}
func (c *CompositeStore) DeletePARSession(ctx context.Context, requestURI string) error {
	log.Printf("[DEBUG] CompositeStore.DeletePARSession called with requestURI=%s", requestURI)
	return c.TokenStore.DeletePARSession(ctx, requestURI)
}

// PKCE
func (c *CompositeStore) CreatePKCERequestSession(ctx context.Context, code string, req fosite.Requester) error {
	log.Printf("[DEBUG] CompositeStore.CreatePKCERequestSession called with code=%s", code)
	return c.TokenStore.CreatePKCERequestSession(ctx, code, req)
}
func (c *CompositeStore) GetPKCERequestSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	log.Printf("[DEBUG] CompositeStore.GetPKCERequestSession called with code=%s", code)
	return c.TokenStore.GetPKCERequestSession(ctx, code, session)
}
func (c *CompositeStore) DeletePKCERequestSession(ctx context.Context, code string) error {
	log.Printf("[DEBUG] CompositeStore.DeletePKCERequestSession called with code=%s", code)
	return c.TokenStore.DeletePKCERequestSession(ctx, code)
}

// Refresh Token
func (c *CompositeStore) CreateRefreshTokenSession(ctx context.Context, signature, accessTokenSignature string, req fosite.Requester) error {
	log.Printf("[DEBUG] CompositeStore.CreateRefreshTokenSession called with signature=%s, accessTokenSignature=%s", signature, accessTokenSignature)
	return c.TokenStore.CreateRefreshTokenSession(ctx, signature, accessTokenSignature, req)
}
func (c *CompositeStore) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	log.Printf("[DEBUG] CompositeStore.GetRefreshTokenSession called with signature=%s", signature)
	return c.TokenStore.GetRefreshTokenSession(ctx, signature, session)
}
func (c *CompositeStore) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	log.Printf("[DEBUG] CompositeStore.DeleteRefreshTokenSession called with signature=%s", signature)
	return c.TokenStore.DeleteRefreshTokenSession(ctx, signature)
}
func (c *CompositeStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	log.Printf("[DEBUG] CompositeStore.RevokeRefreshToken called with requestID=%s", requestID)
	return c.TokenStore.RevokeRefreshToken(ctx, requestID)
}
func (c *CompositeStore) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	log.Printf("[DEBUG] CompositeStore.RotateRefreshToken called with requestID=%s, refreshTokenSignature=%s", requestID, refreshTokenSignature)
	return c.TokenStore.RotateRefreshToken(ctx, requestID, refreshTokenSignature)
}

// Client
func (c *CompositeStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	log.Printf("[DEBUG] CompositeStore.GetClient called with id=%s", id)
	return c.ClientStore.GetClient(ctx, id)
}
func (c *CompositeStore) SetTokenLifespans(clientID string, lifespans *fosite.ClientLifespanConfig) error {
	log.Printf("[DEBUG] CompositeStore.SetTokenLifespans called with clientID=%s, lifespans=%+v", clientID, lifespans)
	return c.ClientStore.SetTokenLifespans(clientID, lifespans)
}

// Public Key (RFC7523)
func (c *CompositeStore) GetPublicKey(ctx context.Context, issuer, subject, keyID string) (*jose.JSONWebKey, error) {
	log.Printf("[DEBUG] CompositeStore.GetPublicKey called with issuer=%s, subject=%s, keyID=%s", issuer, subject, keyID)
	if c.ClientStore != nil {
		return c.ClientStore.GetPublicKey(ctx, issuer, subject, keyID)
	}
	return nil, fosite.ErrNotFound
}
func (c *CompositeStore) GetPublicKeyScopes(ctx context.Context, issuer, subject, keyID string) ([]string, error) {
	log.Printf("[DEBUG] CompositeStore.GetPublicKeyScopes called with issuer=%s, subject=%s, keyID=%s", issuer, subject, keyID)
	if c.ClientStore != nil {
		return c.ClientStore.GetPublicKeyScopes(ctx, issuer, subject, keyID)
	}
	return nil, fosite.ErrNotFound
}
func (c *CompositeStore) GetPublicKeys(ctx context.Context, issuer, subject string) (*jose.JSONWebKeySet, error) {
	log.Printf("[DEBUG] CompositeStore.GetPublicKeys called with issuer=%s, subject=%s", issuer, subject)
	if c.ClientStore != nil {
		return c.ClientStore.GetPublicKeys(ctx, issuer, subject)
	}
	return nil, fosite.ErrNotFound
}