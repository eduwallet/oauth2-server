package store

import (
	"context"
	"github.com/go-jose/go-jose/v3"
	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/rfc8693"
	"github.com/ory/fosite/storage"
	"log"
	"time"
)

// Simplified CompositeStore
type CompositeStore struct {
	ClientManager *ClientManager
	CoreStorage   *storage.MemoryStore
}

func NewCompositeStore() *CompositeStore {
	return &CompositeStore{
		ClientManager: NewClientManager(),
		CoreStorage:   storage.NewMemoryStore(),
	}
}

// Implement ClientManager interface
func (c *CompositeStore) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	return c.ClientManager.GetClient(ctx, id)
}

func (c *CompositeStore) CreateOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) error {
	return c.CoreStorage.CreateOpenIDConnectSession(ctx, authorizeCode, requester)
}

func (c *CompositeStore) GetOpenIDConnectSession(ctx context.Context, authorizeCode string, requester fosite.Requester) (fosite.Requester, error) {
	return c.CoreStorage.GetOpenIDConnectSession(ctx, authorizeCode, requester)
}

func (c *CompositeStore) DeleteOpenIDConnectSession(ctx context.Context, authorizeCode string) error {
	return c.CoreStorage.DeleteOpenIDConnectSession(ctx, authorizeCode)
}

func (c *CompositeStore) SetTokenLifespans(clientID string, lifespans *fosite.ClientLifespanConfig) error {
	return c.CoreStorage.SetTokenLifespans(clientID, lifespans)
}

func (c *CompositeStore) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return c.CoreStorage.ClientAssertionJWTValid(ctx, jti)
}

func (c *CompositeStore) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return c.CoreStorage.SetClientAssertionJWT(ctx, jti, exp)
}

func (c *CompositeStore) CreateAuthorizeCodeSession(ctx context.Context, code string, req fosite.Requester) error {
	return c.CoreStorage.CreateAuthorizeCodeSession(ctx, code, req)
}

func (c *CompositeStore) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	return c.CoreStorage.GetAuthorizeCodeSession(ctx, code, session)
}

func (c *CompositeStore) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	return c.CoreStorage.InvalidateAuthorizeCodeSession(ctx, code)
}

func (c *CompositeStore) CreatePKCERequestSession(ctx context.Context, code string, req fosite.Requester) error {
	return c.CoreStorage.CreatePKCERequestSession(ctx, code, req)
}

func (c *CompositeStore) GetPKCERequestSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	return c.CoreStorage.GetPKCERequestSession(ctx, code, session)
}

func (c *CompositeStore) DeletePKCERequestSession(ctx context.Context, code string) error {
	return c.CoreStorage.DeletePKCERequestSession(ctx, code)
}

func (c *CompositeStore) CreateAccessTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	return c.CoreStorage.CreateAccessTokenSession(ctx, signature, req)
}

func (c *CompositeStore) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return c.CoreStorage.GetAccessTokenSession(ctx, signature, session)
}

func (c *CompositeStore) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return c.CoreStorage.DeleteAccessTokenSession(ctx, signature)
}

func (c *CompositeStore) CreateRefreshTokenSession(ctx context.Context, signature, accessTokenSignature string, req fosite.Requester) error {
	return c.CoreStorage.CreateRefreshTokenSession(ctx, signature, accessTokenSignature, req)
}

func (c *CompositeStore) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	return c.CoreStorage.GetRefreshTokenSession(ctx, signature, session)
}

func (c *CompositeStore) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return c.CoreStorage.DeleteRefreshTokenSession(ctx, signature)
}

func (c *CompositeStore) Authenticate(ctx context.Context, name string, secret string) (subject string, err error) {
	return c.CoreStorage.Authenticate(ctx, name, secret)
}

func (c *CompositeStore) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return c.CoreStorage.RevokeRefreshToken(ctx, requestID)
}

func (c *CompositeStore) RevokeAccessToken(ctx context.Context, requestID string) error {
	return c.CoreStorage.RevokeAccessToken(ctx, requestID)
}

func (c *CompositeStore) GetPublicKey(ctx context.Context, issuer string, subject string, keyId string) (*jose.JSONWebKey, error) {
	return c.CoreStorage.GetPublicKey(ctx, issuer, subject, keyId)
}

func (c *CompositeStore) GetPublicKeys(ctx context.Context, issuer string, subject string) (*jose.JSONWebKeySet, error) {
	return c.CoreStorage.GetPublicKeys(ctx, issuer, subject)
}

func (c *CompositeStore) GetPublicKeyScopes(ctx context.Context, issuer string, subject string, keyId string) ([]string, error) {
	return c.CoreStorage.GetPublicKeyScopes(ctx, issuer, subject, keyId)
}

func (c *CompositeStore) IsJWTUsed(ctx context.Context, jti string) (bool, error) {
	return c.CoreStorage.IsJWTUsed(ctx, jti)
}

func (c *CompositeStore) MarkJWTUsedForTime(ctx context.Context, jti string, exp time.Time) error {
	return c.CoreStorage.MarkJWTUsedForTime(ctx, jti, exp)
}

func (c *CompositeStore) CreatePARSession(ctx context.Context, requestURI string, request fosite.AuthorizeRequester) error {
	return c.CoreStorage.CreatePARSession(ctx, requestURI, request)
}

func (c *CompositeStore) GetPARSession(ctx context.Context, requestURI string) (fosite.AuthorizeRequester, error) {
	return c.CoreStorage.GetPARSession(ctx, requestURI)
}

func (c *CompositeStore) DeletePARSession(ctx context.Context, requestURI string) error {
	return c.CoreStorage.DeletePARSession(ctx, requestURI)
}

func (c *CompositeStore) RotateRefreshToken(ctx context.Context, requestID string, refreshTokenSignature string) error {
	return c.CoreStorage.RotateRefreshToken(ctx, requestID, refreshTokenSignature)
}

// Device flow delegates
func (c *CompositeStore) CreateDeviceAuthSession(ctx context.Context, deviceCodeSignature, userCodeSignature string, req fosite.DeviceRequester) error {
	return c.CoreStorage.CreateDeviceAuthSession(ctx, deviceCodeSignature, userCodeSignature, req)
}

func (c *CompositeStore) GetDeviceCodeSession(ctx context.Context, signature string, session fosite.Session) (fosite.DeviceRequester, error) {
	return c.CoreStorage.GetDeviceCodeSession(ctx, signature, session)
}

func (c *CompositeStore) InvalidateDeviceCodeSession(ctx context.Context, code string) error {
    return c.CoreStorage.InvalidateDeviceCodeSession(ctx, code)
}

// ValidateSubjectToken delegates to TokenStore (RFC8693Storage interface)
func (c *CompositeStore) ValidateSubjectToken(ctx context.Context, token string, tokenType string, client fosite.Client) (*rfc8693.TokenInfo, error) {
	var requester fosite.Requester
	var err error

	switch tokenType {
	case "access_token":
		requester, err = c.CoreStorage.GetAccessTokenSession(ctx, token, nil)
	case "refresh_token":
		requester, err = c.CoreStorage.GetRefreshTokenSession(ctx, token, nil)
	default:
		return nil, fosite.ErrNotFound
	}
	if requester == nil {
		return nil, fosite.ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	session := requester.GetSession()
    subject := session.GetSubject()
    scopes := requester.GetGrantedScopes()
    issuedAt := requester.GetRequestedAt()
    audiences := requester.GetGrantedAudience()

    // Get the expiry for the access token or refresh token
    var expiresAt time.Time
    switch tokenType {
    case "access_token":
        expiresAt = session.GetExpiresAt(fosite.AccessToken)
    case "refresh_token":
        expiresAt = session.GetExpiresAt(fosite.RefreshToken)
    default:
        expiresAt = time.Time{}
    }

    return &rfc8693.TokenInfo{
        TokenType: tokenType,
        Subject:   subject,
        Scopes:    scopes,
        ExpiresAt: expiresAt.Unix(),
        IssuedAt:  issuedAt.Unix(),
        Audiences: audiences,
    }, nil
}

// ValidateActorToken delegates to TokenStore (RFC8693Storage interface)
func (c *CompositeStore) ValidateActorToken(ctx context.Context, token string, tokenType string, client fosite.Client) (*rfc8693.TokenInfo, error) {
	return c.ValidateSubjectToken(ctx, token, tokenType, client)
}

// StoreTokenExchange implements RFC8693Storage interface with correct signature
func (c *CompositeStore) StoreTokenExchange(ctx context.Context, request *rfc8693.TokenExchangeRequest, response *rfc8693.TokenExchangeResponse) error {
	// For now, just log the exchange for audit trail
	if response.IssuedTokenType != "" {
		// Successfully exchanged token
		log.Printf("✅ Token exchange successful: IssuedTokenType=%s",
			response.IssuedTokenType)

	} else {
		// Failed token exchange
		log.Printf("❌ Token exchange failed")
	}

	return nil
}
