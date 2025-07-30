package flows

import (
	"oauth2-server/internal/store"
	"oauth2-server/pkg/config"
)

// TokenExchangeFlow handles RFC 8693 token exchange
type TokenExchangeFlow struct {
	clientStore *store.ClientStore
	tokenStore  *store.TokenStore
	config      *config.Config
}

// NewTokenExchangeFlow creates a new token exchange flow handler
func NewTokenExchangeFlow(clientStore *store.ClientStore, tokenStore *store.TokenStore, cfg *config.Config) *TokenExchangeFlow {
	return &TokenExchangeFlow{
		clientStore: clientStore,
		tokenStore:  tokenStore,
		config:      cfg,
	}
}
