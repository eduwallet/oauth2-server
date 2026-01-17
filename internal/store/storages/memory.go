package storages

import (
	"context"
	"fmt"
	"time"

	"oauth2-server/internal/store/types"
	"oauth2-server/pkg/config"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"github.com/sirupsen/logrus"
)

// UpstreamTokenMapping stores upstream token information for proxy tokens
type UpstreamTokenMapping struct {
	UpstreamAccessToken  string
	UpstreamRefreshToken string
	UpstreamTokenType    string
	UpstreamExpiresIn    int64
	CreatedAt            time.Time
}

// MemoryStoreWrapper wraps fosite's MemoryStore to implement our Storage interface
type MemoryStoreWrapper struct {
	*storage.MemoryStore
	clientSecrets         map[string]string
	attestationConfigs    map[string]*config.ClientAttestationConfig
	trustAnchors          map[string][]byte
	upstreamTokenMappings map[string]*UpstreamTokenMapping
	parRequests           map[string]*types.PARRequest
	logger                *logrus.Logger
}

// NewMemoryStoreWrapper creates a new MemoryStoreWrapper with initialized maps
func NewMemoryStoreWrapper(memoryStore *storage.MemoryStore, logger *logrus.Logger) *MemoryStoreWrapper {
	return &MemoryStoreWrapper{
		MemoryStore:           memoryStore,
		clientSecrets:         make(map[string]string),
		attestationConfigs:    make(map[string]*config.ClientAttestationConfig),
		trustAnchors:          make(map[string][]byte),
		upstreamTokenMappings: make(map[string]*UpstreamTokenMapping),
		parRequests:           make(map[string]*types.PARRequest),
		logger:                logger,
	}
}

// Client management methods
func (m *MemoryStoreWrapper) CreateClient(ctx context.Context, client fosite.Client) error {
	m.MemoryStore.Clients[client.GetID()] = client
	return nil
}

func (m *MemoryStoreWrapper) UpdateClient(ctx context.Context, id string, client fosite.Client) error {
	m.MemoryStore.Clients[id] = client
	return nil
}

func (m *MemoryStoreWrapper) DeleteClient(ctx context.Context, id string) error {
	delete(m.MemoryStore.Clients, id)
	return nil
}

// Add GetUser method that MemoryStore has but our interface requires
func (m *MemoryStoreWrapper) GetUser(ctx context.Context, id string) (*storage.MemoryUserRelation, error) {
	user, exists := m.MemoryStore.Users[id]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}
	return &user, nil
}

// Implement missing methods that MemoryStore doesn't have
func (m *MemoryStoreWrapper) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) error {
	return m.MemoryStore.CreateAccessTokenSession(ctx, signature, request)
}

func (m *MemoryStoreWrapper) CreateRefreshTokenSession(ctx context.Context, signature string, accessTokenSignature string, request fosite.Requester) error {
	return m.MemoryStore.CreateRefreshTokenSession(ctx, signature, accessTokenSignature, request)
}

func (m *MemoryStoreWrapper) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) error {
	return m.MemoryStore.CreateAuthorizeCodeSession(ctx, code, request)
}

func (m *MemoryStoreWrapper) CreatePKCERequestSession(ctx context.Context, code string, request fosite.Requester) error {
	return m.MemoryStore.CreatePKCERequestSession(ctx, code, request)
}

func (m *MemoryStoreWrapper) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	return m.MemoryStore.GetAuthorizeCodeSession(ctx, code, session)
}

func (m *MemoryStoreWrapper) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	return m.MemoryStore.InvalidateAuthorizeCodeSession(ctx, code)
}

func (m *MemoryStoreWrapper) GetPKCERequestSession(ctx context.Context, code string, session fosite.Session) (fosite.Requester, error) {
	return m.MemoryStore.GetPKCERequestSession(ctx, code, session)
}

func (m *MemoryStoreWrapper) DeletePKCERequestSession(ctx context.Context, code string) error {
	return m.MemoryStore.DeletePKCERequestSession(ctx, code)
}

func (m *MemoryStoreWrapper) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return m.MemoryStore.ClientAssertionJWTValid(ctx, jti)
}

func (m *MemoryStoreWrapper) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return m.MemoryStore.SetClientAssertionJWT(ctx, jti, exp)
}

// Device authorization methods
func (m *MemoryStoreWrapper) GetDeviceCodeSession(ctx context.Context, deviceCode string, session fosite.Session) (fosite.DeviceRequester, error) {
	return m.MemoryStore.GetDeviceCodeSession(ctx, deviceCode, session)
}

func (m *MemoryStoreWrapper) CreateDeviceCodeSession(ctx context.Context, deviceCode string, request fosite.Requester) error {
	// MemoryStore uses DeviceAuths map directly
	if deviceReq, ok := request.(fosite.DeviceRequester); ok {
		m.MemoryStore.DeviceAuths[deviceCode] = deviceReq
		return nil
	}
	return fmt.Errorf("request is not a DeviceRequester")
}

func (m *MemoryStoreWrapper) UpdateDeviceCodeSession(ctx context.Context, deviceCode string, request fosite.Requester) error {
	if deviceReq, ok := request.(fosite.DeviceRequester); ok {
		m.MemoryStore.DeviceAuths[deviceCode] = deviceReq
		return nil
	}
	return fmt.Errorf("request is not a DeviceRequester")
}

func (m *MemoryStoreWrapper) InvalidateDeviceCodeSession(ctx context.Context, signature string) error {
	return m.MemoryStore.InvalidateDeviceCodeSession(ctx, signature)
}

func (m *MemoryStoreWrapper) GetPendingDeviceAuths(ctx context.Context) (map[string]fosite.Requester, error) {
	pending := make(map[string]fosite.Requester)
	for deviceCode, auth := range m.MemoryStore.DeviceAuths {
		// Check if it's still pending (no session or empty username)
		session := auth.GetSession()
		if session == nil || session.GetUsername() == "" {
			pending[deviceCode] = auth
		}
	}
	return pending, nil
}

func (m *MemoryStoreWrapper) GetDeviceAuthByUserCode(ctx context.Context, userCode string) (fosite.DeviceRequester, string, error) {
	// In memory store, we need to search through all device auths to find one with matching user code
	// This is inefficient but works for the memory store
	for deviceCode, auth := range m.MemoryStore.DeviceAuths {
		// We can't easily get the user code from the device auth in memory store
		// For now, return the first pending auth (same as before)
		session := auth.GetSession()
		if session == nil || session.GetUsername() == "" {
			return auth, deviceCode, nil
		}
	}
	return nil, "", fmt.Errorf("device authorization not found for user code: %s", userCode)
}

func (m *MemoryStoreWrapper) CreateDeviceAuthSession(ctx context.Context, deviceCodeSignature, userCodeSignature string, request fosite.DeviceRequester) error {
	return m.MemoryStore.CreateDeviceAuthSession(ctx, deviceCodeSignature, userCodeSignature, request)
}

// Statistics methods
func (m *MemoryStoreWrapper) GetClientCount() (int, error) {
	return len(m.MemoryStore.Clients), nil
}

func (m *MemoryStoreWrapper) GetUserCount() (int, error) {
	return len(m.MemoryStore.Users), nil
}

func (m *MemoryStoreWrapper) GetAccessTokenCount() (int, error) {
	return len(m.MemoryStore.AccessTokens), nil
}

func (m *MemoryStoreWrapper) GetRefreshTokenCount() (int, error) {
	return len(m.MemoryStore.RefreshTokens), nil
}

// Secure client data storage methods (for memory store, we store in memory but warn about persistence)
func (m *MemoryStoreWrapper) StoreClientSecret(ctx context.Context, clientID string, encryptedSecret string) error {
	m.clientSecrets[clientID] = encryptedSecret
	m.logger.Warnf("⚠️  [MEMORY STORE] Client secret stored in memory for client %s - this will be lost on restart", clientID)
	return nil
}

func (m *MemoryStoreWrapper) GetClientSecret(ctx context.Context, clientID string) (string, error) {
	secret, exists := m.clientSecrets[clientID]
	if !exists {
		return "", fmt.Errorf("client secret not found")
	}
	m.logger.Warnf("⚠️  [MEMORY STORE] Retrieved client secret from memory for client %s - this data is not persistent", clientID)
	return secret, nil
}

func (m *MemoryStoreWrapper) StoreAttestationConfig(ctx context.Context, clientID string, config *config.ClientAttestationConfig) error {
	m.attestationConfigs[clientID] = config
	m.logger.Warnf("⚠️  [MEMORY STORE] Attestation config stored in memory for client %s - this will be lost on restart", clientID)
	return nil
}

func (m *MemoryStoreWrapper) GetAttestationConfig(ctx context.Context, clientID string) (*config.ClientAttestationConfig, error) {
	config, exists := m.attestationConfigs[clientID]
	if !exists {
		return nil, fmt.Errorf("attestation config not found")
	}
	m.logger.Warnf("⚠️  [MEMORY STORE] Retrieved attestation config from memory for client %s - this data is not persistent", clientID)
	return config, nil
}

func (m *MemoryStoreWrapper) DeleteClientSecret(ctx context.Context, clientID string) error {
	delete(m.clientSecrets, clientID)
	m.logger.Warnf("⚠️  [MEMORY STORE] Client secret deleted from memory for client %s", clientID)
	return nil
}

func (m *MemoryStoreWrapper) DeleteAttestationConfig(ctx context.Context, clientID string) error {
	delete(m.attestationConfigs, clientID)
	m.logger.Warnf("⚠️  [MEMORY STORE] Attestation config deleted from memory for client %s", clientID)
	return nil
}

// Trust anchor storage methods
func (m *MemoryStoreWrapper) StoreTrustAnchor(ctx context.Context, name string, certificateData []byte) error {
	m.trustAnchors[name] = certificateData
	m.logger.Warnf("⚠️  [MEMORY STORE] Trust anchor stored in memory for %s - this will be lost on restart", name)
	return nil
}

func (m *MemoryStoreWrapper) GetTrustAnchor(ctx context.Context, name string) ([]byte, error) {
	data, exists := m.trustAnchors[name]
	if !exists {
		return nil, fmt.Errorf("trust anchor not found")
	}
	m.logger.Warnf("⚠️  [MEMORY STORE] Retrieved trust anchor from memory for %s - this data is not persistent", name)
	return data, nil
}

func (m *MemoryStoreWrapper) ListTrustAnchors(ctx context.Context) ([]string, error) {
	names := make([]string, 0, len(m.trustAnchors))
	for name := range m.trustAnchors {
		names = append(names, name)
	}
	m.logger.Warnf("⚠️  [MEMORY STORE] Listed trust anchors from memory - this data is not persistent")
	return names, nil
}

func (m *MemoryStoreWrapper) DeleteTrustAnchor(ctx context.Context, name string) error {
	if _, exists := m.trustAnchors[name]; !exists {
		return fmt.Errorf("trust anchor not found")
	}
	delete(m.trustAnchors, name)
	m.logger.Warnf("⚠️  [MEMORY STORE] Trust anchor deleted from memory for %s - this data is not persistent", name)
	return nil
}

// Upstream token mapping methods for proxy mode
func (m *MemoryStoreWrapper) StoreUpstreamTokenMapping(ctx context.Context, proxyTokenSignature string, upstreamAccessToken string, upstreamRefreshToken string, upstreamTokenType string, upstreamExpiresIn int64) error {
	m.upstreamTokenMappings[proxyTokenSignature] = &UpstreamTokenMapping{
		UpstreamAccessToken:  upstreamAccessToken,
		UpstreamRefreshToken: upstreamRefreshToken,
		UpstreamTokenType:    upstreamTokenType,
		UpstreamExpiresIn:    upstreamExpiresIn,
		CreatedAt:            time.Now(),
	}
	m.logger.Warnf("⚠️  [MEMORY STORE] Upstream token mapping stored in memory for proxy token %s - this will be lost on restart", proxyTokenSignature)
	return nil
}

func (m *MemoryStoreWrapper) GetUpstreamTokenMapping(ctx context.Context, proxyTokenSignature string) (upstreamAccessToken string, upstreamRefreshToken string, upstreamTokenType string, upstreamExpiresIn int64, err error) {
	mapping, exists := m.upstreamTokenMappings[proxyTokenSignature]
	if !exists {
		return "", "", "", 0, fmt.Errorf("upstream token mapping not found")
	}
	m.logger.Warnf("⚠️  [MEMORY STORE] Retrieved upstream token mapping from memory for proxy token %s - this data is not persistent", proxyTokenSignature)
	return mapping.UpstreamAccessToken, mapping.UpstreamRefreshToken, mapping.UpstreamTokenType, mapping.UpstreamExpiresIn, nil
}

func (m *MemoryStoreWrapper) DeleteUpstreamTokenMapping(ctx context.Context, proxyTokenSignature string) error {
	if _, exists := m.upstreamTokenMappings[proxyTokenSignature]; !exists {
		return fmt.Errorf("upstream token mapping not found")
	}
	delete(m.upstreamTokenMappings, proxyTokenSignature)
	m.logger.Warnf("⚠️  [MEMORY STORE] Upstream token mapping deleted from memory for proxy token %s - this data is not persistent", proxyTokenSignature)
	return nil
}

// PAR methods
func (m *MemoryStoreWrapper) StorePARRequest(ctx context.Context, request *types.PARRequest) error {
	m.parRequests[request.RequestURI] = request
	m.logger.Warnf("⚠️  [MEMORY STORE] PAR request stored in memory for URI %s - this data is not persistent", request.RequestURI)
	return nil
}

func (m *MemoryStoreWrapper) GetPARRequest(ctx context.Context, requestURI string) (*types.PARRequest, error) {
	request, exists := m.parRequests[requestURI]
	if !exists {
		return nil, fmt.Errorf("PAR request not found")
	}
	if time.Now().After(request.ExpiresAt) {
		// Clean up expired request
		delete(m.parRequests, requestURI)
		return nil, fmt.Errorf("PAR request expired")
	}
	return request, nil
}

func (m *MemoryStoreWrapper) DeletePARRequest(ctx context.Context, requestURI string) error {
	if _, exists := m.parRequests[requestURI]; !exists {
		return fmt.Errorf("PAR request not found")
	}
	delete(m.parRequests, requestURI)
	m.logger.Warnf("⚠️  [MEMORY STORE] PAR request deleted from memory for URI %s - this data is not persistent", requestURI)
	return nil
}
