package flows

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"oauth2-server/internal/auth"
	"oauth2-server/internal/models"
	"oauth2-server/internal/store"
	"oauth2-server/internal/utils"
	"oauth2-server/pkg/config"
)

// DeviceCodeFlow handles the device authorization flow (RFC 8628)
type DeviceCodeFlow struct {
	clientStore      *store.ClientStore
	config           *config.Config
	deviceAuths      map[string]*models.DeviceAuthorization
	userCodeToDevice map[string]string
	mutex            sync.RWMutex
	tokenStore       *store.TokenStore
}

// NewDeviceCodeFlow creates a new device code flow handler
func NewDeviceCodeFlow(clientStore *store.ClientStore, tokenStore *store.TokenStore, config *config.Config) *DeviceCodeFlow {
	return &DeviceCodeFlow{
		clientStore:      clientStore,
		tokenStore:       tokenStore,
		config:           config,
		deviceAuths:      make(map[string]*models.DeviceAuthorization),
		userCodeToDevice: make(map[string]string),
	}
}

// HandleAuthorization handles device authorization requests
func (f *DeviceCodeFlow) HandleAuthorization(w http.ResponseWriter, r *http.Request) {
	log.Printf("🎯 Processing device authorization request")

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the request
	if err := r.ParseForm(); err != nil {
		utils.WriteErrorResponse(w, "invalid_request", "Failed to parse request")
		return
	}

	clientID := r.FormValue("client_id")
	scope := r.FormValue("scope")

	if clientID == "" {
		utils.WriteErrorResponse(w, "invalid_request", "client_id is required")
		return
	}

	// Validate client with context
	ctx := context.Background()
	client, err := f.clientStore.GetClient(ctx, clientID)
	if err != nil {
		utils.WriteErrorResponse(w, "invalid_client", "Invalid client")
		return
	}

	// Check if client supports device flow
	if !f.clientSupportsDeviceFlow(client) {
		utils.WriteErrorResponse(w, "unauthorized_client", "Client not authorized for device flow")
		return
	}

	// Generate device code and user code
	deviceCode, err := f.generateDeviceCode()
	if err != nil {
		utils.WriteServerError(w, "Failed to generate device code")
		return
	}

	userCode, err := f.generateUserCode()
	if err != nil {
		utils.WriteServerError(w, "Failed to generate user code")
		return
	}

	// Parse and validate scopes
	requestedScopes := utils.SplitScopes(scope)
	if len(requestedScopes) == 0 {
		requestedScopes = []string{"openid"} // Default scope
	}

	// Store device authorization
	expiresAt := time.Now().Add(time.Duration(f.config.Security.DeviceCodeExpirySeconds) * time.Second)
	deviceAuth := &models.DeviceAuthorization{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   clientID,
		Scopes:     requestedScopes,
		ExpiresAt:  expiresAt,
		IssuedAt:   time.Now(),
		Authorized: false,
		Used:       false,
	}

	f.mutex.Lock()
	f.deviceAuths[deviceCode] = deviceAuth
	f.userCodeToDevice[userCode] = deviceCode
	f.mutex.Unlock()

	// Create response with verification_uri_complete
	baseURL := f.config.BaseURL
	if baseURL == "" {
		baseURL = utils.GetRequestBaseURL(r)
	}

	verificationURI := fmt.Sprintf("%s/device", baseURL)
	verificationURIComplete := fmt.Sprintf("%s/device?user_code=%s", baseURL, userCode)

	response := map[string]interface{}{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURIComplete,
		"expires_in":                expiresAt,
		"interval":                  5, // Polling interval in seconds
	}

	log.Printf("✅ Device authorization created for client: %s, user code: %s", clientID, userCode)
	log.Printf("📱 Verification URI: %s", verificationURI)
	log.Printf("🔗 Complete URI: %s", verificationURIComplete)

	// Write response
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(response)
}

// HandleToken handles device token requests
func (f *DeviceCodeFlow) HandleToken(w http.ResponseWriter, r *http.Request) {
	log.Printf("🎯 Processing device token request")

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse the request
	if err := r.ParseForm(); err != nil {
		utils.WriteErrorResponse(w, "invalid_request", "Failed to parse request")
		return
	}

	grantType := r.FormValue("grant_type")
	deviceCode := r.FormValue("device_code")
	clientID := r.FormValue("client_id")

	if grantType != "urn:ietf:params:oauth:grant-type:device_code" {
		utils.WriteUnsupportedGrantTypeError(w, "Grant type must be device_code")
		return
	}

	if deviceCode == "" {
		utils.WriteInvalidRequestError(w, "device_code is required")
		return
	}

	// Validate client with context
	ctx := context.Background()
	_, err := f.clientStore.GetClient(ctx, clientID)
	if err != nil {
		utils.WriteInvalidClientError(w, "Invalid client")
		return
	}

	// Get device authorization
	f.mutex.RLock()
	deviceAuth, exists := f.deviceAuths[deviceCode]
	f.mutex.RUnlock()

	if !exists {
		utils.WriteInvalidGrantError(w, "Invalid device code")
		return
	}

	// Check if device code has expired
	if time.Now().After(deviceAuth.ExpiresAt.Add(time.Duration(f.config.Security.DeviceCodeExpirySeconds) * time.Second)) {
		f.mutex.Lock()
		delete(f.deviceAuths, deviceCode)
		delete(f.userCodeToDevice, deviceAuth.UserCode)
		f.mutex.Unlock()
		utils.WriteInvalidGrantError(w, "Device code has expired")
		return
	}

	// Check device status
	if deviceAuth.IsPending() {
		// Return authorization_pending error per RFC 8628
		utils.WriteErrorResponse(w, "authorization_pending", "User has not yet authorized the device")
		return
	}

	if !deviceAuth.CanIssueToken() {
		if deviceAuth.Used {
			utils.WriteInvalidGrantError(w, "Device code already used")
		} else {
			utils.WriteInvalidGrantError(w, "Device not authorized")
		}
		return
	}

	// Generate access token using high-level function (and store it)
	expiresIn := time.Duration(f.config.Security.TokenExpirySeconds) * time.Second
	accessToken, err := auth.GenerateAccessToken(f.tokenStore, deviceAuth.UserID, deviceAuth.ClientID, deviceAuth.Scopes, expiresIn)
	if err != nil {
		log.Printf("❌ Error generating access token: %v", err)
		utils.WriteServerError(w, "Failed to generate access token")
		return
	}

	refreshToken, err := auth.GenerateRefreshToken(f.tokenStore, deviceAuth.UserID, deviceAuth.ClientID, deviceAuth.Scopes, expiresIn)
	if err != nil {
		log.Printf("❌ Error generating refresh token: %v", err)
		utils.WriteServerError(w, "Failed to generate refresh token")
		return
	}

	// Create token response
	tokenResponse := map[string]interface{}{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    expiresIn,
		"refresh_token": refreshToken,
		"scope":         utils.JoinScopes(deviceAuth.Scopes),
	}

	// Mark device as used
	f.mutex.Lock()
	deviceAuth.Used = true
	deviceAuth.AccessToken = accessToken
	deviceAuth.RefreshToken = refreshToken
	deviceAuth.TokenType = "Bearer"
	f.mutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(tokenResponse)

	log.Printf("✅ Access token issued for device: %s, user: %s", deviceCode, deviceAuth.UserID)
}

// AuthorizeDevice authorizes a device with user code
func (f *DeviceCodeFlow) AuthorizeDevice(userCode, userID string) bool {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	deviceCode, exists := f.userCodeToDevice[userCode]
	if !exists {
		return false
	}

	deviceAuth, exists := f.deviceAuths[deviceCode]
	if !exists {
		return false
	}

	// Check if expired
	if deviceAuth.IsExpired() {
		delete(f.deviceAuths, deviceCode)
		delete(f.userCodeToDevice, userCode)
		return false
	}

	// Authorize the device
	deviceAuth.Authorized = true
	deviceAuth.UserID = userID

	log.Printf("✅ Device authorized: code=%s, user=%s", userCode, userID)
	return true
}

// clientSupportsDeviceFlow checks if a client supports device flow
func (f *DeviceCodeFlow) clientSupportsDeviceFlow(client interface{}) bool {
	// You would implement this based on your client model
	// For now, return true if client exists
	return client != nil
}

// generateDeviceCode generates a unique device code
func (f *DeviceCodeFlow) generateDeviceCode() (string, error) {
	// Generate a random device code (longer and more secure)
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length = 32

	result := make([]byte, length)
	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[num.Int64()]
	}

	return string(result), nil
}

// generateUserCode generates a user-friendly code
func (f *DeviceCodeFlow) generateUserCode() (string, error) {
	// Generate a short, user-friendly code (e.g., "ABCD-1234")
	const charset = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // Exclude confusing characters
	const length = 8

	result := make([]byte, length)
	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[num.Int64()]
	}

	// Format as XXXX-XXXX for better readability
	code := string(result)
	return fmt.Sprintf("%s-%s", code[:4], code[4:]), nil
}

// GetDeviceAuthByUserCode retrieves device authorization by user code
func (f *DeviceCodeFlow) GetDeviceAuthByUserCode(userCode string) (*models.DeviceAuthorization, bool) {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	deviceCode, exists := f.userCodeToDevice[userCode]
	if !exists {
		return nil, false
	}

	deviceAuth, exists := f.deviceAuths[deviceCode]
	return deviceAuth, exists
}

// GetDeviceAuthByDeviceCode retrieves device authorization by device code
func (f *DeviceCodeFlow) GetDeviceAuthByDeviceCode(deviceCode string) (*models.DeviceAuthorization, bool) {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	deviceAuth, exists := f.deviceAuths[deviceCode]
	return deviceAuth, exists
}

// CleanupExpiredDeviceCodes removes expired device codes
func (f *DeviceCodeFlow) CleanupExpiredDeviceCodes() {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	now := time.Now()
	var expiredCodes []string

	for deviceCode, deviceAuth := range f.deviceAuths {
		if now.After(deviceAuth.ExpiresAt) {
			expiredCodes = append(expiredCodes, deviceCode)
		}
	}

	for _, deviceCode := range expiredCodes {
		deviceAuth := f.deviceAuths[deviceCode]
		delete(f.deviceAuths, deviceCode)
		delete(f.userCodeToDevice, deviceAuth.UserCode)
		log.Printf("🗑️ Cleaned up expired device code: %s", deviceAuth.UserCode)
	}

	if len(expiredCodes) > 0 {
		log.Printf("🗑️ Cleaned up %d expired device codes", len(expiredCodes))
	}
}

// StartCleanupTimer starts a background cleanup timer for expired device codes
func (f *DeviceCodeFlow) StartCleanupTimer() {
	go func() {
		ticker := time.NewTicker(5 * time.Minute) // Clean up every 5 minutes
		defer ticker.Stop()

		for range ticker.C {
			f.CleanupExpiredDeviceCodes()
		}
	}()
	log.Printf("🗑️ Device code cleanup timer started")
}

// GetDeviceStats returns statistics about device authorizations
func (f *DeviceCodeFlow) GetDeviceStats() map[string]interface{} {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	var pending, authorized, used, expired int
	now := time.Now()

	for _, deviceAuth := range f.deviceAuths {
		if now.After(deviceAuth.ExpiresAt) {
			expired++
		} else if deviceAuth.Used {
			used++
		} else if deviceAuth.Authorized {
			authorized++
		} else {
			pending++
		}
	}

	return map[string]interface{}{
		"total":      len(f.deviceAuths),
		"pending":    pending,
		"authorized": authorized,
		"used":       used,
		"expired":    expired,
	}
}
