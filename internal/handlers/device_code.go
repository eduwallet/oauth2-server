package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"oauth2-server/pkg/config"
	"strings"
	"sync"
	"time"

	"github.com/ory/fosite"
	"github.com/sirupsen/logrus"
)

// responseWriter captures and modifies device authorization responses
type responseWriter struct {
	http.ResponseWriter
	baseURL string
	buf     *bytes.Buffer
}

func (rw *responseWriter) Write(data []byte) (int, error) {
	if rw.buf == nil {
		rw.buf = &bytes.Buffer{}
	}
	return rw.buf.Write(data)
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	// Don't write the header yet, we'll do it after modifying the response
}

func (rw *responseWriter) finish() {
	if rw.buf == nil {
		return
	}

	// Parse the JSON response
	var response map[string]interface{}
	if err := json.Unmarshal(rw.buf.Bytes(), &response); err != nil {
		// If we can't parse it, just write the original response
		rw.ResponseWriter.Write(rw.buf.Bytes())
		return
	}

	// Modify the verification URIs
	response["verification_uri"] = rw.baseURL + "/device"
	if userCode, exists := response["user_code"]; exists {
		response["verification_uri_complete"] = rw.baseURL + "/device?user_code=" + userCode.(string)
	}

	// Write the modified response
	rw.ResponseWriter.Header().Set("Content-Type", "application/json")
	rw.ResponseWriter.Header().Set("Cache-Control", "no-store")
	rw.ResponseWriter.Header().Set("Pragma", "no-cache")
	json.NewEncoder(rw.ResponseWriter).Encode(response)
}

// DeviceCodeHandler handles all operations related to the device authorization grant
type DeviceCodeHandler struct {
	OAuth2Provider fosite.OAuth2Provider
	Templates      *template.Template
	Config         *config.Config
	Logger         *logrus.Logger
}

// NewDeviceCodeHandler creates a new DeviceCodeHandler
func NewDeviceCodeHandler(
	provider fosite.OAuth2Provider,
	templates *template.Template,
	config *config.Config,
	logger *logrus.Logger,
) *DeviceCodeHandler {
	return &DeviceCodeHandler{
		OAuth2Provider: provider,
		Templates:      templates,
		Config:         config,
		Logger:         logger,
	}
}

// HandleDeviceAuthorization handles the device authorization request (RFC 8628)
// This is the endpoint that clients call to start the device flow
func (h *DeviceCodeHandler) HandleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse form for fosite
	if err := r.ParseForm(); err != nil {
		h.Logger.WithError(err).Error("Failed to parse form")
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Debug: Log the request details (fosite will extract client ID from Auth header)
	scope := r.FormValue("scope")
	h.Logger.Infof("🔍 Device authorization request - Scope: %s", scope)

	// Debug: Check authentication method
	authHeader := r.Header.Get("Authorization")
	if authHeader != "" {
		truncated := authHeader
		if len(authHeader) > 20 {
			truncated = authHeader[:20] + "..."
		}
		h.Logger.Infof("🔐 Authorization header present: %s", truncated)
	} else {
		h.Logger.Info("⚠️ No Authorization header found")
	}

	// Debug: Check all form values
	h.Logger.Infof("📝 Form values: %v", r.Form)

	// Since fosite v0.42.2 might not have built-in device flow support,
	// we'll implement a simple device authorization flow manually

	// First, authenticate the client if required
	clientID := r.FormValue("client_id")
	if clientID == "" {
		// Try to get client from Authorization header
		if client, err := h.authenticateClient(ctx, r); err == nil {
			clientID = client.GetID()
		} else {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client", "error_description": "Client authentication failed"})
			return
		}
	}

	// Validate the client
	client, err := h.getClient(ctx, clientID)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "invalid_client", "error_description": "Unknown client"})
		return
	}

	// Check if client supports device flow
	if !client.GetGrantTypes().Has("urn:ietf:params:oauth:grant-type:device_code") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "unsupported_grant_type", "error_description": "Client does not support device code flow"})
		return
	}

	// Generate device code and user code
	deviceCode, err := h.generateDeviceCode()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "server_error", "error_description": "Failed to generate device code"})
		return
	}

	userCode, err := h.generateUserCode()
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "server_error", "error_description": "Failed to generate user code"})
		return
	}

	// Store the device authorization
	err = h.storeDeviceAuthorization(deviceCode, userCode, clientID, r.FormValue("scope"))
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": "server_error", "error_description": "Failed to store device authorization"})
		return
	}

	h.Logger.Infof("🔍 Device authorization request created for client: %s", clientID)

	// Build the response
	baseURL := h.Config.GetEffectiveBaseURL(r)
	response := map[string]interface{}{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          baseURL + "/device",
		"verification_uri_complete": baseURL + "/device?user_code=" + userCode,
		"expires_in":                600, // 10 minutes
		"interval":                  5,   // 5 seconds
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	json.NewEncoder(w).Encode(response)
}

// ShowVerificationPage displays the page where users enter the user code
func (h *DeviceCodeHandler) ShowVerificationPage(w http.ResponseWriter, r *http.Request) {
	userCode := r.URL.Query().Get("user_code")
	errorMsg := r.URL.Query().Get("error")

	// Get device code expiry from configuration (default to 600 seconds)
	expiresIn := 600
	if h.Config.YAMLConfig != nil && h.Config.YAMLConfig.Security.DeviceCodeExpirySeconds > 0 {
		expiresIn = h.Config.YAMLConfig.Security.DeviceCodeExpirySeconds
	}

	data := map[string]interface{}{
		"UserCode":   userCode,
		"Error":      errorMsg,
		"ExpiresIn":  expiresIn,
		"Interval":   5,  // Default polling interval
		"DeviceCode": "", // Not needed for manual verification
	}

	if err := h.Templates.ExecuteTemplate(w, "device.html", data); err != nil {
		h.Logger.WithError(err).Error("Failed to render device verification template")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// HandleVerification processes the user's login and consent for a device
func (h *DeviceCodeHandler) HandleVerification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/device?error=Invalid+request", http.StatusFound)
		return
	}

	userCode := r.FormValue("user_code")
	username := r.FormValue("username")
	password := r.FormValue("password")

	h.Logger.Infof("🔍 Processing verification for user code: %s, username: %s", userCode, username)

	// Authenticate user
	user := h.authenticateUser(username, password)
	if user == nil {
		http.Redirect(w, r, "/device?error=Invalid+credentials&user_code="+userCode, http.StatusFound)
		return
	}

	h.Logger.Infof("✅ User %s authenticated successfully for user code: %s", user.Username, userCode)

	// Complete the device user authentication flow using our custom storage
	h.Logger.Infof("🔍 Processing verification for user code: %s, username: %s", userCode, username)

	// Find the device authorization by user code
	deviceAuth := h.findDeviceAuthByUserCode(userCode)
	if deviceAuth == nil {
		h.Logger.Errorf("❌ Device authorization not found for user code: %s", userCode)
		http.Redirect(w, r, "/device?error=Invalid+or+expired+user+code&user_code="+userCode, http.StatusFound)
		return
	}

	// Authorize the device with the authenticated user
	err := h.authorizeDevice(userCode, user.ID)
	if err != nil {
		h.Logger.WithError(err).Errorf("❌ Failed to authorize device for user code: %s", userCode)
		http.Redirect(w, r, "/device?error=Authorization+failed&user_code="+userCode, http.StatusFound)
		return
	}

	h.Logger.Infof("✅ Device authorization completed for user code: %s", userCode)
	h.Logger.Infof("✅ Device verification completed successfully for user code: %s", userCode)

	// Show success page - user has provided consent and device is authorized
	h.showSuccessPage(w, r)
}

// authenticateUser checks user credentials against the configured users
func (h *DeviceCodeHandler) authenticateUser(username, password string) *config.User {
	for _, user := range h.Config.Users {
		if user.Username == username && user.Password == password {
			h.Logger.Infof("✅ User authenticated successfully: %s", username)
			return &user
		}
	}
	h.Logger.Warnf("⚠️ Authentication failed for user: %s", username)
	return nil
}

// showSuccessPage displays a success message after device verification
func (h *DeviceCodeHandler) showSuccessPage(w http.ResponseWriter, r *http.Request) {
	h.Logger.Info("🎯 Attempting to show success page")

	data := map[string]interface{}{
		"Success": true,
		"Message": "Device has been successfully authorized",
	}

	h.Logger.Info("📄 About to execute device_success.html template")
	if err := h.Templates.ExecuteTemplate(w, "device_success.html", data); err != nil {
		h.Logger.WithError(err).Error("❌ Failed to render device success template")
		// Instead of http.Error, let's try a simple response
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<html>
			<head><title>Success</title></head>
			<body>
				<h1>✅ Authorization Successful!</h1>
				<p>Your device has been successfully authorized.</p>
				<p>You can now return to your device and continue using the application.</p>
			</body>
			</html>
		`))
		return
	}
	h.Logger.Info("✅ Successfully rendered device success page")
}

// Helper methods for device authorization

// DeviceAuth represents a device authorization entry
type DeviceAuth struct {
	DeviceCode string
	UserCode   string
	ClientID   string
	Scope      string
	ExpiresAt  time.Time
	IsUsed     bool
	UserID     string
	Mutex      sync.RWMutex
}

// In-memory storage for device authorizations
var deviceAuths = make(map[string]*DeviceAuth)
var deviceAuthsMutex sync.RWMutex

func (h *DeviceCodeHandler) authenticateClient(ctx context.Context, r *http.Request) (fosite.Client, error) {
	if fositeProvider, ok := h.OAuth2Provider.(*fosite.Fosite); ok {
		return fositeProvider.AuthenticateClient(ctx, r, r.Form)
	}
	return nil, fmt.Errorf("unsupported OAuth2 provider type")
}

func (h *DeviceCodeHandler) getClient(ctx context.Context, clientID string) (fosite.Client, error) {
	if fositeProvider, ok := h.OAuth2Provider.(*fosite.Fosite); ok {
		return fositeProvider.Store.GetClient(ctx, clientID)
	}
	return nil, fmt.Errorf("unsupported OAuth2 provider type")
}

func (h *DeviceCodeHandler) generateDeviceCode() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return "ory_dc_" + hex.EncodeToString(bytes), nil
}

func (h *DeviceCodeHandler) generateUserCode() (string, error) {
	bytes := make([]byte, 4)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	// Convert to uppercase letters/digits for easier user input
	encoded := hex.EncodeToString(bytes)
	userCode := strings.ToUpper(encoded)[:8]
	return userCode, nil
}

func (h *DeviceCodeHandler) storeDeviceAuthorization(deviceCode, userCode, clientID, scope string) error {
	deviceAuthsMutex.Lock()
	defer deviceAuthsMutex.Unlock()

	deviceAuths[deviceCode] = &DeviceAuth{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   clientID,
		Scope:      scope,
		ExpiresAt:  time.Now().Add(10 * time.Minute),
		IsUsed:     false,
		UserID:     "",
	}

	// Also store by user code for verification lookup
	deviceAuths[userCode] = deviceAuths[deviceCode]

	return nil
}

func (h *DeviceCodeHandler) findDeviceAuthByUserCode(userCode string) *DeviceAuth {
	deviceAuthsMutex.RLock()
	defer deviceAuthsMutex.RUnlock()

	if auth, exists := deviceAuths[userCode]; exists {
		auth.Mutex.RLock()
		defer auth.Mutex.RUnlock()
		return auth
	}
	return nil
}

func (h *DeviceCodeHandler) authorizeDevice(userCode, userID string) error {
	deviceAuthsMutex.Lock()
	defer deviceAuthsMutex.Unlock()

	if auth, exists := deviceAuths[userCode]; exists {
		auth.Mutex.Lock()
		defer auth.Mutex.Unlock()

		if time.Now().After(auth.ExpiresAt) {
			return fmt.Errorf("device authorization expired")
		}

		if auth.IsUsed {
			return fmt.Errorf("device authorization already used")
		}

		auth.UserID = userID
		auth.IsUsed = true
		return nil
	}

	return fmt.Errorf("device authorization not found")
}
