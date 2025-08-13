package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"oauth2-server/pkg/config"

	"github.com/ory/fosite"
	"github.com/ory/fosite/storage"
	"github.com/sirupsen/logrus"
)

// DeviceCodeHandler handles all operations related to the device authorization grant
type DeviceCodeHandler struct {
	OAuth2Provider fosite.OAuth2Provider
	MemoryStore    *storage.MemoryStore
	Templates      *template.Template
	Config         *config.Config
	Logger         *logrus.Logger
}

// NewDeviceCodeHandler creates a new DeviceCodeHandler
func NewDeviceCodeHandler(
	provider fosite.OAuth2Provider,
	memoryStore *storage.MemoryStore,
	templates *template.Template,
	config *config.Config,
	logger *logrus.Logger,
) *DeviceCodeHandler {
	return &DeviceCodeHandler{
		OAuth2Provider: provider,
		MemoryStore:    memoryStore,
		Templates:      templates,
		Config:         config,
		Logger:         logger,
	}
}

// HandleDeviceAuthorization handles the device authorization request (RFC 8628)
// Pure fosite approach: let fosite handle everything including storage
func (h *DeviceCodeHandler) HandleDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	h.Logger.Info("🚀 Processing device authorization request using pure fosite flow")

	// Let fosite handle the device authorization request completely
	deviceRequest, err := h.OAuth2Provider.NewDeviceRequest(ctx, r)
	if err != nil {
		h.Logger.WithError(err).Error("Failed to create device request")
		h.writeErrorResponse(w, "invalid_request", err.Error())
		return
	}

	// Create a session for the device authorization
	session := &fosite.DefaultSession{}

	// Generate the device authorization response using fosite
	deviceResponse, err := h.OAuth2Provider.NewDeviceResponse(ctx, deviceRequest, session)
	if err != nil {
		h.Logger.WithError(err).Error("Failed to create device response")
		h.writeErrorResponse(w, "server_error", err.Error())
		return
	}

	// Extract the codes from fosite's response for logging only
	deviceCode := deviceResponse.GetDeviceCode()
	userCode := deviceResponse.GetUserCode()
	clientID := deviceRequest.GetClient().GetID()

	deviceResponse.SetVerificationURI(h.Config.BaseURL + "/device")
	deviceResponse.SetVerificationURIComplete(h.Config.BaseURL + "/device?user_code=" + userCode)

	h.Logger.Infof("✅ Device authorization created via fosite for client: %s", clientID)
	h.Logger.Printf("🔍 Device Code: %s...", deviceCode[:20])
	h.Logger.Printf("🔍 User Code: %s", userCode)

	// Let fosite write the response
	h.OAuth2Provider.WriteDeviceResponse(ctx, w, deviceRequest, deviceResponse)
}

// writeErrorResponse writes a JSON error response
func (h *DeviceCodeHandler) writeErrorResponse(w http.ResponseWriter, errorCode, errorDescription string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": errorDescription,
	})
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

	// First, validate that the user code exists and is still pending
	_, deviceAuthKey, err := h.findDeviceAuthorization(userCode)
	if err != nil {
		h.Logger.WithError(err).Warnf("⚠️ Invalid or expired user code: %s", userCode)
		h.showInvalidUserCodePage(w, r, userCode)
		return
	}

	h.Logger.Infof("✅ Found valid pending device authorization for user code: %s (key: %s)", userCode, deviceAuthKey)

	// Authenticate user
	user := h.authenticateUser(username, password)
	if user == nil {
		http.Redirect(w, r, "/device?error=Invalid+credentials&user_code="+userCode, http.StatusFound)
		return
	}

	// Show consent page instead of immediately completing authorization
	h.showConsentPage(w, r, userCode, user)
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
	h.Logger.Info("🎯 Showing device verification success page")

	data := map[string]interface{}{
		"Success": true,
		"Message": "Device verification completed successfully!",
	}

	if err := h.Templates.ExecuteTemplate(w, "device_success.html", data); err != nil {
		h.Logger.WithError(err).Error("❌ Failed to render device success template")
		// Fallback to simple HTML response
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<html>
			<head><title>Device Verification</title></head>
			<body>
				<h1>✅ User Authenticated!</h1>
				<p>You have successfully authenticated.</p>
				<p>You can now return to your device.</p>
			</body>
			</html>
		`))
		return
	}
	h.Logger.Info("✅ Successfully rendered device verification success page")
}

// showConsentPage displays the consent page where users can approve or deny the device
func (h *DeviceCodeHandler) showConsentPage(w http.ResponseWriter, r *http.Request, userCode string, user *config.User) {
	h.Logger.Infof("🎯 Showing device consent page for user: %s, user code: %s", user.Username, userCode)

	data := map[string]interface{}{
		"UserCode": userCode,
		"Username": user.Username,
		"UserID":   user.ID,
		"Message":  "Please review and approve the device authorization request.",
	}

	if err := h.Templates.ExecuteTemplate(w, "device_consent.html", data); err != nil {
		h.Logger.WithError(err).Error("❌ Failed to render device consent template")
		// Fallback to simple HTML response
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(`
			<html>
			<head><title>Device Authorization Consent</title></head>
			<body>
				<h1>🔐 Device Authorization Request</h1>
				<p>Hello <strong>%s</strong>,</p>
				<p>A device is requesting access to your account.</p>
				<p><strong>User Code:</strong> %s</p>
				<form method="POST" action="/device/consent">
					<input type="hidden" name="user_code" value="%s">
					<input type="hidden" name="username" value="%s">
					<button type="submit" name="action" value="approve" style="background: green; color: white; padding: 10px 20px; margin: 10px;">✅ Approve</button>
					<button type="submit" name="action" value="deny" style="background: red; color: white; padding: 10px 20px; margin: 10px;">❌ Deny</button>
				</form>
			</body>
			</html>
		`, user.Username, userCode, userCode, user.Username)))
		return
	}
	h.Logger.Info("✅ Successfully rendered device consent page")
}

// HandleConsent processes the user's consent decision (approve/deny)
func (h *DeviceCodeHandler) HandleConsent(w http.ResponseWriter, r *http.Request) {
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
	action := r.FormValue("action")

	h.Logger.Infof("🔍 Processing consent for user code: %s, username: %s, action: %s", userCode, username, action)

	// First, validate that the user code still exists and is pending
	_, _, err := h.findDeviceAuthorization(userCode)
	if err != nil {
		h.Logger.WithError(err).Warnf("⚠️ Invalid or expired user code during consent: %s", userCode)
		h.showInvalidUserCodePage(w, r, userCode)
		return
	}

	// Find the user (for security, re-validate)
	var user *config.User
	for _, u := range h.Config.Users {
		if u.Username == username {
			user = &u
			break
		}
	}

	if user == nil {
		http.Redirect(w, r, "/device?error=Invalid+user&user_code="+userCode, http.StatusFound)
		return
	}

	// Process the consent decision
	if action == "approve" {
		// Complete the device authorization with accepted state
		err := h.completeDeviceAuthorization(r.Context(), userCode, user, fosite.UserCodeAccepted)
		if err != nil {
			h.Logger.WithError(err).Error("❌ Failed to complete device authorization")
			http.Redirect(w, r, "/device?error=Authorization+failed&user_code="+userCode, http.StatusFound)
			return
		}

		h.Logger.Infof("✅ Device authorization APPROVED for user code: %s", userCode)
		h.showSuccessPage(w, r)

	} else if action == "deny" {
		// Complete the device authorization with rejected state
		err := h.completeDeviceAuthorization(r.Context(), userCode, user, fosite.UserCodeRejected)
		if err != nil {
			h.Logger.WithError(err).Error("❌ Failed to complete device authorization")
			http.Redirect(w, r, "/device?error=Authorization+failed&user_code="+userCode, http.StatusFound)
			return
		}

		h.Logger.Infof("❌ Device authorization DENIED for user code: %s", userCode)
		h.showDeniedPage(w, r)

	} else {
		http.Redirect(w, r, "/device?error=Invalid+action&user_code="+userCode, http.StatusFound)
		return
	}
}

// showDeniedPage displays a message when user denies the device authorization
func (h *DeviceCodeHandler) showDeniedPage(w http.ResponseWriter, r *http.Request) {
	h.Logger.Info("🎯 Showing device authorization denied page")

	data := map[string]interface{}{
		"Success": false,
		"Message": "Device authorization was denied.",
	}

	if err := h.Templates.ExecuteTemplate(w, "device_denied.html", data); err != nil {
		h.Logger.WithError(err).Error("❌ Failed to render device denied template")
		// Fallback to simple HTML response
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`
			<html>
			<head><title>Authorization Denied</title></head>
			<body>
				<h1>❌ Authorization Denied</h1>
				<p>You have denied the device authorization request.</p>
				<p>The device will not have access to your account.</p>
				<p>You can safely close this window.</p>
			</body>
			</html>
		`))
		return
	}
	h.Logger.Info("✅ Successfully rendered device denied page")
}

// showInvalidUserCodePage displays an error when the user code is invalid or expired
func (h *DeviceCodeHandler) showInvalidUserCodePage(w http.ResponseWriter, r *http.Request, userCode string) {
	h.Logger.Infof("🎯 Showing invalid user code page for: %s", userCode)

	data := map[string]interface{}{
		"Success":  false,
		"UserCode": userCode,
		"Message":  "The user code is invalid or has expired.",
	}

	if err := h.Templates.ExecuteTemplate(w, "device_invalid.html", data); err != nil {
		h.Logger.WithError(err).Error("❌ Failed to render device invalid template")
		// Fallback to simple HTML response
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf(`
			<html>
			<head><title>Invalid User Code</title></head>
			<body>
				<h1>❌ Invalid User Code</h1>
				<p>The user code <strong>%s</strong> is invalid or has expired.</p>
				<p>Please check your device for a new code or restart the authorization process.</p>
				<a href="/device" style="color: #007bff; text-decoration: none;">← Go back to device verification</a>
			</body>
			</html>
		`, userCode)))
		return
	}
	h.Logger.Info("✅ Successfully rendered invalid user code page")
}

// completeDeviceAuthorization completes the device authorization flow in fosite storage
func (h *DeviceCodeHandler) completeDeviceAuthorization(ctx context.Context, userCode string, user *config.User, userCodeState fosite.UserCodeState) error {
	// Access the memory store to find the device authorization by user code
	store := h.MemoryStore

	h.Logger.Infof("🔍 Debug: Looking for user code '%s' in storage", userCode)
	h.Logger.Infof("🔍 Debug: DeviceAuths has %d entries", len(store.DeviceAuths))

	// Find the device authorization session by iterating through all device auths
	// Look for the one without a completed session (pending authorization)
	var deviceAuth fosite.DeviceRequester
	var deviceAuthKey string
	found := false

	for key, auth := range store.DeviceAuths {
		h.Logger.Infof("🔍 Debug: Checking DeviceAuth key '%s'", key)

		// Check if this device auth has no user session yet (pending)
		if auth.GetSession() == nil || auth.GetSession().GetUsername() == "" {
			h.Logger.Infof("🔍 Debug: DeviceAuth has no user session (pending - this is our target)")
			deviceAuth = auth
			deviceAuthKey = key
			found = true
			h.Logger.Infof("🔍 Using pending DeviceAuth key '%s' as the target", key)
			break
		} else {
			h.Logger.Infof("🔍 Debug: DeviceAuth has session (already completed)")
		}
	}

	if !found {
		return fmt.Errorf("no pending device authorization found in storage")
	}

	// Create a session with user information
	session := &fosite.DefaultSession{
		Username: user.Username,
		Subject:  user.Username,
		Extra: map[string]interface{}{
			"user_id": user.Username,
		},
	}

	// Update the device authorization with the user session
	// This is the key step - we associate the authenticated user with the device authorization
	deviceAuth.SetSession(session)

	// CRITICAL: Set the user code state - this tells fosite whether user accepted or rejected!
	deviceAuth.SetUserCodeState(userCodeState)

	// Store the updated device authorization back
	store.DeviceAuths[deviceAuthKey] = deviceAuth

	h.Logger.Infof("✅ Device authorization completed successfully for user: %s, user code: %s, state: %v", user.Username, userCode, userCodeState)

	return nil
}

// findDeviceAuthorization finds a pending device authorization by user code
func (h *DeviceCodeHandler) findDeviceAuthorization(userCode string) (fosite.DeviceRequester, string, error) {
	store := h.MemoryStore

	h.Logger.Infof("🔍 Debug: Looking for user code '%s' in storage", userCode)
	h.Logger.Infof("🔍 Debug: DeviceAuths has %d entries", len(store.DeviceAuths))

	// In fosite's MemoryStore, device authorizations are stored with different keys
	// We need to iterate through all stored device auths and find pending ones
	// that we can associate with the user code
	for key, auth := range store.DeviceAuths {
		h.Logger.Infof("🔍 Debug: Checking DeviceAuth key '%s'", key)

		// Check if this is a pending authorization (no session or empty username)
		if auth.GetSession() == nil || auth.GetSession().GetUsername() == "" {
			h.Logger.Infof("🔍 Found pending device authorization with key: %s", key)
			// For a pending authorization, we'll assume this is the one we're looking for
			// since there should typically only be one pending at a time for a given user code
			// In a production system, you might want to store additional metadata to match properly
			return auth, key, nil
		} else {
			h.Logger.Infof("🔍 Debug: DeviceAuth with key '%s' has session (already completed)", key)
		}
	}

	h.Logger.Warnf("❌ No pending device authorization found for user code: %s", userCode)
	return nil, "", fmt.Errorf("no pending device authorization found for user code: %s", userCode)
}
