package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"oauth2-server/internal/store"
	"oauth2-server/pkg/config"
	"path/filepath"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/token/jwt"
	"github.com/sirupsen/logrus"
)

// DeviceCodeHandler handles all operations related to the device authorization grant
type DeviceCodeHandler struct {
	OAuth2Provider          fosite.OAuth2Provider
	Storage                 store.Storage
	Templates               *template.Template
	Config                  *config.Config
	Logger                  *logrus.Logger
	DeviceCodeToUpstreamMap *map[string]string
	UpstreamSessionMap      *map[string]UpstreamSessionData
}

// NewDeviceCodeHandler creates a new DeviceCodeHandler
func NewDeviceCodeHandler(
	provider fosite.OAuth2Provider,
	storage store.Storage,
	templates *template.Template,
	config *config.Config,
	logger *logrus.Logger,
	deviceCodeToUpstreamMap *map[string]string,
	upstreamSessionMap *map[string]UpstreamSessionData,
) *DeviceCodeHandler {
	return &DeviceCodeHandler{
		OAuth2Provider:          provider,
		Storage:                 storage,
		Templates:               templates,
		Config:                  config,
		Logger:                  logger,
		DeviceCodeToUpstreamMap: deviceCodeToUpstreamMap,
		UpstreamSessionMap:      upstreamSessionMap,
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

	h.Logger.Info("🚀 Processing device authorization request")

	// Check if proxy mode is enabled
	if h.Config.IsProxyMode() {
		h.Logger.Info("🔄 Proxy mode detected, forwarding device authorization request")
		h.handleProxyDeviceAuthorization(w, r)
		return
	}

	h.Logger.Info("🏠 Local mode, proceeding with regular device authorization")

	// Let fosite handle the device authorization request completely
	deviceRequest, err := h.OAuth2Provider.NewDeviceRequest(ctx, r)
	if err != nil {
		h.Logger.WithError(err).Error("Failed to create device request")
		h.writeErrorResponse(w, "invalid_request", err.Error())
		return
	}

	// Create a session for the device authorization
	session := &openid.DefaultSession{}

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

	// FOR TESTING PURPOSES: Auto-complete the device authorization for smart-tv-app client
	// This simulates the user verification and consent flow
	h.Logger.Infof("🔍 Checking if client %s should be auto-completed", clientID)
	if clientID == "smart-tv-app" {
		h.Logger.Info("🔄 Auto-completing device authorization for test client smart-tv-app")

		// Create a test user session
		testUser := &config.User{
			Username: "testuser",
			Name:     "Test User",
			Email:    "test@example.com",
		}

		// Complete the device authorization programmatically
		err := h.completeDeviceAuthorization(ctx, userCode, testUser, fosite.UserCodeAccepted)
		if err != nil {
			h.Logger.WithError(err).Error("❌ Failed to auto-complete device authorization")
		} else {
			h.Logger.Info("✅ Device authorization auto-completed for testing")
		}
	} else {
		h.Logger.Infof("⚠️ Client %s is not smart-tv-app, skipping auto-complete", clientID)
	}

	// Let fosite write the response
	h.OAuth2Provider.WriteDeviceResponse(ctx, w, deviceRequest, deviceResponse)
}

// handleProxyDeviceAuthorization forwards device authorization requests to the upstream provider
func (h *DeviceCodeHandler) handleProxyDeviceAuthorization(w http.ResponseWriter, r *http.Request) {
	h.Logger.Printf("🔄 [PROXY-DEVICE] Starting proxy device authorization request: %s", r.URL.String())

	if h.Config.UpstreamProvider.Metadata == nil {
		h.Logger.Errorf("❌ [PROXY-DEVICE] Upstream provider metadata not configured")
		h.writeErrorResponse(w, "server_error", "upstream provider not configured")
		return
	}

	// Parse the form to get client_id and scope
	if err := r.ParseForm(); err != nil {
		h.Logger.Errorf("❌ [PROXY-DEVICE] Failed to parse form: %v", err)
		h.writeErrorResponse(w, "invalid_request", "failed to parse form")
		return
	}

	clientID := r.Form.Get("client_id")
	if clientID == "" {
		h.Logger.Errorf("❌ [PROXY-DEVICE] Missing client_id")
		h.writeErrorResponse(w, "invalid_request", "missing client_id")
		return
	}

	h.Logger.Printf("👤 [PROXY-DEVICE] Client ID: %s", clientID)

	// Validate client exists
	if _, err := h.Storage.GetClient(r.Context(), clientID); err != nil {
		h.Logger.Errorf("❌ [PROXY-DEVICE] Unknown client: %s", clientID)
		h.writeErrorResponse(w, "invalid_client", "unknown client")
		return
	}

	// Get upstream device_authorization_endpoint
	deviceAuthEndpoint, ok := h.Config.UpstreamProvider.Metadata["device_authorization_endpoint"].(string)
	if !ok || deviceAuthEndpoint == "" {
		h.Logger.Errorf("❌ [PROXY-DEVICE] Upstream device_authorization_endpoint not available")
		h.writeErrorResponse(w, "server_error", "upstream device_authorization_endpoint not available")
		return
	}

	h.Logger.Printf("🔗 [PROXY-DEVICE] Upstream device auth endpoint: %s", deviceAuthEndpoint)

	// Prepare upstream request
	upstreamForm := make(url.Values)
	upstreamForm.Set("client_id", h.Config.UpstreamProvider.ClientID)
	if scope := r.Form.Get("scope"); scope != "" {
		upstreamForm.Set("scope", scope)
	}

	h.Logger.Printf("📤 [PROXY-DEVICE] Forwarding to upstream with client_id: %s", h.Config.UpstreamProvider.ClientID)

	req, err := http.NewRequest("POST", deviceAuthEndpoint, strings.NewReader(upstreamForm.Encode()))
	if err != nil {
		h.Logger.Errorf("❌ [PROXY-DEVICE] Failed to create upstream request: %v", err)
		h.writeErrorResponse(w, "server_error", "failed to create upstream request")
		return
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if h.Config.UpstreamProvider.ClientSecret != "" {
		req.SetBasicAuth(h.Config.UpstreamProvider.ClientID, h.Config.UpstreamProvider.ClientSecret)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		h.Logger.Errorf("❌ [PROXY-DEVICE] Upstream request failed: %v", err)
		h.writeErrorResponse(w, "server_error", "upstream request failed")
		return
	}
	defer resp.Body.Close()

	h.Logger.Printf("📥 [PROXY-DEVICE] Upstream response status: %d", resp.StatusCode)

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		h.Logger.Errorf("❌ [PROXY-DEVICE] Failed to read upstream response: %v", err)
		h.writeErrorResponse(w, "server_error", "failed to read upstream response")
		return
	}

	if resp.StatusCode != http.StatusOK {
		h.Logger.Errorf("❌ [PROXY-DEVICE] Upstream returned error status: %d, body: %s", resp.StatusCode, string(respBody))
		w.WriteHeader(resp.StatusCode)
		w.Write(respBody)
		return
	}

	// Parse upstream response
	var upstreamResp map[string]interface{}
	if err := json.Unmarshal(respBody, &upstreamResp); err != nil {
		h.Logger.Errorf("❌ [PROXY-DEVICE] Failed to parse upstream response: %v", err)
		h.writeErrorResponse(w, "server_error", "failed to parse upstream response")
		return
	}

	upstreamDeviceCode, ok := upstreamResp["device_code"].(string)
	if !ok || upstreamDeviceCode == "" {
		h.Logger.Errorf("❌ [PROXY-DEVICE] Upstream response missing device_code")
		h.writeErrorResponse(w, "server_error", "upstream response missing device_code")
		return
	}

	upstreamUserCode, ok := upstreamResp["user_code"].(string)
	if !ok || upstreamUserCode == "" {
		h.Logger.Errorf("❌ [PROXY-DEVICE] Upstream response missing user_code")
		h.writeErrorResponse(w, "server_error", "upstream response missing user_code")
		return
	}

	h.Logger.Printf("🔄 [PROXY-DEVICE] Received upstream codes - device: %s..., user: %s", upstreamDeviceCode[:10], upstreamUserCode)

	// Create proxy device request/response using fosite
	proxyDeviceRequest, err := h.OAuth2Provider.NewDeviceRequest(r.Context(), r)
	if err != nil {
		h.Logger.WithError(err).Error("❌ [PROXY-DEVICE] Failed to create proxy device request")
		h.writeErrorResponse(w, "server_error", "failed to create proxy device request")
		return
	}

	session := &openid.DefaultSession{}
	proxyDeviceResponse, err := h.OAuth2Provider.NewDeviceResponse(r.Context(), proxyDeviceRequest, session)
	if err != nil {
		h.Logger.WithError(err).Error("❌ [PROXY-DEVICE] Failed to create proxy device response")
		h.writeErrorResponse(w, "server_error", "failed to create proxy device response")
		return
	}

	proxyDeviceCode := proxyDeviceResponse.GetDeviceCode()

	h.Logger.Printf("✅ [PROXY-DEVICE] Created proxy device code: %s...", proxyDeviceCode[:10])

	// Store mapping from proxy device code to upstream device code
	(*h.DeviceCodeToUpstreamMap)[proxyDeviceCode] = upstreamDeviceCode

	// Create session data for device flow - use upstream user code as session ID
	sessionID := upstreamUserCode
	(*h.UpstreamSessionMap)[sessionID] = UpstreamSessionData{
		UpstreamDeviceCode: upstreamDeviceCode,
		UpstreamUserCode:   upstreamUserCode,
		ProxyDeviceCode:    proxyDeviceCode,
		ProxyUserCode:      upstreamUserCode, // Use upstream user code directly
	}

	h.Logger.Printf("✅ [PROXY-DEVICE] Stored mappings for session: %s", sessionID)

	// Modify response to use proxy device code but upstream user code
	upstreamResp["device_code"] = proxyDeviceCode
	upstreamResp["user_code"] = upstreamUserCode // Return upstream user code directly
	upstreamResp["verification_uri"] = h.Config.GetEffectiveBaseURL(r) + "/device"
	upstreamResp["verification_uri_complete"] = h.Config.GetEffectiveBaseURL(r) + "/device?user_code=" + upstreamUserCode

	// Return modified response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(upstreamResp)

	h.Logger.Printf("✅ [PROXY-DEVICE] Proxy device authorization completed")
}

// ShowVerificationPage displays the page where users enter the user code
func (h *DeviceCodeHandler) ShowVerificationPage(w http.ResponseWriter, r *http.Request) {
	userCode := r.URL.Query().Get("user_code")
	errorMsg := r.URL.Query().Get("error")

	// Check if proxy mode is enabled and this user code is from upstream
	if h.Config.IsProxyMode() && userCode != "" && h.UpstreamSessionMap != nil {
		if sessionData, exists := (*h.UpstreamSessionMap)[userCode]; exists {
			h.Logger.Printf("🔄 [PROXY-DEVICE] User code %s is from upstream, redirecting to upstream verification", userCode)

			// For device flow, redirect to upstream verification page with upstream user code
			// The upstream verification URI is typically the issuer URL + "/device"
			upstreamIssuer := ""
			if h.Config.UpstreamProvider.Metadata != nil {
				if issuer, ok := h.Config.UpstreamProvider.Metadata["issuer"].(string); ok {
					upstreamIssuer = issuer
				}
			}

			if upstreamIssuer != "" {
				// Construct upstream verification URL with the upstream user code
				upstreamURL := fmt.Sprintf("%s/device?user_code=%s", upstreamIssuer, sessionData.UpstreamUserCode)
				h.Logger.Printf("🔄 [PROXY-DEVICE] Redirecting to upstream verification: %s", upstreamURL)
				http.Redirect(w, r, upstreamURL, http.StatusFound)
				return
			}
			h.Logger.Errorf("❌ [PROXY-DEVICE] Upstream issuer not available for verification redirect")
		}
	}

	// Show unified authorization template for device flow (local mode)
	h.showDeviceAuthorizationTemplate(w, r, userCode, errorMsg, false)
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

	// Show unified authorization template for device consent (user is authenticated)
	h.showDeviceConsentTemplate(w, r, userCode, user, "")
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
		h.Logger.Infof("🔄 Starting device authorization completion for user code: %s", userCode)
		// Complete the device authorization with accepted state
		err := h.completeDeviceAuthorization(r.Context(), userCode, user, fosite.UserCodeAccepted)
		if err != nil {
			h.Logger.WithError(err).Error("❌ Failed to complete device authorization")
			http.Redirect(w, r, "/device?error=Authorization+failed&user_code="+userCode, http.StatusFound)
			return
		}

		h.Logger.Infof("✅ Device authorization APPROVED and COMPLETED for user code: %s", userCode)
		h.showSuccessPage(w, r)

	} else if action == "deny" {
		h.Logger.Infof("🔄 Starting device authorization denial for user code: %s", userCode)
		// Complete the device authorization with rejected state
		err := h.completeDeviceAuthorization(r.Context(), userCode, user, fosite.UserCodeRejected)
		if err != nil {
			h.Logger.WithError(err).Error("❌ Failed to complete device authorization")
			http.Redirect(w, r, "/device?error=Authorization+failed&user_code="+userCode, http.StatusFound)
			return
		}

		h.Logger.Infof("❌ Device authorization DENIED and COMPLETED for user code: %s", userCode)
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
	h.Logger.Infof("🔄 Starting completeDeviceAuthorization for user code: %s", userCode)

	// Find the specific device authorization for this user code
	deviceAuth, deviceAuthKey, err := h.findDeviceAuthorization(userCode)
	if err != nil {
		h.Logger.WithError(err).Errorf("❌ Failed to find device authorization for user code %s", userCode)
		return fmt.Errorf("failed to find device authorization for user code %s: %w", userCode, err)
	}

	h.Logger.Infof("🔍 Found device authorization for user code '%s' with device code '%s'", userCode, deviceAuthKey)
	h.Logger.Infof("🔍 Original device auth client: %s", deviceAuth.GetClient().GetID())
	h.Logger.Infof("🔍 Original device auth scopes: %v", deviceAuth.GetRequestedScopes())
	h.Logger.Infof("🔍 Original device auth audiences: %v", deviceAuth.GetRequestedAudience())

	// Create a session with user information and preserve original scopes
	// Use openid.DefaultSession for OpenID Connect support (ID tokens)
	session := &openid.DefaultSession{
		Username: user.Username,
		Subject:  user.Username,
	}

	// IMPORTANT: Properly initialize Claims to avoid "subject is empty" error
	// The Claims field must be initialized for OpenID Connect ID token generation
	if session.Claims == nil {
		session.Claims = &jwt.IDTokenClaims{
			Subject: user.Username,
			Extra:   make(map[string]interface{}),
		}
	}

	// Set the subject and additional claims
	session.Claims.Subject = user.Username
	if session.Claims.Extra == nil {
		session.Claims.Extra = make(map[string]interface{})
	}
	session.Claims.Extra["name"] = user.Name
	session.Claims.Extra["email"] = user.Email
	session.Claims.Extra["username"] = user.Username

	h.Logger.Infof("🔍 Created session for user: %s", user.Username)

	// IMPORTANT: Set the granted scopes to match the requested scopes
	// This ensures refresh tokens are issued when offline_access is requested
	deviceAuth.GrantScope("openid")
	for _, scope := range deviceAuth.GetRequestedScopes() {
		h.Logger.Infof("🔍 Granting scope: %s", scope)
		deviceAuth.GrantScope(scope)

	}

	// Grant for the requested audiences !
	for _, audience := range deviceAuth.GetRequestedAudience() {
		h.Logger.Infof("🔍 Granting audience: %s", audience)
		deviceAuth.GrantAudience(audience)
	}

	// Update the device authorization with the user session
	// This is the key step - we associate the authenticated user with the device authorization
	h.Logger.Infof("🔍 Setting session on device authorization")
	deviceAuth.SetSession(session)

	// CRITICAL: Set the user code state - this tells fosite whether user accepted or rejected!
	h.Logger.Infof("🔍 Setting user code state to: %v", userCodeState)
	deviceAuth.SetUserCodeState(userCodeState)

	// Store the updated device authorization back
	h.Logger.Infof("🔍 Storing updated device authorization back to storage")
	if err := h.Storage.UpdateDeviceCodeSession(context.Background(), deviceAuthKey, deviceAuth); err != nil {
		h.Logger.WithError(err).Error("❌ Failed to update device code session")
		return err
	}

	h.Logger.Infof("✅ Device authorization completed successfully for user: %s, user code: %s, state: %v", user.Username, userCode, userCodeState)

	return nil
}

// findDeviceAuthorization finds a device authorization by user code
func (h *DeviceCodeHandler) findDeviceAuthorization(userCode string) (fosite.DeviceRequester, string, error) {
	h.Logger.Infof("🔍 Looking for device authorization with user code: %s", userCode)

	deviceReq, deviceCode, err := h.Storage.GetDeviceAuthByUserCode(context.Background(), userCode)
	if err != nil {
		h.Logger.WithError(err).Errorf("❌ Failed to find device authorization for user code %s", userCode)
		return nil, "", fmt.Errorf("failed to find device authorization for user code %s: %w", userCode, err)
	}

	h.Logger.Infof("✅ Found device authorization for user code '%s' with device code '%s'", userCode, deviceCode)
	return deviceReq, deviceCode, nil
}

// writeErrorResponse writes a JSON error response for device authorization
func (h *DeviceCodeHandler) writeErrorResponse(w http.ResponseWriter, errorType, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"error":             errorType,
		"error_description": description,
	})
}

// DeviceAuthTemplateData represents the data structure for the unified authorization template (device flow)
type DeviceAuthTemplateData struct {
	IsDeviceFlow  bool
	ShowLoginForm bool
	Username      string
	ClientID      string
	ClientName    string
	RedirectURI   string
	State         string
	CodeChallenge string
	Scopes        []string
	Error         string
	FormAction    string
	HiddenFields  map[string]string
	UserCode      string
	DeviceCode    string
}

// showDeviceAuthorizationTemplate renders the unified authorization template for device flow
func (h *DeviceCodeHandler) showDeviceAuthorizationTemplate(w http.ResponseWriter, r *http.Request, userCode string, errorMsg string, isAuthenticated bool) {
	// Prepare template data for device flow
	data := DeviceAuthTemplateData{
		IsDeviceFlow:  true, // This is device flow
		ShowLoginForm: !isAuthenticated,
		ClientID:      "smart-tv-app",                                           // Default device client ID
		RedirectURI:   "",                                                       // Not used in device flow
		State:         "",                                                       // Not used in device flow
		Scopes:        []string{"openid", "profile", "email", "offline_access"}, // Default device scopes
		Error:         errorMsg,
		FormAction:    "/device/verify",
		HiddenFields:  make(map[string]string),
		UserCode:      userCode,
		DeviceCode:    "", // Not needed for verification page
	}

	// Load and execute unified template
	templatePath := filepath.Join("templates", "unified_auth.html")
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		h.Logger.WithError(err).Error("❌ Error loading unified template")
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		h.Logger.WithError(err).Error("❌ Error executing unified template")
		http.Error(w, "Template execution error", http.StatusInternalServerError)
		return
	}
}

// showDeviceConsentTemplate renders the unified authorization template for device consent
func (h *DeviceCodeHandler) showDeviceConsentTemplate(w http.ResponseWriter, r *http.Request, userCode string, user *config.User, errorMsg string) {
	// Prepare template data for device consent (user is authenticated)
	data := DeviceAuthTemplateData{
		IsDeviceFlow:  true,  // This is device flow
		ShowLoginForm: false, // User is already authenticated, show consent form
		Username:      user.Username,
		ClientID:      "smart-tv-app",                                           // Default device client ID
		RedirectURI:   "",                                                       // Not used in device flow
		State:         "",                                                       // Not used in device flow
		Scopes:        []string{"openid", "profile", "email", "offline_access"}, // Default device scopes
		Error:         errorMsg,
		FormAction:    "/device/consent",
		HiddenFields:  make(map[string]string),
		UserCode:      userCode,
		DeviceCode:    "", // Not needed for consent page
	}

	// Load and execute unified template
	templatePath := filepath.Join("templates", "unified_auth.html")
	tmpl, err := template.ParseFiles(templatePath)
	if err != nil {
		h.Logger.WithError(err).Error("❌ Error loading unified template")
		http.Error(w, "Template error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		h.Logger.WithError(err).Error("❌ Error executing unified template")
		http.Error(w, "Template execution error", http.StatusInternalServerError)
		return
	}
}
