package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url" // Add this import
	"oauth2-server/internal/storage"
	"strings"
	"time"
)

// HandleDeviceCode handles device authorization requests (RFC 8628)
func (h *Handlers) HandleDeviceCode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.writeError(w, "invalid_request", "Invalid form data", http.StatusBadRequest)
		return
	}

	clientID := r.FormValue("client_id")
	scope := r.FormValue("scope")

	if clientID == "" {
		h.writeError(w, "invalid_request", "Missing client_id", http.StatusBadRequest)
		return
	}

	client := h.findClient(clientID)
	if client == nil {
		h.writeError(w, "invalid_client", "Unknown client", http.StatusBadRequest)
		return
	}

	deviceCode := generateRandomString(32)
	userCode := generateUserCode()
	verificationURI := fmt.Sprintf("%s/device/verify", h.Config.Server.BaseURL)

	expiresIn := 600
	interval := 5

	deviceState := &storage.DeviceCodeState{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ClientID:   clientID,
		Scopes:     strings.Fields(scope),
		ExpiresIn:  expiresIn,
		Interval:   interval,
		CreatedAt:  time.Now(),
		Authorized: false,
	}

	if err := h.Storage.StoreDeviceCode(deviceState); err != nil {
		h.Logger.WithError(err).Error("Failed to store device code")
		h.writeError(w, "server_error", "Failed to generate device code", http.StatusInternalServerError)
		return
	}

	response := storage.DeviceCodeResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         verificationURI,
		VerificationURIComplete: fmt.Sprintf("%s?user_code=%s", verificationURI, userCode),
		ExpiresIn:               expiresIn,
		Interval:                interval,
	}

	w.Header().Set("Content-Type", "application/json")
	h.Logger.Debugf("Device authorization request generated: user_code=%s, client=%s", userCode, clientID)
	json.NewEncoder(w).Encode(response)
}

// HandleDeviceVerify handles device verification page
func (h *Handlers) HandleDeviceVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		h.writeError(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if user is authenticated
	if !h.isUserAuthenticated(r) {
		// Redirect to login with the current URL as redirect target
		currentURL := r.URL.String()
		loginURL := fmt.Sprintf("/login?redirect_url=%s", url.QueryEscape(currentURL))
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	userCode := r.URL.Query().Get("user_code")

	data := map[string]interface{}{
		"UserCode": userCode,
		"Error":    r.URL.Query().Get("error"),
	}

	if err := h.Templates.ExecuteTemplate(w, "device_verify.html", data); err != nil {
		h.Logger.WithError(err).Error("Failed to render device verification template")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// HandleDeviceAuthorize handles device authorization confirmation
func (h *Handlers) HandleDeviceAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeError(w, "invalid_request", "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Check if user is authenticated
	if !h.isUserAuthenticated(r) {
		// Redirect to login with the current URL as redirect target
		loginURL := fmt.Sprintf("/login?redirect_url=%s", url.QueryEscape("/device/verify"))
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	if err := r.ParseForm(); err != nil {
		h.writeError(w, "invalid_request", "Invalid form data", http.StatusBadRequest)
		return
	}

	userCode := r.FormValue("user_code")
	action := r.FormValue("action") // "authorize" or "deny"

	if userCode == "" {
		http.Redirect(w, r, "/device/verify?error=missing_user_code", http.StatusFound)
		return
	}

	// Get current authenticated user
	userID := h.getCurrentUserID(r)
	if userID == "" {
		h.Logger.Error("Could not get user ID from session")
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	// Find device code by user code - now using the correct method signature
	deviceState, err := h.Storage.GetDeviceCodeByUserCode(userCode)
	if err != nil {
		h.Logger.WithError(err).Debug("Device code lookup failed")
		http.Redirect(w, r, "/device/verify?error=invalid_code", http.StatusFound)
		return
	}

	if deviceState == nil {
		http.Redirect(w, r, "/device/verify?error=invalid_code", http.StatusFound)
		return
	}

	// Check if device code is expired
	if time.Now().After(deviceState.CreatedAt.Add(time.Duration(deviceState.ExpiresIn) * time.Second)) {
		http.Redirect(w, r, "/device/verify?error=expired_code", http.StatusFound)
		return
	}

	if action == "authorize" {
		// Mark device as authorized
		deviceState.Authorized = true
		deviceState.UserID = userID
		//		deviceState.AuthorizedAt = time.Now()

		if err := h.Storage.StoreDeviceCode(deviceState); err != nil {
			h.Logger.WithError(err).Error("Failed to update device code")
			http.Redirect(w, r, "/device/verify?error=server_error", http.StatusFound)
			return
		}

		h.Logger.Debugf("Device authorization successful: user_code=%s, user=%s, client=%s",
			userCode, userID, deviceState.ClientID)

		// Show success page
		data := map[string]interface{}{
			"Success": true,
			"Message": "Device has been successfully authorized",
		}

		if err := h.Templates.ExecuteTemplate(w, "device_success.html", data); err != nil {
			h.Logger.WithError(err).Error("Failed to render device success template")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	} else {
		// User denied authorization
		h.Logger.Debugf("Device authorization denied: user_code=%s, user=%s", userCode, userID)

		data := map[string]interface{}{
			"Denied":  true,
			"Message": "Device authorization was denied",
		}

		if err := h.Templates.ExecuteTemplate(w, "device_success.html", data); err != nil {
			h.Logger.WithError(err).Error("Failed to render device success template")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// HandleDevicePoll handles device polling (redirect to token endpoint)
func (h *Handlers) HandleDevicePoll(w http.ResponseWriter, r *http.Request) {
	h.writeError(w, "invalid_request", "Use token endpoint with device_code grant", http.StatusBadRequest)
}
