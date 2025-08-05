package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
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

	if err := h.Storage.StoreDeviceCode(deviceCode, deviceState); err != nil {
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
	if r.Method == http.MethodGet {
		userCode := r.URL.Query().Get("user_code")
		data := map[string]interface{}{
			"UserCode": userCode,
		}

		if err := h.Templates.ExecuteTemplate(w, "device_verify.html", data); err != nil {
			h.Logger.WithError(err).Error("Failed to render device verify template")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}

		userCode := r.FormValue("user_code")
		if userCode == "" {
			http.Error(w, "Missing user code", http.StatusBadRequest)
			return
		}

		deviceState, _, err := h.Storage.GetDeviceCodeByUserCode(userCode)
		if err != nil || deviceState == nil {
			http.Error(w, "Invalid user code", http.StatusBadRequest)
			return
		}

		if time.Since(deviceState.CreatedAt) > time.Duration(deviceState.ExpiresIn)*time.Second {
			http.Error(w, "User code has expired", http.StatusBadRequest)
			return
		}

		data := map[string]interface{}{
			"DeviceCode": deviceState.DeviceCode,
			"ClientID":   deviceState.ClientID,
			"Scope":      strings.Join(deviceState.Scopes, " "),
		}

		if err := h.Templates.ExecuteTemplate(w, "device_authorize.html", data); err != nil {
			h.Logger.WithError(err).Error("Failed to render device authorize template")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// HandleDeviceAuthorize handles device authorization confirmation
func (h *Handlers) HandleDeviceAuthorize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form data", http.StatusBadRequest)
		return
	}

	deviceCode := r.FormValue("device_code")
	action := r.FormValue("action")

	if deviceCode == "" {
		http.Error(w, "Missing device code", http.StatusBadRequest)
		return
	}

	deviceState, err := h.Storage.GetDeviceCode(deviceCode)
	if err != nil || deviceState == nil {
		http.Error(w, "Invalid device code", http.StatusBadRequest)
		return
	}

	if action == "authorize" {
		accessToken := generateRandomString(64)
		userID := h.getCurrentUserID(r)
		if userID == "" {
			userID = "device_user"
		}

		accessTokenInfo := &storage.TokenInfo{
			Token:     accessToken,
			TokenType: "access_token",
			ClientID:  deviceState.ClientID,
			UserID:    userID,
			Scopes:    deviceState.Scopes,
			Audience:  []string{},
			IssuedAt:  time.Now(),
			ExpiresAt: time.Now().Add(time.Duration(h.Config.Security.TokenExpirySeconds) * time.Second),
			Active:    true,
			Extra:     make(map[string]interface{}),
		}

		if err := h.Storage.StoreToken(accessTokenInfo); err != nil {
			h.Logger.WithError(err).Error("Failed to store access token")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		deviceState.Authorized = true
		deviceState.AccessToken = accessToken
		deviceState.UserID = userID

		if err := h.Storage.UpdateDeviceCode(deviceCode, deviceState); err != nil {
			h.Logger.WithError(err).Error("Failed to update device code")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}

		h.Logger.Debugf("Device authorization successful: user_code=%s, client=%s, user=%s", deviceState.UserCode, deviceState.ClientID, userID)

		if err := h.Templates.ExecuteTemplate(w, "device_success.html", nil); err != nil {
			h.Logger.WithError(err).Error("Failed to render success template")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	} else {
		if err := h.Storage.DeleteDeviceCode(deviceCode); err != nil {
			h.Logger.WithError(err).Error("Failed to delete device code")
		}

		h.Logger.Debugf("Device authorization denied: user_code=%s, client=%s", deviceState.UserCode, deviceState.ClientID)

		if err := h.Templates.ExecuteTemplate(w, "device_denied.html", nil); err != nil {
			h.Logger.WithError(err).Error("Failed to render denied template")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}
}

// HandleDevicePoll handles device polling (redirect to token endpoint)
func (h *Handlers) HandleDevicePoll(w http.ResponseWriter, r *http.Request) {
	h.writeError(w, "invalid_request", "Use token endpoint with device_code grant", http.StatusBadRequest)
}
