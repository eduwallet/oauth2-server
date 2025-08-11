package handlers

import (
	"context"
	"html/template"
	"net/http"
	"oauth2-server/pkg/config"

	"github.com/ory/fosite"
	"github.com/sirupsen/logrus"
)

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

	// Create a session for the device authorization
	session := &fosite.DefaultSession{
		Subject: "", // Will be filled by the user later during verification
	}

	// Let fosite handle the device request
	deviceRequest, err := h.OAuth2Provider.NewDeviceRequest(ctx, r)
	if err != nil {
		h.Logger.WithError(err).Error("Error during device authorization request")
		return
	}

	// Create a response from the request
	deviceResponse, err := h.OAuth2Provider.NewDeviceResponse(ctx, deviceRequest, session)
	if err != nil {
		h.Logger.WithError(err).Error("Error creating device response")
		// Return an error response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Let fosite write the response with the correct parameters
	h.OAuth2Provider.WriteDeviceResponse(ctx, w, deviceRequest, deviceResponse)
}

// ShowVerificationPage displays the page where users enter the user code
func (h *DeviceCodeHandler) ShowVerificationPage(w http.ResponseWriter, r *http.Request) {
	userCode := r.URL.Query().Get("user_code")
	errorMsg := r.URL.Query().Get("error")

	data := map[string]interface{}{
		"UserCode": userCode,
		"Error":    errorMsg,
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

	// Authenticate user
	user := h.authenticateUser(username, password)
	if user == nil {
		http.Redirect(w, r, "/device?error=Invalid+credentials&user_code="+userCode, http.StatusFound)
		return
	}

	// Create a hasher to hash the user code (fosite stores codes in hashed form)
	hasher := &fosite.BCrypt{}

	// Hash the user code
	ctx := r.Context()
	signatureBytes, err := hasher.Hash(ctx, []byte(userCode))
	if err != nil {
		h.Logger.WithError(err).Error("Failed to hash user code")
		http.Redirect(w, r, "/device?error=Internal+server+error", http.StatusFound)
		return
	}

	// Convert signature from []byte to string
	signature := string(signatureBytes)

	// Find the device code session by user code
	session := &fosite.DefaultSession{}
	requester, err := h.getDeviceCodeSession(ctx, signature, session)
	if err != nil {
		h.Logger.WithError(err).Error("Failed to find device code session")
		http.Redirect(w, r, "/device?error=Invalid+or+expired+user+code", http.StatusFound)
		return
	}

	// Set the user information in the session using the requester's SetSession method
	if requester != nil {
		// Get the existing session
		existingSession := requester.GetSession()

		// Log the actual session type for debugging
		h.Logger.Infof("Session type: %T", existingSession)

		// Try multiple approaches to set the subject
		if defaultSession, ok := existingSession.(*fosite.DefaultSession); ok {
			defaultSession.Subject = user.ID
			h.Logger.Info("Set subject via DefaultSession")
		} else if setter, ok := existingSession.(interface{ SetSubject(string) }); ok {
			// Try using a setter interface if available
			setter.SetSubject(user.ID)
			h.Logger.Info("Set subject via SetSubject method")
		} else {
			// Last resort: create a new session with the subject
			newSession := &fosite.DefaultSession{
				Subject: user.ID,
				// Copy any other needed fields from the original session
			}
			requester.SetSession(newSession)
			h.Logger.Info("Set subject via new session")
		}
	} else {
		h.Logger.Error("Requester is nil")
		http.Redirect(w, r, "/device?error=Internal+server+error", http.StatusFound)
		return
	}

	// Show success page
	h.showSuccessPage(w, r)
}

// getDeviceCodeSession attempts to retrieve the device code session using the user code
func (h *DeviceCodeHandler) getDeviceCodeSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	// Try to access the internal storage to get the session
	// This is a bit of a hack, but fosite doesn't expose a clean way to do this
	if store, ok := h.OAuth2Provider.(*fosite.Fosite).Store.(interface {
		GetUserCodeSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error)
	}); ok {
		return store.GetUserCodeSession(ctx, signature, session)
	}

	return nil, fosite.ErrNotFound
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
	data := map[string]interface{}{
		"Success": true,
		"Message": "Device has been successfully authorized",
	}

	if err := h.Templates.ExecuteTemplate(w, "device_success.html", data); err != nil {
		h.Logger.WithError(err).Error("Failed to render device success template")
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}
