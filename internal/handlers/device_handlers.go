package handlers

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"

	"oauth2-server/internal/flows"
	"oauth2-server/internal/utils"
	"oauth2-server/pkg/config"
)

// DeviceHandlers handles device flow user verification
type DeviceHandlers struct {
	deviceFlow *flows.DeviceCodeFlow
	config     *config.Config
}

// NewDeviceHandlers creates a new device handlers instance
func NewDeviceHandlers(deviceFlow *flows.DeviceCodeFlow, config *config.Config) *DeviceHandlers {
	return &DeviceHandlers{
		deviceFlow: deviceFlow,
		config:     config,
	}
}

// HandleDeviceVerification handles the device verification endpoint
func (h *DeviceHandlers) HandleDeviceVerification(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		h.showDeviceForm(w, r)
	case "POST":
		h.handleDeviceForm(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// showDeviceForm displays the device verification form
func (h *DeviceHandlers) showDeviceForm(w http.ResponseWriter, r *http.Request) {
	userCode := r.URL.Query().Get("user_code")
	errorMsg := r.URL.Query().Get("error")

	// Auto-uppercase and format the user code if present
	if userCode != "" {
		userCode = strings.ToUpper(strings.ReplaceAll(userCode, " ", ""))
		// Add hyphen formatting if not present
		if len(userCode) == 8 && !strings.Contains(userCode, "-") {
			userCode = fmt.Sprintf("%s-%s", userCode[:4], userCode[4:])
		}
	}

	tmpl := `
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Device Verification</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 50px; 
            background-color: #f5f5f5; 
            line-height: 1.6;
        }
        .container { 
            max-width: 500px; 
            margin: 0 auto; 
            background: white; 
            padding: 30px; 
            border-radius: 8px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
        }
        .form-group { 
            margin-bottom: 20px; 
        }
        label { 
            display: block; 
            margin-bottom: 5px; 
            font-weight: bold; 
        }
        input[type="text"], input[type="password"] { 
            width: 100%; 
            padding: 12px; 
            border: 1px solid #ddd; 
            border-radius: 4px; 
            box-sizing: border-box; 
            font-size: 16px;
        }
        .btn { 
            background-color: #007bff; 
            color: white; 
            padding: 12px 24px; 
            border: none; 
            border-radius: 4px; 
            cursor: pointer; 
            width: 100%; 
            font-size: 16px;
        }
        .btn:hover { 
            background-color: #0056b3; 
        }
        .error { 
            background-color: #f8d7da; 
            color: #721c24; 
            padding: 15px; 
            border-radius: 4px; 
            margin-bottom: 20px; 
            border: 1px solid #f5c6cb; 
        }
        .info { 
            background-color: #d1ecf1; 
            color: #0c5460; 
            padding: 15px; 
            border-radius: 4px; 
            margin-bottom: 20px; 
            border: 1px solid #bee5eb; 
        }
        .success { 
            background-color: #d4edda; 
            color: #155724; 
            padding: 15px; 
            border-radius: 4px; 
            margin-bottom: 20px; 
            border: 1px solid #c3e6cb; 
        }
        .test-users { 
            margin-top: 20px; 
            padding: 15px; 
            background-color: #f8f9fa; 
            border-radius: 4px; 
        }
        .test-users h4 { 
            margin: 0 0 10px 0; 
            color: #6c757d; 
        }
        .test-users ul { 
            margin: 0; 
            padding-left: 20px; 
        }
        .test-users li { 
            margin-bottom: 5px; 
            font-family: monospace; 
            font-size: 12px; 
        }
        .user-code { 
            font-family: monospace; 
            font-size: 18px; 
            font-weight: bold; 
            color: #007bff; 
            background-color: #f8f9fa; 
            padding: 8px; 
            border-radius: 4px; 
            text-align: center; 
            text-transform: uppercase;
            letter-spacing: 2px;
        }
    </style>
</head>
<body>
    <div class="container">
        <h2>📱 Device Verification</h2>
        
        {{if .Error}}
        <div class="error">❌ {{.Error}}</div>
        {{end}}
        
        {{if .UserCode}}
        <div class="success">
            ✅ Device code detected!
        </div>
        <div class="user-code">Your code: <span>{{.UserCode}}</span></div>
        {{else}}
        <div class="info">
            Enter the code displayed on your device and sign in to authorize the application.
        </div>
        {{end}}
        
        <form method="post">
            <div class="form-group">
                <label for="user_code">Device Code:</label>
                <input type="text" id="user_code" name="user_code" value="{{.UserCode}}" 
                       placeholder="Enter the code from your device (e.g., ABCD-1234)" required 
                       style="text-transform: uppercase; letter-spacing: 2px;" maxlength="9">
            </div>
            
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required 
                       placeholder="Enter your username">
            </div>
            
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required
                       placeholder="Enter your password">
            </div>
            
            <button type="submit" class="btn">Authorize Device</button>
        </form>

        <div class="test-users">
            <h4>Available Test Users:</h4>
            <ul>{{.TestUsersList}}</ul>
        </div>
    </div>

    <script>
        // Auto-format user code input
        document.getElementById('user_code').addEventListener('input', function(e) {
            let value = e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, '');
            if (value.length > 4) {
                value = value.substring(0, 4) + '-' + value.substring(4, 8);
            }
            e.target.value = value;
        });
    </script>
</body>
</html>`

	data := struct {
		UserCode      string
		Error         string
		TestUsersList string
	}{
		UserCode:      userCode,
		Error:         errorMsg,
		TestUsersList: h.generateTestUsersList(),
	}

	t, err := template.New("device").Parse(tmpl)
	if err != nil {
		log.Printf("❌ Template parsing error: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.Execute(w, data); err != nil {
		log.Printf("❌ Template execution error: %v", err)
	}
}

// generateTestUsersList creates an HTML list of available test users
func (h *DeviceHandlers) generateTestUsersList() string {
	var usersList strings.Builder

	for _, user := range h.config.Users {
		usersList.WriteString(fmt.Sprintf(
			"<li><strong>%s</strong> / %s (%s)</li>",
			user.Username,
			user.Password,
			user.Name,
		))
	}

	if usersList.Len() == 0 {
		usersList.WriteString("<li>No test users configured</li>")
	}

	return usersList.String()
}

// handleDeviceForm processes the device verification form submission
func (h *DeviceHandlers) handleDeviceForm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.redirectWithError(w, r, "Failed to parse form")
		return
	}

	userCode := strings.TrimSpace(strings.ToUpper(r.FormValue("user_code")))
	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	if userCode == "" {
		h.redirectWithError(w, r, "Device code is required")
		return
	}

	if username == "" || password == "" {
		h.redirectWithError(w, r, "Username and password are required")
		return
	}

	// Authenticate user against configured users
	user := h.authenticateUser(username, password)
	if user == nil {
		h.redirectWithError(w, r, "Invalid username or password")
		return
	}

	// Authorize the device
	if !h.deviceFlow.AuthorizeDevice(userCode, user.ID) {
		h.redirectWithError(w, r, "Invalid or expired device code")
		return
	}

	// Show success page
	h.showSuccessPage(w, user.Name)
	log.Printf("✅ Device authorized for user: %s (%s)", user.Username, user.Name)
}

// authenticateUser validates user credentials against the configured users
func (h *DeviceHandlers) authenticateUser(username, password string) *config.User {
	// Look up user in the configuration
	if user, found := h.config.GetUserByUsername(username); found {
		// In a real implementation, you'd hash and compare passwords properly
		if user.Password == password {
			return user
		}
	}
	return nil
}

// redirectWithError redirects back to the form with an error message
func (h *DeviceHandlers) redirectWithError(w http.ResponseWriter, r *http.Request, errorMsg string) {
	userCode := r.FormValue("user_code")
	redirectURL := fmt.Sprintf("/device?error=%s", errorMsg)
	if userCode != "" {
		redirectURL += fmt.Sprintf("&user_code=%s", userCode)
	}
	http.Redirect(w, r, redirectURL, http.StatusSeeOther)
}

// showSuccessPage displays the success page after device authorization
func (h *DeviceHandlers) showSuccessPage(w http.ResponseWriter, userName string) {
	successHTML := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Device Authorized</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 50px; 
            background-color: #f5f5f5; 
            line-height: 1.6;
        }
        .container { 
            max-width: 500px; 
            margin: 0 auto; 
            background: white; 
            padding: 30px; 
            border-radius: 8px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
            text-align: center;
        }
        .success { 
            color: #28a745; 
            font-size: 24px;
            margin-bottom: 20px;
        }
        .info { 
            background-color: #d4edda; 
            color: #155724; 
            padding: 15px; 
            border-radius: 4px; 
            margin-bottom: 20px; 
            border: 1px solid #c3e6cb; 
        }
        .btn { 
            background-color: #6c757d; 
            color: white; 
            padding: 10px 20px; 
            border: none; 
            border-radius: 4px; 
            cursor: pointer; 
            text-decoration: none;
            display: inline-block;
        }
        .btn:hover { 
            background-color: #545b62; 
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="success">✅ Device Authorized!</div>
        
        <div class="info">
            <strong>Hello, %s!</strong><br><br>
            Your device has been successfully authorized. You can now return to your device 
            and continue using the application.
        </div>
        
        <p>This window can be safely closed.</p>
        
        <a href="/" class="btn">Return to Home</a>
    </div>
</body>
</html>`, userName)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(successHTML))
}

// HandleDeviceStatus returns the status of a device authorization (for AJAX polling)
func (h *DeviceHandlers) HandleDeviceStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	userCode := r.URL.Query().Get("user_code")
	if userCode == "" {
		utils.WriteJSONResponse(w, http.StatusBadRequest, map[string]string{
			"error": "user_code parameter is required",
		})
		return
	}

	// You would implement device status checking here
	// For now, return a simple response
	utils.WriteJSONResponse(w, http.StatusOK, map[string]interface{}{
		"status":    "pending",
		"user_code": userCode,
		"timestamp": time.Now().Unix(),
	})
}
