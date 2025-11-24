package utils

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/sirupsen/logrus"
)

// WriteHTMLResponse writes an HTML response with the given status code and content
func WriteHTMLResponse(w http.ResponseWriter, statusCode int, content string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)

	html := fmt.Sprintf(`
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OAuth2 Server</title>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 50px; 
            background-color: #f5f5f5; 
            line-height: 1.6;
        }
        .container { 
            max-width: 600px; 
            margin: 0 auto; 
            background: white; 
            padding: 30px; 
            border-radius: 8px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1); 
        }
        h2 { 
            color: #333; 
            margin-top: 0; 
        }
        p { 
            margin-bottom: 15px; 
        }
        strong { 
            color: #555; 
        }
        .error { 
            color: #dc3545; 
        }
        .success { 
            color: #28a745; 
        }
        .info { 
            color: #17a2b8; 
        }
        .code { 
            background-color: #f8f9fa; 
            padding: 10px; 
            border-radius: 4px; 
            font-family: monospace; 
            word-break: break-all; 
        }
    </style>
</head>
<body>
    <div class="container">
        %s
    </div>
</body>
</html>`, content)

	w.Write([]byte(html))
}

// WriteJSONResponse writes a JSON response with the given status code and data
func WriteJSONResponse(w http.ResponseWriter, statusCode int, data interface{}, logger *logrus.Logger) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		logger.Errorf("❌ Error encoding JSON response: %v", err)
	}
}

// WriteTextResponse writes a plain text response
func WriteTextResponse(w http.ResponseWriter, statusCode int, text string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(statusCode)
	w.Write([]byte(text))
}

// WriteErrorHTML writes an HTML error response
func WriteErrorHTML(w http.ResponseWriter, statusCode int, title, message string) {
	content := fmt.Sprintf(`
        <h2 class="error">❌ %s</h2>
        <p>%s</p>
        <p><small>Status Code: %d</small></p>
    `, title, message, statusCode)

	WriteHTMLResponse(w, statusCode, content)
}

// WriteSuccessHTML writes an HTML success response
func WriteSuccessHTML(w http.ResponseWriter, title, message string) {
	content := fmt.Sprintf(`
        <h2 class="success">✅ %s</h2>
        <p>%s</p>
    `, title, message)

	WriteHTMLResponse(w, http.StatusOK, content)
}

// WriteInfoHTML writes an HTML info response
func WriteInfoHTML(w http.ResponseWriter, title, message string) {
	content := fmt.Sprintf(`
        <h2 class="info">ℹ️ %s</h2>
        <p>%s</p>
    `, title, message)

	WriteHTMLResponse(w, http.StatusOK, content)
}
