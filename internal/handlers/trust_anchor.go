package handlers

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// TrustAnchorHandler manages trust anchor certificate uploads
type TrustAnchorHandler struct {
	storageDir string
}

// NewTrustAnchorHandler creates a new trust anchor handler
func NewTrustAnchorHandler(storageDir string) *TrustAnchorHandler {
	// Ensure storage directory exists
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		log.Printf("⚠️  Failed to create trust anchor storage directory: %v", err)
	}
	return &TrustAnchorHandler{
		storageDir: storageDir,
	}
}

// HandleUpload handles trust anchor certificate uploads
func (h *TrustAnchorHandler) HandleUpload(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate name (basic security - no path traversal)
	if strings.Contains(name, "/") || strings.Contains(name, "..") || name == "" {
		http.Error(w, "Invalid trust anchor name", http.StatusBadRequest)
		return
	}

	// Parse multipart form
	err := r.ParseMultipartForm(32 << 20) // 32MB max
	if err != nil {
		http.Error(w, "Failed to parse multipart form", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("certificate")
	if err != nil {
		http.Error(w, "Failed to get certificate file from form", http.StatusBadRequest)
		return
	}
	defer file.Close()

	// Validate file size (max 1MB)
	if header.Size > 1024*1024 {
		http.Error(w, "Certificate file too large (max 1MB)", http.StatusBadRequest)
		return
	}

	// Read certificate data
	certData, err := io.ReadAll(file)
	if err != nil {
		http.Error(w, "Failed to read certificate data", http.StatusInternalServerError)
		return
	}

	// Validate that it's a valid certificate
	block, _ := pem.Decode(certData)
	if block == nil || block.Type != "CERTIFICATE" {
		http.Error(w, "Invalid PEM certificate format", http.StatusBadRequest)
		return
	}

	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		http.Error(w, "Invalid certificate format", http.StatusBadRequest)
		return
	}

	// Create filename with .pem extension
	filename := name + ".pem"
	filepath := filepath.Join(h.storageDir, filename)

	// Write certificate to file
	if err := os.WriteFile(filepath, certData, 0644); err != nil {
		log.Printf("❌ Failed to save certificate %s: %v", name, err)
		http.Error(w, "Failed to save certificate", http.StatusInternalServerError)
		return
	}

	log.Printf("✅ Trust anchor certificate uploaded: %s -> %s", name, filepath)

	// Return success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, `{"name":"%s","path":"%s","status":"uploaded"}`, name, filepath)
}

// HandleList lists all available trust anchors
func (h *TrustAnchorHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	files, err := os.ReadDir(h.storageDir)
	if err != nil {
		http.Error(w, "Failed to read trust anchors directory", http.StatusInternalServerError)
		return
	}

	var anchors []string
	for _, file := range files {
		if strings.HasSuffix(file.Name(), ".pem") {
			name := strings.TrimSuffix(file.Name(), ".pem")
			anchors = append(anchors, name)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"trust_anchors":%q}`, anchors)
}

// HandleDelete deletes a trust anchor certificate
func (h *TrustAnchorHandler) HandleDelete(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Validate name
	if strings.Contains(name, "/") || strings.Contains(name, "..") || name == "" {
		http.Error(w, "Invalid trust anchor name", http.StatusBadRequest)
		return
	}

	filename := name + ".pem"
	filepath := filepath.Join(h.storageDir, filename)

	// Check if file exists
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		http.Error(w, "Trust anchor not found", http.StatusNotFound)
		return
	}

	// Delete file
	if err := os.Remove(filepath); err != nil {
		log.Printf("❌ Failed to delete certificate %s: %v", name, err)
		http.Error(w, "Failed to delete certificate", http.StatusInternalServerError)
		return
	}

	log.Printf("✅ Trust anchor certificate deleted: %s", name)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"name":"%s","status":"deleted"}`, name)
}

// ResolvePath resolves a trust anchor name to its file path
func (h *TrustAnchorHandler) ResolvePath(name string) string {
	if strings.Contains(name, "/") || strings.Contains(name, "..") {
		return "" // Invalid name
	}
	return filepath.Join(h.storageDir, name+".pem")
}
