package handlers

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
)

// TrustAnchorStorage interface for storing trust anchors
type TrustAnchorStorage interface {
	StoreTrustAnchor(ctx context.Context, name string, certificateData []byte) error
	GetTrustAnchor(ctx context.Context, name string) ([]byte, error)
	ListTrustAnchors(ctx context.Context) ([]string, error)
	DeleteTrustAnchor(ctx context.Context, name string) error
}

// TrustAnchorHandler manages trust anchor certificate uploads
type TrustAnchorHandler struct {
	storage TrustAnchorStorage
}

// NewTrustAnchorHandler creates a new trust anchor handler
func NewTrustAnchorHandler(storage TrustAnchorStorage) *TrustAnchorHandler {
	return &TrustAnchorHandler{
		storage: storage,
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

	// Store certificate using the storage backend
	if err := h.storage.StoreTrustAnchor(r.Context(), name, certData); err != nil {
		log.Printf("❌ Failed to save certificate %s: %v", name, err)
		http.Error(w, "Failed to save certificate", http.StatusInternalServerError)
		return
	}

	log.Printf("✅ Trust anchor certificate uploaded: %s", name)

	// Return success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	fmt.Fprintf(w, `{"name":"%s","status":"uploaded"}`, name)
}

// HandleList lists all available trust anchors
func (h *TrustAnchorHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	anchors, err := h.storage.ListTrustAnchors(r.Context())
	if err != nil {
		http.Error(w, "Failed to read trust anchors", http.StatusInternalServerError)
		return
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

	// Check if trust anchor exists
	if _, err := h.storage.GetTrustAnchor(r.Context(), name); err != nil {
		http.Error(w, "Trust anchor not found", http.StatusNotFound)
		return
	}

	// Delete trust anchor
	if err := h.storage.DeleteTrustAnchor(r.Context(), name); err != nil {
		log.Printf("❌ Failed to delete certificate %s: %v", name, err)
		http.Error(w, "Failed to delete certificate", http.StatusInternalServerError)
		return
	}

	log.Printf("✅ Trust anchor certificate deleted: %s", name)

	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"name":"%s","status":"deleted"}`, name)
}

// ResolvePath resolves a trust anchor name to its certificate data
func (h *TrustAnchorHandler) ResolvePath(name string) ([]byte, error) {
	if strings.Contains(name, "/") || strings.Contains(name, "..") {
		return nil, fmt.Errorf("invalid trust anchor name")
	}
	return h.storage.GetTrustAnchor(context.Background(), name)
}
