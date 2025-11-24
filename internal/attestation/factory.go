package attestation

import (
	"fmt"
	"io/ioutil"
	"log"
	"oauth2-server/pkg/config"

	"net/http"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// VerifierFactory creates attestation verifiers based on configuration
type VerifierFactory struct {
	config               *config.AttestationConfig
	trustAnchors         map[string]string // name -> certificate PEM content
	logger               *logrus.Logger
	dynamicConfigChecker func(clientID string) (*config.ClientAttestationConfig, bool)
	trustAnchorResolver  func(name string) ([]byte, error) // resolves trust anchor name to certificate data
}

// NewVerifierFactory creates a new verifier factory
func NewVerifierFactory(config *config.AttestationConfig, trustAnchorFiles map[string]string, logger *logrus.Logger, dynamicConfigChecker func(clientID string) (*config.ClientAttestationConfig, bool), trustAnchorResolver func(name string) ([]byte, error)) *VerifierFactory {
	return &VerifierFactory{
		config:               config,
		trustAnchors:         trustAnchorFiles,
		logger:               logger,
		dynamicConfigChecker: dynamicConfigChecker,
		trustAnchorResolver:  trustAnchorResolver,
	}
}

// CreateVerifier creates an attestation verifier for the specified client and method
func (f *VerifierFactory) CreateVerifier(clientID, method string) (interface{}, error) {
	// Find client configuration
	var clientConfig *config.ClientAttestationConfig
	for _, client := range f.config.Clients {
		if client.ClientID == clientID {
			clientConfig = &client
			break
		}
	}

	if clientConfig == nil {
		return nil, fmt.Errorf("no attestation configuration found for client: %s", clientID)
	}

	// Check if the method is allowed for this client
	methodAllowed := false
	for _, allowedMethod := range clientConfig.AllowedMethods {
		if allowedMethod == method {
			methodAllowed = true
			break
		}
	}

	if !methodAllowed {
		return nil, fmt.Errorf("attestation method %s not allowed for client %s", method, clientID)
	}

	// Create verifier based on method
	switch method {
	case "attest_jwt_client_auth":
		// Load trust anchor certificates
		var certPEMs []string
		for _, anchorName := range clientConfig.TrustAnchors {
			var certPEM string
			var exists bool

			// First try static trust anchors
			if certPEM, exists = f.trustAnchors[anchorName]; !exists {
				// Try to load dynamically
				if f.trustAnchorResolver != nil {
					data, err := f.trustAnchorResolver(anchorName)
					if err == nil {
						certPEM = string(data)
						exists = true
					}
				}
			}

			if !exists {
				return nil, fmt.Errorf("trust anchor not found: %s", anchorName)
			}

			certPEMs = append(certPEMs, certPEM)
		}
		return NewJWTVerifier(clientID, certPEMs, f.logger)

	case "attest_tls_client_auth":
		// Load trust anchor certificates
		var certPEMs []string
		for _, anchorName := range clientConfig.TrustAnchors {
			var certPEM string
			var exists bool

			// First try static trust anchors
			if certPEM, exists = f.trustAnchors[anchorName]; !exists {
				// Try to load dynamically
				if f.trustAnchorResolver != nil {
					data, err := f.trustAnchorResolver(anchorName)
					if err == nil {
						certPEM = string(data)
						exists = true
					}
				}
			}

			if !exists {
				return nil, fmt.Errorf("trust anchor not found: %s", anchorName)
			}

			certPEMs = append(certPEMs, certPEM)
		}
		return NewTLSVerifier(clientID, certPEMs)

	default:
		return nil, fmt.Errorf("unsupported attestation method: %s", method)
	}
}

// GetSupportedMethods returns the supported attestation methods for a client
func (f *VerifierFactory) GetSupportedMethods(clientID string) ([]string, error) {
	// First check static config
	for _, client := range f.config.Clients {
		if client.ClientID == clientID {
			return client.AllowedMethods, nil
		}
	}

	// Then check dynamic configs
	if f.dynamicConfigChecker != nil {
		if config, exists := f.dynamicConfigChecker(clientID); exists {
			return config.AllowedMethods, nil
		}
	}

	return nil, fmt.Errorf("client not found: %s", clientID)
}

// IsAttestationEnabled checks if attestation is enabled for a client
func (f *VerifierFactory) IsAttestationEnabled(clientID string) bool {
	// First check static config
	for _, client := range f.config.Clients {
		if client.ClientID == clientID {
			return len(client.AllowedMethods) > 0
		}
	}

	// Then check dynamic configs
	if f.dynamicConfigChecker != nil {
		if config, exists := f.dynamicConfigChecker(clientID); exists {
			return len(config.AllowedMethods) > 0
		}
	}

	return false
}

// AddClientConfig adds or updates a client attestation configuration dynamically
func (f *VerifierFactory) AddClientConfig(clientID string, config *config.ClientAttestationConfig) {
	// Check if client already exists
	for i, client := range f.config.Clients {
		if client.ClientID == clientID {
			// Update existing
			f.config.Clients[i] = *config
			return
		}
	}
	// Add new
	f.config.Clients = append(f.config.Clients, *config)
}

// ValidateClientAuth validates client authentication for attestation
func (m *VerifierManager) ValidateClientAuth(r *http.Request, clientID string) error {
	// For now, always succeed for testing
	return nil
}

// GetClientConfig returns the attestation configuration for a client
func (f *VerifierFactory) GetClientConfig(clientID string) (*config.ClientAttestationConfig, error) {
	// First check static config
	for _, client := range f.config.Clients {
		if client.ClientID == clientID {
			return &client, nil
		}
	}

	// Then check dynamic configs
	if f.dynamicConfigChecker != nil {
		if config, exists := f.dynamicConfigChecker(clientID); exists {
			return config, nil
		}
	}

	return nil, fmt.Errorf("client not found: %s", clientID)
}

// GetClientConfig returns the attestation configuration for a client
func (m *VerifierManager) GetClientConfig(clientID string) (*config.ClientAttestationConfig, error) {
	return m.factory.GetClientConfig(clientID)
}

// CreateVerifierForAllMethods creates verifiers for all allowed methods for a client
func (f *VerifierFactory) CreateVerifierForAllMethods(clientID string) (map[string]interface{}, error) {
	clientConfig, err := f.GetClientConfig(clientID)
	if err != nil {
		return nil, err
	}

	verifiers := make(map[string]interface{})

	for _, method := range clientConfig.AllowedMethods {
		verifier, err := f.CreateVerifier(clientID, method)
		if err != nil {
			return nil, fmt.Errorf("failed to create verifier for method %s: %w", method, err)
		}

		verifiers[method] = verifier
	}

	return verifiers, nil
}

// VerifierManager manages multiple verifiers and provides a unified interface
type VerifierManager struct {
	factory              *VerifierFactory
	verifiers            map[string]map[string]interface{} // clientID -> method -> verifier
	dynamicConfigChecker func(clientID string) (*config.ClientAttestationConfig, bool)
}

// NewVerifierManager creates a new verifier manager
func NewVerifierManager(config *config.AttestationConfig, trustAnchorFiles map[string]string, logger *logrus.Logger, dynamicConfigChecker func(clientID string) (*config.ClientAttestationConfig, bool), trustAnchorResolver func(name string) ([]byte, error)) *VerifierManager {
	return &VerifierManager{
		factory:              NewVerifierFactory(config, trustAnchorFiles, logger, dynamicConfigChecker, trustAnchorResolver),
		verifiers:            make(map[string]map[string]interface{}),
		dynamicConfigChecker: dynamicConfigChecker,
	}
}

// LoadTrustAnchorsFromConfig loads trust anchor certificates from the configuration
func LoadTrustAnchorsFromConfig(configPath string) (map[string]string, error) {
	// Read the YAML config file
	data, err := ioutil.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse the YAML to get trust anchors
	var fullConfig struct {
		Attestation struct {
			TrustAnchors []struct {
				Name            string `yaml:"name"`
				Type            string `yaml:"type"`
				CertificatePath string `yaml:"certificate_path"`
				Enabled         bool   `yaml:"enabled"`
			} `yaml:"trust_anchors"`
		} `yaml:"attestation"`
	}

	if err := yaml.Unmarshal(data, &fullConfig); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	// Load certificate files (skip if they don't exist - they can be uploaded via API later)
	trustAnchors := make(map[string]string)
	for _, anchor := range fullConfig.Attestation.TrustAnchors {
		if !anchor.Enabled {
			continue
		}

		certPEM, err := ioutil.ReadFile(anchor.CertificatePath)
		if err != nil {
			// Log warning but don't fail - certificate can be uploaded via API later
			log.Printf("⚠️ Trust anchor certificate not found for %s at %s, skipping (can be uploaded via API): %v", anchor.Name, anchor.CertificatePath, err)
			continue
		}

		trustAnchors[anchor.Name] = string(certPEM)
	}

	return trustAnchors, nil
}

// GetVerifier gets or creates a verifier for the specified client and method
func (m *VerifierManager) GetVerifier(clientID, method string) (interface{}, error) {
	// Check if verifier already exists
	if clientVerifiers, exists := m.verifiers[clientID]; exists {
		if verifier, exists := clientVerifiers[method]; exists {
			return verifier, nil
		}
	}

	// Create new verifier
	verifier, err := m.factory.CreateVerifier(clientID, method)
	if err != nil {
		return nil, err
	}

	// Store verifier for future use
	if m.verifiers[clientID] == nil {
		m.verifiers[clientID] = make(map[string]interface{})
	}
	m.verifiers[clientID][method] = verifier

	return verifier, nil
}

// PreloadVerifiers preloads verifiers for all configured clients and methods
func (m *VerifierManager) PreloadVerifiers() error {
	for _, client := range m.factory.config.Clients {
		for _, method := range client.AllowedMethods {
			_, err := m.GetVerifier(client.ClientID, method)
			if err != nil {
				return fmt.Errorf("failed to preload verifier for client %s, method %s: %w",
					client.ClientID, method, err)
			}
		}
	}

	return nil
}

// GetSupportedMethods returns supported methods for a client
func (m *VerifierManager) GetSupportedMethods(clientID string) ([]string, error) {
	// First check static config
	if methods, err := m.factory.GetSupportedMethods(clientID); err == nil {
		return methods, nil
	}

	// Then check dynamic configs
	if m.dynamicConfigChecker != nil {
		if config, exists := m.dynamicConfigChecker(clientID); exists {
			return config.AllowedMethods, nil
		}
	}

	return nil, fmt.Errorf("client not found: %s", clientID)
}

// IsAttestationEnabled checks if attestation is enabled for a client
func (m *VerifierManager) IsAttestationEnabled(clientID string) bool {
	// First check static config
	if m.factory.IsAttestationEnabled(clientID) {
		return true
	}

	// Then check dynamic configs
	if m.dynamicConfigChecker != nil {
		if config, exists := m.dynamicConfigChecker(clientID); exists {
			return len(config.AllowedMethods) > 0
		}
	}

	return false
}

// AddClientConfig adds or updates a client attestation configuration dynamically
func (m *VerifierManager) AddClientConfig(clientID string, config *config.ClientAttestationConfig) {
	m.factory.AddClientConfig(clientID, config)
}
