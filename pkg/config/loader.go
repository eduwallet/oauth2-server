package config

import (
	"fmt"
	"oauth2-server/internal/utils"
	"os"

	"gopkg.in/yaml.v3"
)

func (c *Config) NormalizeAllClientRedirectURIs() {
	for i := range c.Clients {
		for j, uri := range c.Clients[i].RedirectURIs {
			c.Clients[i].RedirectURIs[j] = utils.NormalizeRedirectURI(c.PublicBaseURL, uri)
		}
	}
}

// LoadFromPath loads configuration from a specific config file path
func LoadFromPath(configPath string) (*Config, error) {
	cfg := &Config{}

	// 1. Load YAML config
	if _, err := os.Stat(configPath); err == nil {
		if err := LoadFromFile(configPath, cfg); err != nil {
			return nil, fmt.Errorf("failed to load config file: %w", err)
		}
	}

	// 2. Apply environment variable overrides
	cfg.LoadFromEnv()

	// 3. Set defaults for missing configuration
	cfg.SetDefaults()

	// 4. Normalize redirect URIs with the final base URL
	cfg.NormalizeAllClientRedirectURIs()

	// 5. Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

// LoadFromFile loads configuration from a YAML file
func LoadFromFile(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file: %w", err)
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return fmt.Errorf("failed to parse config file: %w", err)
	}

	return nil
}
