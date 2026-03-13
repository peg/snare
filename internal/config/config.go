// Package config manages the snare device configuration at ~/.snare/config.json.
package config

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const configFile = "config.json"

// Config holds device-level snare configuration.
type Config struct {
	DeviceID     string `json:"device_id"`               // unique ID for this machine
	DeviceSecret string `json:"device_secret,omitempty"`  // secret for API auth (never sent to snare.sh — only hash is stored)
	CallbackBase string `json:"callback_base"`            // e.g. https://snare.sh/c
	WebhookURL   string `json:"webhook_url,omitempty"`    // optional local override
}

// Load reads ~/.snare/config.json. Returns (nil, nil) if not initialized.
func Load() (*Config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}

	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Migrate: generate device secret if missing (pre-auth configs)
	if c.DeviceSecret == "" {
		secret, err := newDeviceSecret()
		if err != nil {
			return &c, nil // non-fatal: work without auth
		}
		c.DeviceSecret = secret
		_ = c.Save() // best-effort save
	}

	return &c, nil
}

// RegisterURL returns the URL for registering a token webhook with snare.sh.
func (c *Config) RegisterURL() string {
	// Derive API base from callback base: https://snare.sh/c → https://snare.sh/api
	base := c.CallbackBase
	if idx := len(base) - len("/c"); idx > 0 && base[idx:] == "/c" {
		base = base[:idx]
	}
	return base + "/api/register"
}

// RevokeURL returns the URL for revoking a token webhook registration.
func (c *Config) RevokeURL() string {
	base := c.CallbackBase
	if idx := len(base) - len("/c"); idx > 0 && base[idx:] == "/c" {
		base = base[:idx]
	}
	return base + "/api/revoke"
}

// Init creates a new device config with a fresh device ID.
// Errors if config already exists (use --force to overwrite).
func Init(callbackBase, webhookURL string, force bool) (*Config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}

	if !force {
		if _, err := os.Stat(path); err == nil {
			return nil, fmt.Errorf("already initialized — run `snare status` or use --force to reinitialize")
		}
	}

	deviceID, err := newDeviceID()
	if err != nil {
		return nil, err
	}

	if callbackBase == "" {
		callbackBase = "https://snare.sh/c"
	}

	deviceSecret, err := newDeviceSecret()
	if err != nil {
		return nil, err
	}

	c := &Config{
		DeviceID:     deviceID,
		DeviceSecret: deviceSecret,
		CallbackBase: callbackBase,
		WebhookURL:   webhookURL,
	}

	if err := c.Save(); err != nil {
		return nil, err
	}
	return c, nil
}

// Save writes config to ~/.snare/config.json atomically.
func (c *Config) Save() error {
	path, err := configPath()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("creating ~/.snare: %w", err)
	}

	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// CallbackURL returns the full callback URL for a given token ID.
func (c *Config) CallbackURL(tokenID string) string {
	return c.CallbackBase + "/" + tokenID
}

func newDeviceSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating device secret: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func newDeviceID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating device ID: %w", err)
	}
	return "dev-" + hex.EncodeToString(b), nil
}

func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".snare", configFile), nil
}
