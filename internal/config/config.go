// Package config manages the snare device configuration at ~/.snare/config.json.
package config

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var httpClient = &http.Client{Timeout: 15 * time.Second}

const configFile = "config.json"

// Config holds device-level snare configuration.
type Config struct {
	DeviceID     string `json:"device_id"`               // unique ID for this machine
	DeviceSecret string `json:"device_secret,omitempty"` // secret for API auth (never sent to snare.sh — only hash is stored)
	CallbackBase string `json:"callback_base"`           // e.g. https://snare.sh/c
	WebhookURL   string `json:"webhook_url,omitempty"`   // optional local override
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
	return c.APIBase() + "/api/register"
}

// RevokeURL returns the URL for revoking a token webhook registration.
func (c *Config) RevokeURL() string {
	return c.APIBase() + "/api/revoke"
}

// DevicesURL returns the URL for creating a server-assigned device.
func (c *Config) DevicesURL() string {
	return c.APIBase() + "/api/devices"
}

// RotateURL returns the URL for rotating the device secret on snare.sh.
func (c *Config) RotateURL() string {
	return c.APIBase() + "/api/rotate"
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

	if callbackBase == "" {
		callbackBase = strings.TrimSpace(os.Getenv("SNARE_CALLBACK_BASE"))
		if callbackBase == "" {
			callbackBase = "https://snare.sh/c"
		}
	}

	deviceSecret, err := newDeviceSecret()
	if err != nil {
		return nil, err
	}

	// Try to get a server-assigned device ID (prevents squatting). Managed
	// snare.sh retains the legacy offline fallback; custom servers fail closed.
	deviceID := ""
	apiBase := callbackBase
	if len(apiBase) > 2 && apiBase[len(apiBase)-2:] == "/c" {
		apiBase = apiBase[:len(apiBase)-2]
	}
	deviceID, registerErr := registerDeviceWithServer(apiBase, deviceSecret)
	if deviceID == "" {
		if callbackBase != "https://snare.sh/c" {
			return nil, fmt.Errorf("registering device with self-hosted server: %w", registerErr)
		}
		// Server unreachable — generate local ID as fallback
		deviceID, err = newDeviceID()
		if err != nil {
			return nil, err
		}
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
	return NewDeviceSecret()
}

// NewDeviceSecret generates a new 256-bit random device secret. Exported for rotation.
func NewDeviceSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating device secret: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// APIBase returns the base URL for API calls (e.g. https://snare.sh).
func (c *Config) APIBase() string {
	base := c.CallbackBase
	if idx := len(base) - len("/c"); idx > 0 && base[idx:] == "/c" {
		base = base[:idx]
	}
	return base
}

// registerDeviceWithServer calls POST /api/devices to get a server-minted device ID.
// SNARE_ENROLLMENT_TOKEN is sent only for this request and is never persisted.
func registerDeviceWithServer(apiBase, deviceSecret string) (string, error) {
	payload, _ := json.Marshal(map[string]string{"device_secret": deviceSecret})
	req, err := http.NewRequest(http.MethodPost, apiBase+"/api/devices", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if enrollmentToken := strings.TrimSpace(os.Getenv("SNARE_ENROLLMENT_TOKEN")); enrollmentToken != "" {
		req.Header.Set("Authorization", "Bearer "+enrollmentToken)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", fmt.Errorf("device enrollment returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var result struct {
		DeviceID string `json:"device_id"`
	}
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &result); err != nil {
		return "", fmt.Errorf("decoding device enrollment response: %w", err)
	}
	if result.DeviceID == "" {
		return "", fmt.Errorf("device enrollment response omitted device_id")
	}
	return result.DeviceID, nil
}

func newDeviceID() (string, error) {
	b := make([]byte, 16) // 128 bits (was 64 bits — increased per security audit)
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
