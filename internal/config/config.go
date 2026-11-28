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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var httpClient = &http.Client{Timeout: 15 * time.Second}

const configFile = "config.json"

// The hosted receiver serves its API on snare.sh and canary callbacks on a
// neutral host, so planted files do not name the project.
const (
	DefaultAPIBase      = "https://snare.sh"
	DefaultCallbackBase = "https://edge.knowitsdown.com/c"
	legacyCallbackBase  = "https://snare.sh/c"
)

// Config holds device-level snare configuration.
type Config struct {
	DeviceID     string `json:"device_id"`               // unique ID for this machine
	DeviceSecret string `json:"device_secret,omitempty"` // secret for API auth (only its hash leaves this machine)
	CallbackBase string `json:"callback_base"`           // base of planted callback URLs, e.g. https://edge.knowitsdown.com/c
	APIBaseURL   string `json:"api_base,omitempty"`      // receiver API; derived from CallbackBase when empty
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

	// Same Worker and database on both hosts, so only new plants change.
	if c.CallbackBase == legacyCallbackBase && c.APIBaseURL == "" {
		c.CallbackBase, c.APIBaseURL = DefaultCallbackBase, DefaultAPIBase
		_ = c.Save()
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

	callbackBase, apiBase, err := resolveBases(callbackBase)
	if err != nil {
		return nil, err
	}

	deviceSecret, err := newDeviceSecret()
	if err != nil {
		return nil, err
	}

	// The receiver mints the device ID (prevents squatting). Fail closed: a
	// locally invented ID is unknown to the receiver, so every later
	// registration would be rejected and no canary could ever alert.
	deviceID, err := registerDeviceWithServer(apiBase, deviceSecret)
	if err != nil {
		return nil, fmt.Errorf("enrolling this device with %s: %w — nothing was written; try again when the receiver is reachable", apiBase, err)
	}

	c := &Config{
		DeviceID:     deviceID,
		DeviceSecret: deviceSecret,
		CallbackBase: callbackBase,
		APIBaseURL:   apiBase,
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
	if c.APIBaseURL != "" {
		return c.APIBaseURL
	}
	return strings.TrimSuffix(c.CallbackBase, "/c")
}

// resolveBases picks the callback and API bases from the argument,
// SNARE_CALLBACK_BASE and SNARE_API_BASE. A custom callback base without an
// API base is a self-hosted receiver that serves both on one host.
func resolveBases(callbackBase string) (string, string, error) {
	if callbackBase == "" {
		callbackBase = os.Getenv("SNARE_CALLBACK_BASE")
	}
	callbackBase = strings.TrimSuffix(strings.TrimSpace(callbackBase), "/")
	apiBase := strings.TrimSuffix(strings.TrimSpace(os.Getenv("SNARE_API_BASE")), "/")
	switch {
	case callbackBase == "" && apiBase != "":
		return "", "", fmt.Errorf("SNARE_API_BASE needs SNARE_CALLBACK_BASE: canaries must call back to the receiver that registers them")
	case callbackBase == "" || callbackBase == DefaultCallbackBase:
		if apiBase != "" && apiBase != DefaultAPIBase {
			return "", "", fmt.Errorf("the hosted callback base only works with %s", DefaultAPIBase)
		}
		callbackBase, apiBase = DefaultCallbackBase, DefaultAPIBase
	case apiBase == DefaultAPIBase:
		return "", "", fmt.Errorf("custom callback domains need your own receiver; see docs/custom-domain.md")
	case apiBase == "":
		apiBase = strings.TrimSuffix(callbackBase, "/c")
	}
	for _, u := range []string{callbackBase, apiBase} {
		if p, err := url.Parse(u); err != nil || (p.Scheme != "https" && p.Scheme != "http") || p.Host == "" || p.User != nil || p.RawQuery != "" || p.Fragment != "" {
			return "", "", fmt.Errorf("invalid receiver URL %q: use http(s)://host[/path]", u)
		}
	}
	return callbackBase, apiBase, nil
}

// Reenroll replaces the device identity with a fresh server-minted one. It is
// the recovery path for configs whose device ID the receiver does not know
// (for example one created by an older CLI's offline fallback).
func (c *Config) Reenroll() error {
	secret, err := newDeviceSecret()
	if err != nil {
		return err
	}
	id, err := registerDeviceWithServer(c.APIBase(), secret)
	if err != nil {
		return fmt.Errorf("enrolling this device with %s: %w", c.APIBase(), err)
	}
	c.DeviceID, c.DeviceSecret = id, secret
	return c.Save()
}

// enrollRetryDelay is the wait before retry n (1-based); tests shorten it.
var enrollRetryDelay = func(n int) time.Duration { return time.Duration(n) * 2 * time.Second }

const enrollAttempts = 3

// registerDeviceWithServer calls POST /api/devices to get a server-minted
// device ID, retrying network errors, 429 and 5xx responses.
func registerDeviceWithServer(apiBase, deviceSecret string) (string, error) {
	var lastErr error
	for attempt := 1; attempt <= enrollAttempts; attempt++ {
		id, retry, err := enrollOnce(apiBase, deviceSecret)
		if err == nil {
			return id, nil
		}
		lastErr = err
		if !retry || attempt == enrollAttempts {
			break
		}
		time.Sleep(enrollRetryDelay(attempt))
	}
	return "", lastErr
}

// enrollOnce makes one enrollment request. SNARE_ENROLLMENT_TOKEN is sent only
// for this request and is never persisted.
func enrollOnce(apiBase, deviceSecret string) (id string, retry bool, err error) {
	payload, _ := json.Marshal(map[string]string{"device_secret": deviceSecret})
	req, err := http.NewRequest(http.MethodPost, apiBase+"/api/devices", bytes.NewReader(payload))
	if err != nil {
		return "", false, err
	}
	req.Header.Set("Content-Type", "application/json")
	if enrollmentToken := strings.TrimSpace(os.Getenv("SNARE_ENROLLMENT_TOKEN")); enrollmentToken != "" {
		req.Header.Set("Authorization", "Bearer "+enrollmentToken)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", true, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		retry := resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500
		return "", retry, fmt.Errorf("device enrollment returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(data)))
	}
	var result struct {
		DeviceID string `json:"device_id"`
	}
	data, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(data, &result); err != nil {
		return "", false, fmt.Errorf("decoding device enrollment response: %w", err)
	}
	if result.DeviceID == "" {
		return "", false, fmt.Errorf("device enrollment response omitted device_id")
	}
	return result.DeviceID, false, nil
}

func configPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".snare", configFile), nil
}
