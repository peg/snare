package config

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	return dir
}

func TestLoad(t *testing.T) {
	t.Run("missing config returns nil nil", func(t *testing.T) {
		setupHome(t)

		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg != nil {
			t.Fatalf("Load() = %#v, want nil", cfg)
		}
	})

	t.Run("invalid JSON returns parse error", func(t *testing.T) {
		home := setupHome(t)
		path := filepath.Join(home, ".snare", configFile)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		if err := os.WriteFile(path, []byte("{not-json"), 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		cfg, err := Load()
		if err == nil {
			t.Fatal("Load() error = nil, want parse error")
		}
		if cfg != nil {
			t.Fatalf("Load() cfg = %#v, want nil", cfg)
		}
		if !strings.Contains(err.Error(), "parsing config") {
			t.Fatalf("Load() error = %v, want parsing config", err)
		}
	})

	t.Run("migrates missing device secret and saves it", func(t *testing.T) {
		home := setupHome(t)
		path := filepath.Join(home, ".snare", configFile)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}

		original := Config{
			DeviceID:     "dev-existing",
			CallbackBase: "https://snare.sh/c",
			WebhookURL:   "https://hooks.example.test/a",
		}
		data, err := json.Marshal(original)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		cfg, err := Load()
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if cfg == nil {
			t.Fatal("Load() returned nil config")
		}
		if cfg.DeviceID != original.DeviceID {
			t.Fatalf("DeviceID = %q, want %q", cfg.DeviceID, original.DeviceID)
		}
		if cfg.DeviceSecret == "" {
			t.Fatal("DeviceSecret was not migrated")
		}
		if len(cfg.DeviceSecret) != 64 {
			t.Fatalf("DeviceSecret len = %d, want 64", len(cfg.DeviceSecret))
		}

		reloaded, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}
		var persisted Config
		if err := json.Unmarshal(reloaded, &persisted); err != nil {
			t.Fatalf("Unmarshal persisted config: %v", err)
		}
		if persisted.DeviceSecret != cfg.DeviceSecret {
			t.Fatalf("persisted DeviceSecret = %q, want %q", persisted.DeviceSecret, cfg.DeviceSecret)
		}
	})
}

func TestInit(t *testing.T) {
	t.Run("uses server-assigned device ID", func(t *testing.T) {
		home := setupHome(t)
		var gotSecret string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s, want POST", r.Method)
			}
			if r.URL.Path != "/api/devices" {
				t.Fatalf("path = %s, want /api/devices", r.URL.Path)
			}

			var body struct {
				DeviceSecret string `json:"device_secret"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatalf("Decode request: %v", err)
			}
			gotSecret = body.DeviceSecret
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"device_id":"dev-from-server"}`))
		}))
		defer srv.Close()

		cfg, err := Init(srv.URL+"/c", "https://hooks.example.test/snare", false)
		if err != nil {
			t.Fatalf("Init: %v", err)
		}
		if cfg.DeviceID != "dev-from-server" {
			t.Fatalf("DeviceID = %q, want dev-from-server", cfg.DeviceID)
		}
		if cfg.DeviceSecret == "" {
			t.Fatal("DeviceSecret is empty")
		}
		if gotSecret != cfg.DeviceSecret {
			t.Fatalf("server saw secret %q, want %q", gotSecret, cfg.DeviceSecret)
		}

		path := filepath.Join(home, ".snare", configFile)
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat config: %v", err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("config perms = %o, want 0600", info.Mode().Perm())
		}
	})

	t.Run("falls back to local device ID when server unavailable", func(t *testing.T) {
		setupHome(t)

		cfg, err := Init("://bad/c", "", false)
		if err != nil {
			t.Fatalf("Init: %v", err)
		}
		if !strings.HasPrefix(cfg.DeviceID, "dev-") {
			t.Fatalf("DeviceID = %q, want dev-* fallback", cfg.DeviceID)
		}
		if len(cfg.DeviceID) != 36 {
			t.Fatalf("DeviceID len = %d, want 36", len(cfg.DeviceID))
		}
		if cfg.CallbackBase != "://bad/c" {
			t.Fatalf("CallbackBase = %q, want custom value preserved", cfg.CallbackBase)
		}
	})

	t.Run("defaults callback base when empty", func(t *testing.T) {
		setupHome(t)

		cfg, err := Init("", "", false)
		if err != nil {
			t.Fatalf("Init: %v", err)
		}
		if cfg.CallbackBase != "https://snare.sh/c" {
			t.Fatalf("CallbackBase = %q, want default", cfg.CallbackBase)
		}
	})

	t.Run("refuses overwrite without force", func(t *testing.T) {
		setupHome(t)

		if _, err := Init("://bad/c", "", false); err != nil {
			t.Fatalf("first Init: %v", err)
		}
		if _, err := Init("://bad/c", "", false); err == nil {
			t.Fatal("second Init() error = nil, want already initialized error")
		}
	})

	t.Run("force overwrites existing config", func(t *testing.T) {
		setupHome(t)

		first, err := Init("://bad/c", "https://hooks.example.test/one", false)
		if err != nil {
			t.Fatalf("first Init: %v", err)
		}
		second, err := Init("://bad/c", "https://hooks.example.test/two", true)
		if err != nil {
			t.Fatalf("forced Init: %v", err)
		}
		if first.DeviceID == second.DeviceID {
			t.Fatalf("DeviceID did not change on force reinit: %q", second.DeviceID)
		}
		if second.WebhookURL != "https://hooks.example.test/two" {
			t.Fatalf("WebhookURL = %q, want overwrite", second.WebhookURL)
		}
	})
}

func TestSave(t *testing.T) {
	t.Run("writes config atomically", func(t *testing.T) {
		home := setupHome(t)
		cfg := &Config{
			DeviceID:     "dev-abc",
			DeviceSecret: strings.Repeat("a", 64),
			CallbackBase: "https://snare.sh/c",
			WebhookURL:   "https://hooks.example.test",
		}

		if err := cfg.Save(); err != nil {
			t.Fatalf("Save: %v", err)
		}

		path := filepath.Join(home, ".snare", configFile)
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile: %v", err)
		}

		var saved Config
		if err := json.Unmarshal(data, &saved); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}
		if saved != *cfg {
			t.Fatalf("saved config = %#v, want %#v", saved, *cfg)
		}

		if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
			t.Fatalf("tmp file exists after Save: %v", err)
		}
	})

	t.Run("returns error when config dir cannot be created", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "homefile")
		if err := os.WriteFile(parent, []byte("x"), 0600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		t.Setenv("HOME", parent)

		cfg := &Config{DeviceID: "dev-abc", CallbackBase: "https://snare.sh/c"}
		if err := cfg.Save(); err == nil {
			t.Fatal("Save() error = nil, want mkdir failure")
		}
	})
}

func TestURLsAndSecrets(t *testing.T) {
	t.Run("URL helpers derive from callback base", func(t *testing.T) {
		tests := []struct {
			name         string
			callbackBase string
			apiBase      string
			callbackURL  string
		}{
			{
				name:         "standard callback suffix",
				callbackBase: "https://snare.sh/c",
				apiBase:      "https://snare.sh",
				callbackURL:  "https://snare.sh/c/tok-123",
			},
			{
				name:         "custom callback path without suffix stripping",
				callbackBase: "https://example.test/custom",
				apiBase:      "https://example.test/custom",
				callbackURL:  "https://example.test/custom/tok-123",
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				cfg := &Config{CallbackBase: tt.callbackBase}
				if got := cfg.APIBase(); got != tt.apiBase {
					t.Fatalf("APIBase() = %q, want %q", got, tt.apiBase)
				}
				if got := cfg.RegisterURL(); got != tt.apiBase+"/api/register" {
					t.Fatalf("RegisterURL() = %q", got)
				}
				if got := cfg.RevokeURL(); got != tt.apiBase+"/api/revoke" {
					t.Fatalf("RevokeURL() = %q", got)
				}
				if got := cfg.DevicesURL(); got != tt.apiBase+"/api/devices" {
					t.Fatalf("DevicesURL() = %q", got)
				}
				if got := cfg.CallbackURL("tok-123"); got != tt.callbackURL {
					t.Fatalf("CallbackURL() = %q, want %q", got, tt.callbackURL)
				}
			})
		}
	})

	t.Run("NewDeviceSecret returns 256-bit hex secret", func(t *testing.T) {
		secret1, err := NewDeviceSecret()
		if err != nil {
			t.Fatalf("NewDeviceSecret: %v", err)
		}
		secret2, err := newDeviceSecret()
		if err != nil {
			t.Fatalf("newDeviceSecret: %v", err)
		}

		for _, secret := range []string{secret1, secret2} {
			if len(secret) != 64 {
				t.Fatalf("secret len = %d, want 64", len(secret))
			}
			if strings.IndexFunc(secret, func(r rune) bool {
				return !strings.ContainsRune("0123456789abcdef", r)
			}) != -1 {
				t.Fatalf("secret %q contains non-hex characters", secret)
			}
		}
		if secret1 == secret2 {
			t.Fatal("two generated secrets matched; want different values")
		}
	})
}

func TestRegisterDeviceWithServer(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
		wantID string
	}{
		{name: "success", status: http.StatusOK, body: `{"device_id":"dev-test"}`, wantID: "dev-test"},
		{name: "non-200", status: http.StatusForbidden, body: `{"device_id":"dev-test"}`, wantID: ""},
		{name: "invalid json", status: http.StatusOK, body: `{`, wantID: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/devices" {
					t.Fatalf("path = %s, want /api/devices", r.URL.Path)
				}
				w.WriteHeader(tt.status)
				_, _ = w.Write([]byte(tt.body))
			}))
			defer srv.Close()

			if got := registerDeviceWithServer(srv.URL, strings.Repeat("a", 64)); got != tt.wantID {
				t.Fatalf("registerDeviceWithServer() = %q, want %q", got, tt.wantID)
			}
		})
	}
}
