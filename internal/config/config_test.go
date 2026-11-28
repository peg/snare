package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
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

// fakeManagedEnrollment routes every enrollment request (including ones to
// the default https://snare.sh) to a local server minting unique device IDs,
// so tests never enroll devices on production.
func fakeManagedEnrollment(t *testing.T) {
	t.Helper()
	var n int
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		n++
		id := fmt.Sprintf("dev-fake-%d", n)
		mu.Unlock()
		_, _ = fmt.Fprintf(w, `{"device_id":%q}`, id)
	}))
	t.Cleanup(srv.Close)
	target, _ := url.Parse(srv.URL)
	old := httpClient
	httpClient = &http.Client{Timeout: time.Second, Transport: rewriteTransport{target}}
	t.Cleanup(func() { httpClient = old })
}

type rewriteTransport struct{ target *url.URL }

func (rt rewriteTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.URL.Scheme, r.URL.Host = rt.target.Scheme, rt.target.Host
	return http.DefaultTransport.RoundTrip(r)
}

func noEnrollDelay(t *testing.T) {
	old := enrollRetryDelay
	enrollRetryDelay = func(int) time.Duration { return 0 }
	t.Cleanup(func() { enrollRetryDelay = old })
}

func TestInit(t *testing.T) {
	t.Run("uses server-assigned device ID", func(t *testing.T) {
		home := setupHome(t)
		t.Setenv("SNARE_ENROLLMENT_TOKEN", "enrollment-secret")
		var gotSecret string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Fatalf("method = %s, want POST", r.Method)
			}
			if r.URL.Path != "/api/devices" {
				t.Fatalf("path = %s, want /api/devices", r.URL.Path)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer enrollment-secret" {
				t.Fatalf("Authorization = %q, want enrollment bearer token", got)
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

	t.Run("fails closed and writes nothing when managed enrollment fails", func(t *testing.T) {
		home := setupHome(t)
		noEnrollDelay(t)
		var calls int
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			w.WriteHeader(http.StatusTooManyRequests)
		}))
		defer srv.Close()
		target, _ := url.Parse(srv.URL)
		old := httpClient
		httpClient = &http.Client{Timeout: time.Second, Transport: rewriteTransport{target}}
		defer func() { httpClient = old }()

		if _, err := Init("", "", false); err == nil {
			t.Fatal("Init() error = nil, want enrollment failure instead of a local device ID")
		}
		if calls != enrollAttempts {
			t.Fatalf("enrollment attempts = %d, want %d retries on 429", calls, enrollAttempts)
		}
		if _, err := os.Stat(filepath.Join(home, ".snare", configFile)); !os.IsNotExist(err) {
			t.Fatalf("config written after failed enrollment: %v", err)
		}
	})

	t.Run("fails closed when custom server enrollment fails", func(t *testing.T) {
		setupHome(t)

		if _, err := Init("://bad/c", "", false); err == nil {
			t.Fatal("Init() error = nil, want custom enrollment failure")
		}
	})

	t.Run("defaults callback base when empty", func(t *testing.T) {
		setupHome(t)
		fakeManagedEnrollment(t)

		cfg, err := Init("", "", false)
		if err != nil {
			t.Fatalf("Init: %v", err)
		}
		if cfg.CallbackBase != DefaultCallbackBase || cfg.APIBase() != DefaultAPIBase {
			t.Fatalf("bases = %q, %q, want defaults", cfg.CallbackBase, cfg.APIBase())
		}
	})

	t.Run("uses callback base from environment", func(t *testing.T) {
		setupHome(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"device_id":"dev-from-env"}`))
		}))
		defer srv.Close()
		t.Setenv("SNARE_CALLBACK_BASE", srv.URL+"/c")

		cfg, err := Init("", "", false)
		if err != nil {
			t.Fatalf("Init: %v", err)
		}
		if cfg.CallbackBase != srv.URL+"/c" {
			t.Fatalf("CallbackBase = %q, want environment value", cfg.CallbackBase)
		}
	})

	t.Run("resolves callback and API bases", func(t *testing.T) {
		for _, tt := range []struct{ callback, api, wantCallback, wantAPI string }{
			{"https://canary.example.com/c", "", "https://canary.example.com/c", "https://canary.example.com"},
			{"https://canary.example.com/c/", "https://snare.sh/", "https://canary.example.com/c", "https://snare.sh"},
			{"", "https://api.example.com", DefaultCallbackBase, "https://api.example.com"},
		} {
			setupHome(t)
			fakeManagedEnrollment(t)
			t.Setenv("SNARE_CALLBACK_BASE", tt.callback)
			t.Setenv("SNARE_API_BASE", tt.api)
			cfg, err := Init("", "", false)
			if err != nil {
				t.Fatalf("Init(%q, %q): %v", tt.callback, tt.api, err)
			}
			if cfg.CallbackBase != tt.wantCallback || cfg.APIBase() != tt.wantAPI {
				t.Fatalf("Init(%q, %q) = %q, %q", tt.callback, tt.api, cfg.CallbackBase, cfg.APIBase())
			}
		}
		for _, bad := range []string{"ftp://x/c", "https:///c", "https://u:p@x/c", "https://x/c?q=1"} {
			setupHome(t)
			t.Setenv("SNARE_CALLBACK_BASE", bad)
			if _, err := Init("", "", false); err == nil {
				t.Fatalf("Init(%q) error = nil", bad)
			}
		}
	})

	t.Run("refuses overwrite without force", func(t *testing.T) {
		setupHome(t)
		fakeManagedEnrollment(t)

		if _, err := Init("", "", false); err != nil {
			t.Fatalf("first Init: %v", err)
		}
		if _, err := Init("", "", false); err == nil {
			t.Fatal("second Init() error = nil, want already initialized error")
		}
	})

	t.Run("force overwrites existing config", func(t *testing.T) {
		setupHome(t)
		fakeManagedEnrollment(t)

		first, err := Init("", "https://hooks.example.test/one", false)
		if err != nil {
			t.Fatalf("first Init: %v", err)
		}
		second, err := Init("", "https://hooks.example.test/two", true)
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

func TestRegisterDeviceWithServerTimeout(t *testing.T) {
	noEnrollDelay(t)
	oldClient := httpClient
	httpClient = &http.Client{Timeout: 25 * time.Millisecond}
	t.Cleanup(func() { httpClient = oldClient })

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(`{"device_id":"dev-late"}`))
	}))
	defer srv.Close()

	start := time.Now()
	got, err := registerDeviceWithServer(srv.URL, strings.Repeat("a", 64))
	if got != "" || err == nil {
		t.Fatalf("device ID = %q, want fallback", got)
	}
	if time.Since(start) > time.Second {
		t.Fatal("registerDeviceWithServer did not use timeout client")
	}
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

func TestRegisterDeviceWithServerRetries(t *testing.T) {
	noEnrollDelay(t)
	for _, tt := range []struct {
		name      string
		statuses  []int
		wantCalls int
		wantOK    bool
	}{
		{"retries 503 then succeeds", []int{503, 200}, 2, true},
		{"does not retry 403", []int{403, 200}, 1, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				status := tt.statuses[calls]
				calls++
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"device_id":"dev-retry"}`))
			}))
			defer srv.Close()
			id, err := registerDeviceWithServer(srv.URL, strings.Repeat("a", 64))
			if calls != tt.wantCalls || (err == nil) != tt.wantOK {
				t.Fatalf("calls=%d id=%q err=%v", calls, id, err)
			}
		})
	}
}

func TestReenroll(t *testing.T) {
	setupHome(t)
	fakeManagedEnrollment(t)
	c := &Config{DeviceID: "dev-local-orphan", DeviceSecret: strings.Repeat("a", 64), CallbackBase: "https://snare.sh/c"}
	if err := c.Reenroll(); err != nil {
		t.Fatalf("Reenroll: %v", err)
	}
	if c.DeviceID == "dev-local-orphan" || c.DeviceSecret == strings.Repeat("a", 64) {
		t.Fatalf("identity not replaced: %+v", c)
	}
	loaded, err := Load()
	if err != nil || loaded.DeviceID != c.DeviceID {
		t.Fatalf("reenrolled identity not saved: %v %+v", err, loaded)
	}
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

			got, err := registerDeviceWithServer(srv.URL, strings.Repeat("a", 64))
			if got != tt.wantID {
				t.Fatalf("registerDeviceWithServer() = %q, want %q", got, tt.wantID)
			}
			if tt.wantID == "" && err == nil {
				t.Fatal("registerDeviceWithServer() error = nil, want failure")
			}
			if tt.wantID != "" && err != nil {
				t.Fatalf("registerDeviceWithServer() error = %v", err)
			}
		})
	}
}
