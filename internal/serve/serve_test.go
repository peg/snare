package serve

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// testServer creates a Server backed by a temp SQLite DB for use in tests.
func testServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{
		Port:   0,
		DBPath: filepath.Join(dir, "test.db"),
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.db.close() })
	return s
}

// ─── Canary callback handler ──────────────────────────────────────────────────

func TestHandleCanary_returnsGIF(t *testing.T) {
	s := testServer(t)

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		req := httptest.NewRequest(method, "/c/test-token-abc123", nil)
		rr := httptest.NewRecorder()

		s.handleCanary(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("%s: got status %d, want 200", method, rr.Code)
		}
		if ct := rr.Header().Get("Content-Type"); ct != "image/gif" {
			t.Errorf("%s: Content-Type = %q, want image/gif", method, ct)
		}
		if body := rr.Body.Bytes(); len(body) == 0 {
			t.Errorf("%s: empty body", method)
		}
		// Must be the 1×1 GIF (37 bytes)
		if len(rr.Body.Bytes()) != len(pixel) {
			t.Errorf("%s: gif size = %d, want %d", method, rr.Body.Len(), len(pixel))
		}
	}
}

func TestHandleCanary_invalidToken(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest(http.MethodGet, "/c/!!", nil)
	rr := httptest.NewRecorder()
	s.handleCanary(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("expected 404 for invalid token, got %d", rr.Code)
	}
}

func TestHandleCanary_storesEvent(t *testing.T) {
	s := testServer(t)

	// Call processAlert directly (it's synchronous in tests, no goroutine race).
	s.processAlert("stored-token123", "1.2.3.4", "TestAgent/1.0", "GET", "/c/stored-token123", "2024-01-01T00:00:00Z", false)

	events, err := s.db.getEvents("stored-token123")
	if err != nil {
		t.Fatalf("getEvents: %v", err)
	}
	if len(events) < 1 {
		t.Errorf("expected at least 1 event, got %d", len(events))
	}
	if events[0].IP != "1.2.3.4" {
		t.Errorf("IP = %q, want 1.2.3.4", events[0].IP)
	}
	if events[0].UserAgent != "TestAgent/1.0" {
		t.Errorf("UserAgent = %q, want TestAgent/1.0", events[0].UserAgent)
	}
}

// ─── Auth middleware ──────────────────────────────────────────────────────────

func TestValidateDevice_success(t *testing.T) {
	s := testServer(t)

	const (
		deviceID     = "dev-test0001"
		deviceSecret = "supersecretpassword0000000000001"
	)

	if err := s.db.createDevice(deviceID, deviceSecret); err != nil {
		t.Fatalf("createDevice: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/register", nil)
	req.Header.Set("Authorization", "Bearer "+deviceSecret)

	ok, err := s.validateDevice(req, deviceID)
	if err != nil {
		t.Fatalf("validateDevice: %v", err)
	}
	if !ok {
		t.Error("expected validation to succeed")
	}
}

func TestValidateDevice_wrongSecret(t *testing.T) {
	s := testServer(t)

	const deviceID = "dev-test0002"
	if err := s.db.createDevice(deviceID, "correctpassword0000000000000001"); err != nil {
		t.Fatalf("createDevice: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/register", nil)
	req.Header.Set("Authorization", "Bearer wrongpassword000000000000000001")

	ok, err := s.validateDevice(req, deviceID)
	if err != nil {
		t.Fatalf("validateDevice: %v", err)
	}
	if ok {
		t.Error("expected validation to fail with wrong secret")
	}
}

func TestValidateDevice_missingHeader(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/register", nil)
	ok, err := s.validateDevice(req, "dev-any")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected validation to fail with no Authorization header")
	}
}

func TestValidateDevice_unknownDevice(t *testing.T) {
	s := testServer(t)

	req := httptest.NewRequest(http.MethodPost, "/api/register", nil)
	req.Header.Set("Authorization", "Bearer somepassword00000000000000000001")

	ok, err := s.validateDevice(req, "dev-nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Error("expected validation to fail for unknown device")
	}
}

// ─── POST /api/devices ───────────────────────────────────────────────────────

func TestHandleCreateDevice(t *testing.T) {
	s := testServer(t)

	body, _ := json.Marshal(map[string]string{
		"device_secret": "averylongsecretpassword000000001", // 32 chars
	})
	req := httptest.NewRequest(http.MethodPost, "/api/devices", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	s.handleCreateDevice(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "created" {
		t.Errorf("status = %q, want 'created'", resp["status"])
	}
	if resp["device_id"] == "" {
		t.Error("device_id is empty")
	}
}

func TestHandleCreateDevice_shortSecret(t *testing.T) {
	s := testServer(t)

	body, _ := json.Marshal(map[string]string{"device_secret": "short"})
	req := httptest.NewRequest(http.MethodPost, "/api/devices", bytes.NewReader(body))
	rr := httptest.NewRecorder()
	s.handleCreateDevice(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

// ─── Health ──────────────────────────────────────────────────────────────────

func TestHandleHealth(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rr := httptest.NewRecorder()
	s.handleHealth(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["status"] != "ok" {
		t.Errorf("status = %q, want 'ok'", resp["status"])
	}
}

// ─── hashSecret ──────────────────────────────────────────────────────────────

func TestHashSecret_deterministic(t *testing.T) {
	h1 := hashSecret("mysecret")
	h2 := hashSecret("mysecret")
	if h1 != h2 {
		t.Error("hashSecret not deterministic")
	}
	if h1 == "" {
		t.Error("hashSecret returned empty string")
	}
	// SHA-256 → 64 hex chars
	if len(h1) != 64 {
		t.Errorf("expected 64 hex chars, got %d", len(h1))
	}
}

func TestHashSecret_distinct(t *testing.T) {
	if hashSecret("secret1") == hashSecret("secret2") {
		t.Error("different secrets should produce different hashes")
	}
}

// ─── DB helpers ──────────────────────────────────────────────────────────────

func TestDB_tokenRoundtrip(t *testing.T) {
	dir := t.TempDir()
	db, err := openDB(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	defer db.close()

	if err := db.createDevice("dev-001", "secret0000000000000000000000001"); err != nil {
		t.Fatalf("createDevice: %v", err)
	}

	tok := tokenReg{
		TokenID:      "mytoken-abc12345",
		DeviceID:     "dev-001",
		WebhookURL:   "https://hooks.slack.com/test",
		CanaryType:   "aws",
		Label:        "prod",
		RegisteredAt: "2024-01-01T00:00:00Z",
	}
	if err := db.upsertToken(tok); err != nil {
		t.Fatalf("upsertToken: %v", err)
	}

	got, err := db.getToken("mytoken-abc12345")
	if err != nil {
		t.Fatalf("getToken: %v", err)
	}
	if got == nil {
		t.Fatal("expected token, got nil")
	}
	if got.CanaryType != "aws" || got.Label != "prod" {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

// TestMain ensures any temp test databases are cleaned up.
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
