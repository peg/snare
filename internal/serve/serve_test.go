package serve

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
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

// ─── Webhook gating on token registration ────────────────────────────────────

func TestHandleCanary_unregisteredTokenNoWebhook(t *testing.T) {
	// Stand up a webhook endpoint that records whether it was called.
	called := false
	whServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer whServer.Close()

	dir := t.TempDir()
	cfg := Config{
		Port:       0,
		DBPath:     filepath.Join(dir, "test.db"),
		WebhookURL: whServer.URL, // global webhook configured
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.db.close() })

	// Fire a canary hit via the HTTP handler — token is valid format but NOT registered.
	req := httptest.NewRequest(http.MethodGet, "/c/some-unregistered-token-abc123", nil)
	rr := httptest.NewRecorder()
	s.handleCanary(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); ct != "image/gif" {
		t.Errorf("Content-Type = %q, want image/gif", ct)
	}

	// handleCanary fires processAlert in a goroutine; call it synchronously
	// to deterministically verify webhook behaviour.
	s.processAlert("some-unregistered-token-abc123", "1.2.3.4", "TestAgent/1.0", "GET", "/c/some-unregistered-token-abc123", "2024-01-01T00:00:00Z", false)

	if called {
		t.Error("webhook was called for an unregistered token — expected no webhook")
	}
}

func TestHandleCanary_registeredTokenFiresWebhook(t *testing.T) {
	called := false
	whServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer whServer.Close()

	dir := t.TempDir()
	cfg := Config{
		Port:       0,
		DBPath:     filepath.Join(dir, "test.db"),
		WebhookURL: whServer.URL,
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.db.close() })

	// Register the token so processAlert finds it in the DB.
	if err := s.db.createDevice("dev-wh-test", "secret0000000000000000000000001"); err != nil {
		t.Fatalf("createDevice: %v", err)
	}
	if err := s.db.upsertToken(tokenReg{
		TokenID:      "registered-token-abc123",
		DeviceID:     "dev-wh-test",
		WebhookURL:   "use-global",
		CanaryType:   "aws",
		Label:        "test-label",
		RegisteredAt: "2024-01-01T00:00:00Z",
	}); err != nil {
		t.Fatalf("upsertToken: %v", err)
	}

	s.processAlert("registered-token-abc123", "1.2.3.4", "TestAgent/1.0", "GET", "/c/registered-token-abc123", "2024-01-01T00:00:00Z", false)

	if !called {
		t.Error("webhook was NOT called for a registered token — expected webhook delivery")
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

// ─── Dashboard session auth ──────────────────────────────────────────────────

const testDashToken = "test-dashboard-token-0123456789abcdef"

// testDashServer creates a Server with DashboardToken set.
func testDashServer(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := Config{
		Port:           0,
		DBPath:         filepath.Join(dir, "test.db"),
		DashboardToken: testDashToken,
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.db.close() })
	return s
}

func TestLoginPost_validToken(t *testing.T) {
	s := testDashServer(t)

	form := url.Values{"token": {testDashToken}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	s.handleLogin(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d: %s", rr.Code, rr.Body.String())
	}
	cookies := rr.Result().Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == sessionCookieName {
			found = true
			if !c.HttpOnly {
				t.Error("cookie should be HttpOnly")
			}
			// Secure flag is only set when TLSDomain is configured;
			// test server has no TLSDomain so Secure should be false here.
			if c.Secure {
				t.Error("cookie should not be Secure when TLSDomain is empty")
			}
			if c.SameSite != http.SameSiteStrictMode {
				t.Error("cookie should be SameSite=Strict")
			}
		}
	}
	if !found {
		t.Error("session cookie not set")
	}
}

func TestLoginPost_invalidToken(t *testing.T) {
	s := testDashServer(t)

	form := url.Values{"token": {"wrong-token"}}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	s.handleLogin(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); !strings.Contains(loc, "error=invalid") {
		t.Errorf("expected redirect to /?error=invalid, got %q", loc)
	}
}

func TestLoginPost_JSON(t *testing.T) {
	s := testDashServer(t)

	body, _ := json.Marshal(map[string]string{"token": testDashToken})
	req := httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	s.handleLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestLogin_methodNotAllowed(t *testing.T) {
	s := testDashServer(t)

	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()
	s.handleLogin(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestDashboard_sessionCookie(t *testing.T) {
	s := testDashServer(t)

	// First, login to get the cookie
	form := url.Values{"token": {testDashToken}}
	loginReq := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(form.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRR := httptest.NewRecorder()
	s.handleLogin(loginRR, loginReq)

	// Extract session cookie
	var sessionCookie *http.Cookie
	for _, c := range loginRR.Result().Cookies() {
		if c.Name == sessionCookieName {
			sessionCookie = c
		}
	}
	if sessionCookie == nil {
		t.Fatal("no session cookie after login")
	}

	// Access dashboard with cookie
	dashReq := httptest.NewRequest(http.MethodGet, "/", nil)
	dashReq.AddCookie(sessionCookie)
	dashRR := httptest.NewRecorder()
	s.mux.ServeHTTP(dashRR, dashReq)

	if dashRR.Code != http.StatusOK {
		t.Errorf("expected 200 with session cookie, got %d", dashRR.Code)
	}
}

func TestDashboard_bearerStillWorks(t *testing.T) {
	s := testDashServer(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+testDashToken)
	rr := httptest.NewRecorder()
	s.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200 with Bearer token, got %d", rr.Code)
	}
}

func TestDashboard_queryParamRejected(t *testing.T) {
	s := testDashServer(t)

	req := httptest.NewRequest(http.MethodGet, "/?token="+testDashToken, nil)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()
	s.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for query param auth (removed), got %d", rr.Code)
	}
}

func TestDashboard_noCreds(t *testing.T) {
	s := testDashServer(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()
	s.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", rr.Code)
	}
	// Login form should POST to /login, not GET with ?token=
	body := rr.Body.String()
	if !strings.Contains(body, `action="/login"`) {
		t.Error("login form should POST to /login")
	}
	if !strings.Contains(body, `method="POST"`) {
		t.Error("login form should use POST method")
	}
}

func TestLogout_clearsCookie(t *testing.T) {
	s := testDashServer(t)

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()
	s.handleLogout(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Errorf("expected 303, got %d", rr.Code)
	}
	for _, c := range rr.Result().Cookies() {
		if c.Name == sessionCookieName && c.MaxAge == -1 {
			return // cookie cleared
		}
	}
	t.Error("session cookie not cleared on logout")
}

// TestMain ensures any temp test databases are cleaned up.
func TestMain(m *testing.M) {
	os.Exit(m.Run())
}
