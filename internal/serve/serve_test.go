package serve

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net"
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
		Port:            0,
		DBPath:          filepath.Join(dir, "test.db"),
		EnrollmentToken: testEnrollmentToken,
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.db.close() })
	s.runAsync = func(fn func()) { fn() }
	return s
}

const testEnrollmentToken = "test-enrollment-token-0123456789abcdef"

func captureLogs(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	oldWriter := log.Writer()
	oldFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() {
		log.SetOutput(oldWriter)
		log.SetFlags(oldFlags)
	}()
	fn()
	return buf.String()
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

func TestClientIPOnlyTrustsConfiguredProxies(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/c/test-token-abc123", nil)
	req.RemoteAddr = "198.51.100.10:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.8")

	if got := clientIP(req, nil); got != "198.51.100.10" {
		t.Fatalf("clientIP without trusted proxies = %q, want remote addr", got)
	}

	trusted, err := parseTrustedProxyCIDRs([]string{"198.51.100.0/24"})
	if err != nil {
		t.Fatalf("parseTrustedProxyCIDRs: %v", err)
	}
	if got := clientIP(req, trusted); got != "203.0.113.8" {
		t.Fatalf("clientIP with trusted proxy = %q, want forwarded IP", got)
	}
}

func TestClientIPRejectsMalformedTrustedProxyHeaders(t *testing.T) {
	trusted, err := parseTrustedProxyCIDRs([]string{"198.51.100.0/24"})
	if err != nil {
		t.Fatalf("parseTrustedProxyCIDRs: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/c/test-token-abc123", nil)
	req.RemoteAddr = "198.51.100.10:1234"
	req.Header.Set("X-Forwarded-For", "not-an-ip")
	req.Header.Set("X-Real-Ip", "203.0.113.9")
	if got := clientIP(req, trusted); got != "203.0.113.9" {
		t.Fatalf("clientIP with malformed XFF and valid X-Real-IP = %q, want X-Real-IP", got)
	}

	req.Header.Set("X-Real-Ip", "also-not-an-ip")
	if got := clientIP(req, trusted); got != "198.51.100.10" {
		t.Fatalf("clientIP with malformed forwarded headers = %q, want remote addr", got)
	}
}

func TestHandleCanary_storesEvent(t *testing.T) {
	s := testServer(t)
	const tokenID = "stored-token123"

	if err := s.db.createDevice("dev-store-test", "secret0000000000000000000000001"); err != nil {
		t.Fatalf("createDevice: %v", err)
	}
	if err := s.db.upsertToken(tokenReg{
		TokenID:      tokenID,
		DeviceID:     "dev-store-test",
		WebhookURL:   "",
		CanaryType:   "aws",
		Label:        "store-test",
		RegisteredAt: "2024-01-01T00:00:00Z",
	}); err != nil {
		t.Fatalf("upsertToken: %v", err)
	}

	// Call processAlert directly (it's synchronous in tests, no goroutine race).
	logs := captureLogs(t, func() {
		s.processAlert(tokenID, "1.2.3.4", "TestAgent/1.0", "GET", "/c/"+tokenID, "2024-01-01T00:00:00Z", false)
	})
	if strings.Contains(logs, tokenID) || strings.Contains(logs, "1.2.3.4") {
		t.Fatalf("processAlert log exposed token/IP: %q", logs)
	}
	if !strings.Contains(logs, "CANARY_FIRED token=*** ip=***") {
		t.Fatalf("processAlert log did not include redacted canary marker: %q", logs)
	}

	events, err := s.db.getEvents(tokenID)
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

func TestHandleCanary_unregisteredTokenDoesNotStoreEvent(t *testing.T) {
	s := testServer(t)
	const tokenID = "some-unregistered-token-abc123"

	logs := captureLogs(t, func() {
		s.processAlert(tokenID, "1.2.3.4", "TestAgent/1.0", "GET", "/c/"+tokenID, "2024-01-01T00:00:00Z", false)
	})
	if strings.Contains(logs, tokenID) || strings.Contains(logs, "1.2.3.4") {
		t.Fatalf("unregistered token log exposed token/IP: %q", logs)
	}
	if !strings.Contains(logs, "UNREGISTERED token=*** ip=***") {
		t.Fatalf("unregistered token log did not include redacted marker: %q", logs)
	}

	events, err := s.db.getEvents(tokenID)
	if err != nil {
		t.Fatalf("getEvents: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("unregistered token stored %d event(s), want 0", len(events))
	}
}

func TestHandleCanary_unregisteredTestTokenDoesNotStoreOrWebhook(t *testing.T) {
	called := false
	whServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer whServer.Close()

	dir := t.TempDir()
	s, err := New(Config{Port: 0, DBPath: filepath.Join(dir, "test.db")})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.db.close() })
	s.cfg.WebhookURL = whServer.URL
	s.webhookClient = whServer.Client()

	const tokenID = "snare-test-unregistered123"
	s.processAlert(tokenID, "1.2.3.4", "TestAgent/1.0", "GET", "/c/"+tokenID, "2024-01-01T00:00:00Z", true)

	events, err := s.db.getEvents(tokenID)
	if err != nil {
		t.Fatalf("getEvents: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("unregistered test token stored %d event(s), want 0", len(events))
	}
	if called {
		t.Fatal("webhook was called for an unregistered test token")
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

func TestValidateDevice_malformedStoredHash(t *testing.T) {
	s := testServer(t)
	_, err := s.db.db.Exec(
		`INSERT INTO devices (device_id, secret_hash, created_at) VALUES (?, ?, ?)`,
		"dev-badhash", "not-a-sha256", "2024-01-01T00:00:00Z",
	)
	if err != nil {
		t.Fatalf("insert device: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/register", nil)
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 64))

	ok, err := s.validateDevice(req, "dev-badhash")
	if err != nil {
		t.Fatalf("validateDevice: %v", err)
	}
	if ok {
		t.Fatal("malformed stored hash validated")
	}
}

func TestSecurityHeaders(t *testing.T) {
	h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))

	if rr.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal("missing X-Frame-Options")
	}
	if !strings.Contains(rr.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("missing CSP frame-ancestors")
	}
}

func TestJSONBodyLimit(t *testing.T) {
	s := testServer(t)
	body := `{"device_secret":"` + strings.Repeat("a", int(maxRequestBodyBytes)) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/devices", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testEnrollmentToken)
	rr := httptest.NewRecorder()

	s.handleCreateDevice(rr, req)
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rr.Code)
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
	req.Header.Set("Authorization", "Bearer "+testEnrollmentToken)
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
	req.Header.Set("Authorization", "Bearer "+testEnrollmentToken)
	rr := httptest.NewRecorder()
	s.handleCreateDevice(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestHandleCreateDevice_requiresEnrollmentToken(t *testing.T) {
	s := testServer(t)
	body, _ := json.Marshal(map[string]string{
		"device_secret": "averylongsecretpassword000000001",
	})

	for _, authorization := range []string{"", "Bearer wrong-enrollment-token"} {
		req := httptest.NewRequest(http.MethodPost, "/api/devices", bytes.NewReader(body))
		req.Header.Set("Authorization", authorization)
		rr := httptest.NewRecorder()
		s.handleCreateDevice(rr, req)

		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("Authorization %q status = %d, want 401", authorization, rr.Code)
		}
	}
}

func TestHandleRotate_updatesDeviceSecret(t *testing.T) {
	s := testServer(t)

	const (
		deviceID  = "dev-rotate-test"
		oldSecret = "oldsecret000000000000000000000001"
		newSecret = "newsecret000000000000000000000001"
	)
	if err := s.db.createDevice(deviceID, oldSecret); err != nil {
		t.Fatalf("createDevice: %v", err)
	}

	body, _ := json.Marshal(map[string]string{
		"device_id":  deviceID,
		"new_secret": newSecret,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/rotate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+oldSecret)
	rr := httptest.NewRecorder()

	s.handleRotate(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	oldReq := httptest.NewRequest(http.MethodPost, "/api/register", nil)
	oldReq.Header.Set("Authorization", "Bearer "+oldSecret)
	ok, err := s.validateDevice(oldReq, deviceID)
	if err != nil {
		t.Fatalf("validateDevice old secret: %v", err)
	}
	if ok {
		t.Fatal("old secret still valid after rotation")
	}

	newReq := httptest.NewRequest(http.MethodPost, "/api/register", nil)
	newReq.Header.Set("Authorization", "Bearer "+newSecret)
	ok, err = s.validateDevice(newReq, deviceID)
	if err != nil {
		t.Fatalf("validateDevice new secret: %v", err)
	}
	if !ok {
		t.Fatal("new secret not valid after rotation")
	}
}

// ─── Health ──────────────────────────────────────────────────────────────────

func TestDiscordPayloadFooterMatchesWorkerPrivacyCopy(t *testing.T) {
	payload := buildDiscordPayload(event{TokenID: "tok-12345678", Timestamp: "2026-04-15T16:00:00Z", Method: "GET", IP: "1.2.3.4", UserAgent: "ua"}, nil, canaryTypeMeta{Name: "Canary", Emoji: "🎣"}, false)
	embeds := payload["embeds"].([]map[string]interface{})
	footer := embeds[0]["footer"].(map[string]string)["text"]
	if footer != "snare-server · IP, UA, timestamp only — no request body" {
		t.Fatalf("footer = %q", footer)
	}
}

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

func TestValidateWebhookURLRejectsNonPublicDestinations(t *testing.T) {
	for _, raw := range []string{
		"http://hooks.example.com/alert",
		"https://127.0.0.1/alert",
		"https://169.254.169.254/latest/meta-data",
		"https://10.0.0.1/alert",
		"https://[::1]/alert",
		"https://user:pass@hooks.example.com/alert",
		"https://hooks.example.com/alert#fragment",
	} {
		if err := validateWebhookURL(raw); err == nil {
			t.Errorf("validateWebhookURL(%q) error = nil, want rejection", raw)
		}
	}

	if err := validateWebhookURL("https://hooks.slack.com/services/a/b/c"); err != nil {
		t.Fatalf("public HTTPS webhook rejected: %v", err)
	}
}

func TestWebhookDialRejectsPrivateDNSResolution(t *testing.T) {
	client := newWebhookClient(func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host != "hooks.example.com" {
			t.Fatalf("lookup host = %q", host)
		}
		return []net.IPAddr{
			{IP: net.ParseIP("93.184.216.34")},
			{IP: net.ParseIP("127.0.0.1")},
		}, nil
	})
	transport := client.Transport.(*http.Transport)

	conn, err := transport.DialContext(context.Background(), "tcp", "hooks.example.com:443")
	if conn != nil {
		_ = conn.Close()
		t.Fatal("private DNS result unexpectedly produced a connection")
	}
	if err == nil || !strings.Contains(err.Error(), "non-public") {
		t.Fatalf("DialContext error = %v, want non-public rejection", err)
	}
}

func TestWebhookClientRefusesRedirects(t *testing.T) {
	client := newWebhookClient(net.DefaultResolver.LookupIPAddr)
	req := httptest.NewRequest(http.MethodGet, "https://hooks.example.com/redirected", nil)
	if err := client.CheckRedirect(req, nil); err != http.ErrUseLastResponse {
		t.Fatalf("CheckRedirect error = %v, want ErrUseLastResponse", err)
	}
}

func TestHandleRegisterRejectsPrivateWebhook(t *testing.T) {
	s := testServer(t)
	const (
		deviceID     = "dev-private-webhook"
		deviceSecret = "secret0000000000000000000000001"
	)
	if err := s.db.createDevice(deviceID, deviceSecret); err != nil {
		t.Fatalf("createDevice: %v", err)
	}

	body, _ := json.Marshal(map[string]string{
		"token_id":    "private-webhook-token",
		"webhook_url": "https://127.0.0.1/internal",
		"device_id":   deviceID,
		"canary_type": "generic",
		"label":       "private",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/register", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+deviceSecret)
	rr := httptest.NewRecorder()
	s.handleRegister(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
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
		Port:   0,
		DBPath: filepath.Join(dir, "test.db"),
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.db.close() })
	s.runAsync = func(fn func()) { fn() }
	s.cfg.WebhookURL = whServer.URL
	s.webhookClient = whServer.Client()

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
		Port:   0,
		DBPath: filepath.Join(dir, "test.db"),
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { s.db.close() })
	s.cfg.WebhookURL = whServer.URL
	s.webhookClient = whServer.Client()

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

func TestHandleEventsAfterRevokeStillRequiresOriginalOwner(t *testing.T) {
	s := testServer(t)

	const (
		ownerDeviceID  = "dev-owner-001"
		ownerSecret    = "ownersecret0000000000000000000001"
		otherDeviceID  = "dev-other-001"
		otherSecret    = "othersecret0000000000000000000001"
		tokenID        = "token-events-abc123"
		registeredAt   = "2026-04-27T22:00:00Z"
		eventTimestamp = "2026-04-27T22:05:00Z"
	)

	if err := s.db.createDevice(ownerDeviceID, ownerSecret); err != nil {
		t.Fatalf("create owner device: %v", err)
	}
	if err := s.db.createDevice(otherDeviceID, otherSecret); err != nil {
		t.Fatalf("create other device: %v", err)
	}
	if err := s.db.upsertToken(tokenReg{
		TokenID:      tokenID,
		DeviceID:     ownerDeviceID,
		WebhookURL:   "use-global",
		CanaryType:   "awsproc",
		Label:        "prod",
		RegisteredAt: registeredAt,
	}); err != nil {
		t.Fatalf("upsertToken: %v", err)
	}

	s.processAlert(tokenID, "1.2.3.4", "curl/8.0", "GET", "/c/"+tokenID, eventTimestamp, false)

	if err := s.db.deleteToken(tokenID); err != nil {
		t.Fatalf("deleteToken: %v", err)
	}

	unauthReq := httptest.NewRequest(http.MethodGet, "/api/events/"+tokenID, nil)
	unauthReq.Header.Set("Authorization", "Bearer "+otherSecret)
	unauthReq.Header.Set("X-Snare-Device-Id", otherDeviceID)
	unauthRR := httptest.NewRecorder()
	s.handleEvents(unauthRR, unauthReq)
	if unauthRR.Code != http.StatusUnauthorized {
		t.Fatalf("wrong owner status = %d, want 401", unauthRR.Code)
	}

	ownerReq := httptest.NewRequest(http.MethodGet, "/api/events/"+tokenID, nil)
	ownerReq.Header.Set("Authorization", "Bearer "+ownerSecret)
	ownerReq.Header.Set("X-Snare-Device-Id", ownerDeviceID)
	ownerRR := httptest.NewRecorder()
	s.handleEvents(ownerRR, ownerReq)
	if ownerRR.Code != http.StatusOK {
		t.Fatalf("owner status = %d, want 200: %s", ownerRR.Code, ownerRR.Body.String())
	}
}

func TestHandleEventsRejectsUnregisteredTokenEvenWithValidDeviceHeader(t *testing.T) {
	s := testServer(t)
	deviceID := "dev-owner"
	secret := "ownersecret000000000000000000000001"

	if err := s.db.createDevice(deviceID, secret); err != nil {
		t.Fatalf("create device: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/events/unregistered-token-001", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("X-Snare-Device-Id", deviceID)
	rr := httptest.NewRecorder()
	s.handleEvents(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("unregistered token status = %d, want 401: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "token not registered") {
		t.Fatalf("unregistered token response should explain registration state: %s", rr.Body.String())
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
