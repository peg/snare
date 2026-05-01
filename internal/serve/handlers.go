package serve

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

// ─── GET /health ─────────────────────────────────────────────────────────────

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	jsonResp(w, http.StatusOK, map[string]string{
		"status": "ok",
		"ts":     time.Now().UTC().Format(time.RFC3339),
	})
}

// ─── GET/POST /c/{token}[/*] ─────────────────────────────────────────────────
//
// PRIVACY CRITICAL PATH — same guarantee as the Cloudflare Worker:
//   - Only header-derived metadata is captured.
//   - The request body is NEVER read, stored, or forwarded.
//   - Response is returned immediately; alert processing is fire-and-forget.

func (s *Server) handleCanary(w http.ResponseWriter, r *http.Request) {
	// Extract token from /c/{token}[/anything]
	rest := strings.TrimPrefix(r.URL.Path, "/c/")
	parts := strings.SplitN(rest, "/", 2)
	token := parts[0]

	if !tokenPattern.MatchString(token) {
		http.NotFound(w, r)
		return
	}

	// Capture metadata from headers ONLY — body is never touched.
	ip := clientIP(r, s.trustedProxyNets)
	ua := r.Header.Get("User-Agent")
	now := time.Now().UTC().Format(time.RFC3339)
	method := r.Method
	path := r.URL.Path
	isTest := strings.HasPrefix(token, "snare-test-")

	// Return the pixel response immediately.
	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "no-store, max-age=0")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(pixel)

	// Process asynchronously — response is already sent.
	go func() {
		s.processAlert(token, ip, ua, method, path, now, isTest)
	}()
}

func (s *Server) processAlert(token, ip, ua, method, path, timestamp string, isTest bool) {
	// Look up token registration first so stored events retain ownership
	// even after a token is later revoked.
	reg, err := s.db.getToken(token)
	if err != nil {
		log.Printf("get token error: %v", err)
	}

	e := event{
		TokenID:   token,
		DeviceID:  "",
		IsTest:    isTest,
		Timestamp: timestamp,
		IP:        ip,
		UserAgent: ua,
		Method:    method,
		Path:      path,
		CreatedAt: timestamp,
	}
	if reg != nil {
		e.DeviceID = reg.DeviceID
	}

	log.Printf("CANARY_FIRED token=%s ip=%s is_test=%v ua=%s", token, ip, isTest, truncate(ua, 80))

	if err := s.db.insertEvent(e); err != nil {
		log.Printf("insert event error: %v", err)
	}

	// Unregistered tokens never fire webhooks — avoids false alerts from
	// probe traffic hitting random/partial token URLs.
	if reg == nil {
		log.Printf("UNREGISTERED token=%s — skipping webhook", token)
		return
	}

	// Determine webhook target
	webhookURL := s.cfg.WebhookURL // global fallback
	if reg.WebhookURL != "" && reg.WebhookURL != "use-global" {
		webhookURL = reg.WebhookURL
	}

	if webhookURL != "" {
		deliverWebhook(webhookURL, e, reg)
	}
}

// ─── POST /api/devices ───────────────────────────────────────────────────────

func (s *Server) handleCreateDevice(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResp(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var body struct {
		DeviceSecret string `json:"device_secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if len(body.DeviceSecret) < 32 {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "device_secret required (min 32 chars)"})
		return
	}

	deviceID, err := newID("dev-", 16) // 128-bit random
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "id generation failed"})
		return
	}

	if err := s.db.createDevice(deviceID, body.DeviceSecret); err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
		log.Printf("createDevice: %v", err)
		return
	}

	jsonResp(w, http.StatusOK, map[string]string{
		"status":    "created",
		"device_id": deviceID,
	})
}

// ─── POST /api/register ──────────────────────────────────────────────────────

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResp(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var body struct {
		TokenID    string `json:"token_id"`
		WebhookURL string `json:"webhook_url"`
		DeviceID   string `json:"device_id"`
		CanaryType string `json:"canary_type"`
		Label      string `json:"label"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}

	if !tokenPattern.MatchString(body.TokenID) {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid token_id"})
		return
	}
	if body.DeviceID == "" {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "missing device_id"})
		return
	}
	if body.WebhookURL == "" {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "missing webhook_url"})
		return
	}
	if body.WebhookURL != "use-global" && !strings.HasPrefix(body.WebhookURL, "https://") {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "webhook_url must be https:// or 'use-global'"})
		return
	}

	// Auth: validate Bearer device_secret
	ok, err := s.validateDevice(r, body.DeviceID)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "auth error"})
		return
	}
	if !ok {
		jsonResp(w, http.StatusUnauthorized, map[string]string{"error": "invalid device secret"})
		return
	}

	// Check if token is already owned by a different device
	existing, err := s.db.getToken(body.TokenID)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
		return
	}
	if existing != nil && existing.DeviceID != body.DeviceID {
		jsonResp(w, http.StatusForbidden, map[string]string{"error": "token already registered to another device"})
		return
	}

	if err := s.db.upsertToken(tokenReg{
		TokenID:      body.TokenID,
		DeviceID:     body.DeviceID,
		WebhookURL:   body.WebhookURL,
		CanaryType:   body.CanaryType,
		Label:        body.Label,
		RegisteredAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
		log.Printf("upsertToken: %v", err)
		return
	}

	jsonResp(w, http.StatusOK, map[string]string{
		"status":   "registered",
		"token_id": body.TokenID,
	})
}

// ─── POST /api/revoke ────────────────────────────────────────────────────────

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResp(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var body struct {
		TokenID  string `json:"token_id"`
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if body.TokenID == "" {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "missing token_id"})
		return
	}
	if body.DeviceID == "" {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "missing device_id"})
		return
	}

	// Auth
	ok, err := s.validateDevice(r, body.DeviceID)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "auth error"})
		return
	}
	if !ok {
		jsonResp(w, http.StatusUnauthorized, map[string]string{"error": "invalid device secret"})
		return
	}

	// Ownership check
	existing, err := s.db.getToken(body.TokenID)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
		return
	}
	if existing != nil && existing.DeviceID != body.DeviceID {
		jsonResp(w, http.StatusForbidden, map[string]string{"error": "device_id mismatch — only the registering device can revoke"})
		return
	}

	if err := s.db.deleteToken(body.TokenID); err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
		return
	}

	jsonResp(w, http.StatusOK, map[string]string{
		"status":   "revoked",
		"token_id": body.TokenID,
	})
}

// ─── POST /api/rotate ────────────────────────────────────────────────────────

func (s *Server) handleRotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonResp(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var body struct {
		DeviceID  string `json:"device_id"`
		NewSecret string `json:"new_secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if body.DeviceID == "" {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "missing device_id"})
		return
	}
	if len(body.NewSecret) < 32 {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "new_secret too short (min 32 chars)"})
		return
	}

	ok, err := s.validateDevice(r, body.DeviceID)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "auth error"})
		return
	}
	if !ok {
		jsonResp(w, http.StatusUnauthorized, map[string]string{"error": "invalid device secret"})
		return
	}

	updated, err := s.db.updateDeviceSecret(body.DeviceID, body.NewSecret)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
		return
	}
	if !updated {
		jsonResp(w, http.StatusUnauthorized, map[string]string{"error": "unknown device_id"})
		return
	}

	jsonResp(w, http.StatusOK, map[string]string{
		"status":    "rotated",
		"device_id": body.DeviceID,
	})
}

// ─── GET /api/events/{token} ─────────────────────────────────────────────────

func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResp(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	tokenID := strings.TrimPrefix(r.URL.Path, "/api/events/")
	tokenID = strings.TrimSuffix(tokenID, "/")
	if !tokenPattern.MatchString(tokenID) {
		jsonResp(w, http.StatusBadRequest, map[string]string{"error": "invalid token"})
		return
	}

	// Determine device that owns this token
	reg, err := s.db.getToken(tokenID)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
		return
	}

	// Auth is required. Device ID comes from the token registration, or from X-Snare-Device-Id header.
	deviceID := ""
	if reg != nil {
		deviceID = reg.DeviceID
	}
	if deviceID == "" {
		deviceID, err = s.db.latestEventDeviceID(tokenID)
		if err != nil {
			jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
			return
		}
	}
	if deviceID == "" {
		deviceID = r.Header.Get("X-Snare-Device-Id")
	}
	if deviceID == "" {
		jsonResp(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
		return
	}

	ok, err := s.validateDevice(r, deviceID)
	if err != nil || !ok {
		jsonResp(w, http.StatusUnauthorized, map[string]string{"error": "invalid device secret"})
		return
	}

	events, err := s.db.getEvents(tokenID)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
		return
	}

	if len(events) == 0 {
		jsonResp(w, http.StatusNotFound, map[string]interface{}{"token": tokenID, "events": []struct{}{}})
		return
	}

	// Serialise in the same shape as the Cloudflare Worker response.
	type eventOut struct {
		Token     string `json:"token"`
		IsTest    bool   `json:"is_test"`
		Timestamp string `json:"timestamp"`
		IP        string `json:"ip"`
		UserAgent string `json:"userAgent"`
		Method    string `json:"method"`
		Path      string `json:"path"`
		Country   string `json:"country,omitempty"`
		City      string `json:"city,omitempty"`
		ASN       string `json:"asn,omitempty"`
		ASNOrg    string `json:"asnOrg,omitempty"`
	}
	out := make([]eventOut, len(events))
	for i, e := range events {
		out[i] = eventOut{
			Token:     e.TokenID,
			IsTest:    e.IsTest,
			Timestamp: e.Timestamp,
			IP:        e.IP,
			UserAgent: e.UserAgent,
			Method:    e.Method,
			Path:      e.Path,
			Country:   e.Country,
			City:      e.City,
			ASN:       e.ASN,
			ASNOrg:    e.ASNOrg,
		}
	}
	jsonResp(w, http.StatusOK, map[string]interface{}{
		"token":  tokenID,
		"events": out,
	})
}

// ─── GET /api/dashboard/alerts ───────────────────────────────────────────────

func (s *Server) handleDashboardAlerts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResp(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	events, err := s.db.recentEvents(50)
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
		return
	}

	// Enrich events with canary type / label from token registration.
	type alertOut struct {
		ID         int64  `json:"id"`
		TokenID    string `json:"token_id"`
		CanaryType string `json:"canary_type"`
		Label      string `json:"label"`
		IsTest     bool   `json:"is_test"`
		Timestamp  string `json:"timestamp"`
		IP         string `json:"ip"`
		UserAgent  string `json:"user_agent"`
		Method     string `json:"method"`
	}

	// Batch-look up token registrations (simple n+1, acceptable for dashboard)
	cache := map[string]*tokenReg{}
	out := make([]alertOut, len(events))
	for i, e := range events {
		reg := cache[e.TokenID]
		if reg == nil {
			reg, _ = s.db.getToken(e.TokenID)
			cache[e.TokenID] = reg
		}
		a := alertOut{
			ID:        e.ID,
			TokenID:   e.TokenID,
			IsTest:    e.IsTest,
			Timestamp: e.Timestamp,
			IP:        e.IP,
			UserAgent: e.UserAgent,
			Method:    e.Method,
		}
		if reg != nil {
			a.CanaryType = reg.CanaryType
			a.Label = reg.Label
		}
		out[i] = a
	}
	jsonResp(w, http.StatusOK, out)
}

// ─── GET /api/dashboard/devices ──────────────────────────────────────────────

func (s *Server) handleDashboardDevices(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonResp(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	devices, err := s.db.listDevices()
	if err != nil {
		jsonResp(w, http.StatusInternalServerError, map[string]string{"error": "db error"})
		return
	}
	jsonResp(w, http.StatusOK, devices)
}
