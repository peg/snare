package serve

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

const sessionCookieName = "snare_session"
const maxRequestBodyBytes int64 = 1 << 20

// Config holds the server configuration.
type Config struct {
	Port              int      // listen port (default 8080)
	DBPath            string   // path to SQLite database
	TLSDomain         string   // if set, enable Let's Encrypt TLS
	WebhookURL        string   // global fallback webhook URL
	DashboardToken    string   // bearer token for dashboard + dashboard API auth (required)
	EnrollmentToken   string   // bearer token for creating devices (required)
	TrustedProxyCIDRs []string // trusted reverse proxies allowed to supply X-Forwarded-For / X-Real-IP
}

// DefaultConfig returns sensible defaults.
func DefaultConfig() Config {
	home, _ := os.UserHomeDir()
	return Config{
		Port:   8080,
		DBPath: home + "/.snare/serve/snare.db",
	}
}

// Server is the snare self-hosted server.
type Server struct {
	cfg              Config
	db               *DB
	mux              *http.ServeMux
	sessionSecret    []byte // random secret generated at startup for HMAC session cookies
	trustedProxyNets []*net.IPNet
	webhookClient    *http.Client
	runAsync         func(func())
}

// tokenPattern validates token IDs in URL paths.
var tokenPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{8,80}$`)

// 1×1 transparent GIF
var pixel = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x21, 0xf9, 0x04,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x2c, 0x00, 0x00,
	0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02,
	0x02, 0x44, 0x01, 0x00, 0x3b,
}

// New creates a new Server. Call Serve to start listening.
func New(cfg Config) (*Server, error) {
	db, err := openDB(cfg.DBPath)
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}

	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, fmt.Errorf("generating session secret: %w", err)
	}

	trustedProxyNets, err := parseTrustedProxyCIDRs(cfg.TrustedProxyCIDRs)
	if err != nil {
		return nil, fmt.Errorf("parsing trusted proxy CIDRs: %w", err)
	}

	if cfg.WebhookURL != "" {
		if err := validateWebhookURL(cfg.WebhookURL); err != nil {
			_ = db.close()
			return nil, fmt.Errorf("invalid global webhook URL: %w", err)
		}
	}

	s := &Server{
		cfg:              cfg,
		db:               db,
		mux:              http.NewServeMux(),
		sessionSecret:    secret,
		trustedProxyNets: trustedProxyNets,
		webhookClient:    newWebhookClient(net.DefaultResolver.LookupIPAddr),
		runAsync: func(fn func()) {
			go fn()
		},
	}
	s.routes()
	return s, nil
}

// routes wires all HTTP handlers.
func (s *Server) routes() {
	// Unauthenticated: canary callbacks and health
	s.mux.HandleFunc("/c/", s.handleCanary)
	s.mux.HandleFunc("/health", s.handleHealth)

	// Device enrollment uses an operator token. Remaining device API calls use
	// the per-device bearer secret.
	s.mux.HandleFunc("/api/devices", s.handleCreateDevice)
	s.mux.HandleFunc("/api/register", s.handleRegister)
	s.mux.HandleFunc("/api/revoke", s.handleRevoke)
	s.mux.HandleFunc("/api/rotate", s.handleRotate)
	s.mux.HandleFunc("/api/events/", s.handleEvents)

	// Dashboard auth: login / logout
	s.mux.HandleFunc("/login", s.handleLogin)
	s.mux.HandleFunc("/logout", s.handleLogout)

	// Dashboard: authenticated by session cookie or Bearer token (operator-level access)
	s.mux.HandleFunc("/api/dashboard/alerts", s.requireDashboardAuth(s.handleDashboardAlerts))
	s.mux.HandleFunc("/api/dashboard/devices", s.requireDashboardAuth(s.handleDashboardDevices))
	s.mux.HandleFunc("/", s.requireDashboardAuth(s.handleDashboard))
}

// sessionMAC returns the expected session cookie value for the current server instance.
func (s *Server) sessionMAC() string {
	mac := hmac.New(sha256.New, s.sessionSecret)
	mac.Write([]byte("snare_session"))
	return hex.EncodeToString(mac.Sum(nil))
}

// validSession checks whether the request carries a valid session cookie.
func (s *Server) validSession(r *http.Request) bool {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return false
	}
	return secureCompare(c.Value, s.sessionMAC())
}

// setSessionCookie writes the session cookie to the response.
// Secure flag is only set when TLS is configured — plain HTTP self-hosted
// instances (localhost, internal servers) would break with Secure=true.
func (s *Server) setSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    s.sessionMAC(),
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.TLSDomain != "",
		SameSite: http.SameSiteStrictMode,
	})
}

// clearSessionCookie removes the session cookie.
func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   s.cfg.TLSDomain != "",
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// handleLogin accepts a POST with the dashboard token and sets a session cookie.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cfg.DashboardToken == "" {
		http.Error(w, "dashboard auth not configured", http.StatusServiceUnavailable)
		return
	}

	var token string
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var body struct {
			Token string `json:"token"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			status, msg := requestBodyError(err)
			http.Error(w, msg, status)
			return
		}
		token = body.Token
	} else {
		if err := r.ParseForm(); err != nil {
			status, msg := requestBodyError(err)
			http.Error(w, msg, status)
			return
		}
		token = r.Form.Get("token")
	}

	if !secureCompare(token, s.cfg.DashboardToken) {
		// For HTML form submissions, redirect back to / which shows the login form
		if strings.Contains(r.Header.Get("Accept"), "text/html") ||
			r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
			http.Redirect(w, r, "/?error=invalid", http.StatusSeeOther)
			return
		}
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	s.setSessionCookie(w)

	// For HTML form submissions, redirect to dashboard
	if r.Header.Get("Content-Type") == "application/x-www-form-urlencoded" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	jsonResp(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleLogout clears the session cookie.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	s.clearSessionCookie(w)
	if r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	jsonResp(w, http.StatusOK, map[string]string{"status": "logged out"})
}

// requireDashboardAuth wraps a handler to require a valid session cookie or Bearer token.
// The token must match cfg.DashboardToken. If DashboardToken is empty, the
// server refuses to start (enforced in cmdServe).
func (s *Server) requireDashboardAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.DashboardToken == "" {
			http.Error(w, "dashboard auth not configured", http.StatusServiceUnavailable)
			return
		}
		// Accept Bearer token in Authorization header (for API clients)
		if secureCompare(bearerToken(r), s.cfg.DashboardToken) {
			next(w, r)
			return
		}
		// Accept valid session cookie (for browser sessions)
		if s.validSession(r) {
			next(w, r)
			return
		}
		// For the dashboard HTML page, show a simple login form
		if r.Header.Get("Accept") != "" && strings.Contains(r.Header.Get("Accept"), "text/html") {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `<!doctype html><html><head><title>Snare — Login</title>
<style>body{background:#0a0a0b;color:#f0f0f2;font-family:monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
form{background:#111113;border:1px solid #232328;border-radius:8px;padding:2rem;display:flex;flex-direction:column;gap:1rem;min-width:320px}
input{background:#0a0a0b;border:1px solid #232328;color:#f0f0f2;padding:.625rem .875rem;border-radius:5px;font-family:monospace}
button{background:#f5a623;color:#0a0a0b;border:none;padding:.625rem 1.25rem;border-radius:5px;font-weight:600;cursor:pointer}
.error{color:#e84040;font-size:12px}</style></head>
<body><form method="POST" action="/login"><h2 style="margin:0">🪤 snare</h2>
<input type="password" name="token" placeholder="Dashboard token" autofocus>
<button>Access dashboard</button></form></body></html>`)
			return
		}
		w.Header().Set("WWW-Authenticate", `Bearer realm="snare dashboard"`)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}
}

// Serve starts the HTTP (or HTTPS) server and blocks until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	defer s.db.close()

	handler := securityHeaders(s.mux)

	if s.cfg.TLSDomain != "" {
		return s.serveTLS(ctx, handler)
	}
	return s.servePlain(ctx, handler)
}

func (s *Server) servePlain(ctx context.Context, h http.Handler) error {
	addr := fmt.Sprintf(":%d", s.cfg.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      h,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	log.Printf("snare server listening on %s (db: %s)", addr, s.cfg.DBPath)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) serveTLS(ctx context.Context, h http.Handler) error {
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(s.cfg.TLSDomain),
		Cache:      autocert.DirCache(os.ExpandEnv("$HOME/.snare/serve/certs")),
	}

	srv := &http.Server{
		Addr:         ":443",
		Handler:      h,
		TLSConfig:    m.TLSConfig(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Redirect HTTP → HTTPS
	redir := &http.Server{
		Addr:    ":80",
		Handler: m.HTTPHandler(nil),
	}
	go func() {
		if err := redir.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Printf("http redirect: %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
		_ = redir.Shutdown(shutCtx)
	}()

	log.Printf("snare server listening on :443 (TLS, domain=%s, db: %s)", s.cfg.TLSDomain, s.cfg.DBPath)
	if err := srv.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func jsonResp(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decodeJSONBody(w http.ResponseWriter, r *http.Request, v interface{}) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	return json.NewDecoder(r.Body).Decode(v)
}

func requestBodyError(err error) (int, string) {
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		return http.StatusRequestEntityTooLarge, "request body too large"
	}
	return http.StatusBadRequest, "bad request"
}

func jsonDecodeError(w http.ResponseWriter, err error) {
	status, msg := requestBodyError(err)
	if status == http.StatusBadRequest {
		msg = "invalid JSON"
	}
	jsonResp(w, status, map[string]string{"error": msg})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request, trustedProxyNets []*net.IPNet) string {
	remoteIP := remoteAddrIP(r.RemoteAddr)
	if trustedProxy(remoteIP, trustedProxyNets) {
		if ip := firstForwardedIP(r.Header.Get("X-Forwarded-For")); ip != "" {
			return ip
		}
		if ip := validHeaderIP(r.Header.Get("X-Real-Ip")); ip != "" {
			return ip
		}
	}
	return remoteIP
}

func remoteAddrIP(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return host
	}
	return remoteAddr
}

func firstForwardedIP(xff string) string {
	if xff == "" {
		return ""
	}
	parts := strings.SplitN(xff, ",", 2)
	if len(parts) == 0 {
		return ""
	}
	return validHeaderIP(parts[0])
}

func validHeaderIP(value string) string {
	ip := strings.TrimSpace(value)
	if ip == "" || net.ParseIP(ip) == nil {
		return ""
	}
	return ip
}

func parseTrustedProxyCIDRs(cidrs []string) ([]*net.IPNet, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}
	trusted := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("%q: %w", cidr, err)
		}
		trusted = append(trusted, network)
	}
	return trusted, nil
}

func trustedProxy(remoteIP string, trustedProxyNets []*net.IPNet) bool {
	if len(trustedProxyNets) == 0 {
		return false
	}
	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return false
	}
	for _, network := range trustedProxyNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// newID generates a random hex-encoded ID with the given prefix.
func newID(prefix string, bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}

// bearerToken extracts the Bearer token from the Authorization header.
func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	if after, ok := strings.CutPrefix(h, "Bearer "); ok {
		return strings.TrimSpace(after)
	}
	if after, ok := strings.CutPrefix(h, "bearer "); ok {
		return strings.TrimSpace(after)
	}
	return ""
}

// validateDevice checks the Bearer token against the stored hash for deviceID.
// Returns (true, nil) when valid.
func (s *Server) validateDevice(r *http.Request, deviceID string) (bool, error) {
	secret := bearerToken(r)
	if secret == "" {
		return false, nil
	}
	stored, err := s.db.deviceSecretHash(deviceID)
	if err != nil {
		return false, err
	}
	if stored == "" {
		return false, nil
	}
	return secureCompare(hashSecret(secret), stored), nil
}

func secureCompare(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return hmac.Equal([]byte(a), []byte(b))
}
