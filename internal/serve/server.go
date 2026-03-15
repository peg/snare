package serve

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
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

// Config holds the server configuration.
type Config struct {
	Port           int    // listen port (default 8080)
	DBPath         string // path to SQLite database
	TLSDomain      string // if set, enable Let's Encrypt TLS
	WebhookURL     string // global fallback webhook URL
	DashboardToken string // bearer token for dashboard + dashboard API auth (required)
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
	cfg Config
	db  *DB
	mux *http.ServeMux
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

	s := &Server{cfg: cfg, db: db, mux: http.NewServeMux()}
	s.routes()
	return s, nil
}

// routes wires all HTTP handlers.
func (s *Server) routes() {
	// Unauthenticated: canary callbacks and health
	s.mux.HandleFunc("/c/", s.handleCanary)
	s.mux.HandleFunc("/health", s.handleHealth)

	// Device API: authenticated by device secret (per-device bearer token)
	s.mux.HandleFunc("/api/devices", s.handleCreateDevice)
	s.mux.HandleFunc("/api/register", s.handleRegister)
	s.mux.HandleFunc("/api/revoke", s.handleRevoke)
	s.mux.HandleFunc("/api/events/", s.handleEvents)

	// Dashboard: authenticated by DashboardToken (operator-level access)
	s.mux.HandleFunc("/api/dashboard/alerts", s.requireDashboardAuth(s.handleDashboardAlerts))
	s.mux.HandleFunc("/api/dashboard/devices", s.requireDashboardAuth(s.handleDashboardDevices))
	s.mux.HandleFunc("/", s.requireDashboardAuth(s.handleDashboard))
}

// requireDashboardAuth wraps a handler to require Bearer token authentication.
// The token must match cfg.DashboardToken. If DashboardToken is empty, the
// server refuses to start (enforced in cmdServe).
func (s *Server) requireDashboardAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.cfg.DashboardToken == "" {
			http.Error(w, "dashboard auth not configured", http.StatusServiceUnavailable)
			return
		}
		auth := r.Header.Get("Authorization")
		if auth == "Bearer "+s.cfg.DashboardToken {
			next(w, r)
			return
		}
		// Also accept token as query param for browser access to the dashboard
		if r.URL.Query().Get("token") == s.cfg.DashboardToken {
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
button{background:#f5a623;color:#0a0a0b;border:none;padding:.625rem 1.25rem;border-radius:5px;font-weight:600;cursor:pointer}</style></head>
<body><form method="GET"><h2 style="margin:0">🪤 snare</h2>
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

	handler := s.mux

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

func clientIP(r *http.Request) string {
	// Honour standard proxy headers when running behind a reverse proxy.
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		// X-Forwarded-For can contain a comma-separated list; take the first.
		if parts := strings.SplitN(ip, ",", 2); len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	if ip := r.Header.Get("X-Real-Ip"); ip != "" {
		return ip
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	return host
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
	return hashSecret(secret) == stored, nil
}
