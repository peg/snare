package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/peg/snare/internal/serve"
)

// cmdServe starts the self-hosted snare HTTP server.
func cmdServe(args []string) {
	if hasFlag(args, "--help") || hasFlag(args, "-h") {
		fmt.Print(`snare serve — run a self-hosted callback server

Usage:
  snare serve [--port <port>] [--db <path>] [--dashboard-token <token>] [--webhook-url <url>] [--tls-domain <domain>] [--trusted-proxy <cidr,...>]

Required:
  --dashboard-token <token>   token for dashboard and dashboard API auth
                              also accepted via SNARE_DASHBOARD_TOKEN

Flags:
  --port <port>               listen port (default: 8080)
  --db <path>                 SQLite database path (default: ~/.snare/serve/snare.db)
  --webhook-url <url>         global fallback webhook destination
  --tls-domain <domain>       enable Let's Encrypt TLS for this domain
  --trusted-proxy <cidr,...>  trusted reverse proxy CIDRs allowed to set client IP headers
  --help                      show this help

Examples:
  SNARE_DASHBOARD_TOKEN="$(openssl rand -hex 32)" snare serve
  snare serve --port 8080 --db /data/snare.db --dashboard-token "$SNARE_DASHBOARD_TOKEN"
`)
		return
	}

	portStr := flagValue(args, "--port")
	dbPath := flagValue(args, "--db")
	tlsDomain := flagValue(args, "--tls-domain")
	webhookURL := flagValue(args, "--webhook-url")
	dashToken := flagValue(args, "--dashboard-token")
	trustedProxy := flagValue(args, "--trusted-proxy")

	// Also accept token from env var
	if dashToken == "" {
		dashToken = os.Getenv("SNARE_DASHBOARD_TOKEN")
	}

	if dashToken == "" {
		fmt.Fprintln(os.Stderr, "error: --dashboard-token is required for snare serve")
		fmt.Fprintln(os.Stderr, "  This token protects the dashboard and alert API from unauthorized access.")
		fmt.Fprintln(os.Stderr, "  Set it with --dashboard-token <token> or SNARE_DASHBOARD_TOKEN env var.")
		fmt.Fprintln(os.Stderr, "  Generate one with: openssl rand -hex 32")
		os.Exit(1)
	}

	if len(dashToken) < 16 {
		fmt.Fprintln(os.Stderr, "error: --dashboard-token must be at least 16 characters")
		os.Exit(1)
	}

	cfg := serve.DefaultConfig()
	cfg.DashboardToken = dashToken

	if portStr != "" {
		p, err := strconv.Atoi(portStr)
		if err != nil || p < 1 || p > 65535 {
			fmt.Fprintf(os.Stderr, "error: invalid --port %q\n", portStr)
			os.Exit(1)
		}
		cfg.Port = p
	}
	if dbPath != "" {
		cfg.DBPath = dbPath
	}
	if tlsDomain != "" {
		cfg.TLSDomain = tlsDomain
	}
	if webhookURL != "" {
		cfg.WebhookURL = webhookURL
	}
	if trustedProxy != "" {
		cfg.TrustedProxyCIDRs = strings.Split(trustedProxy, ",")
	}

	srv, err := serve.New(cfg)
	if err != nil {
		fatal(fmt.Errorf("starting server: %w", err))
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if err := srv.Serve(ctx); err != nil {
		fatal(err)
	}
}
