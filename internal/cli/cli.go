// Package cli implements the snare command-line interface.
package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/peg/snare/internal/bait"
	"github.com/peg/snare/internal/config"
	"github.com/peg/snare/internal/manifest"
	"github.com/peg/snare/internal/serve"
	"github.com/peg/snare/internal/token"
)

// reliability returns a human-readable reliability label per canary type.
func reliability(t string) string {
	switch bait.Type(t) {
	// High: callback URL is the real SDK service endpoint — fires on any use
	case bait.TypeAWS, bait.TypeAWSProc, bait.TypeGCP,
		bait.TypeSSH, bait.TypeK8s, bait.TypePyPI,
		bait.TypeAzure:
		return "high"
	// Medium-high: fires reliably but requires specific agent behavior
	case bait.TypeOpenAI, bait.TypeAnthropic, bait.TypeNPM, bait.TypeMCP,
		bait.TypeHuggingFace, bait.TypeDocker:
		return "medium"
	default:
		return "medium"
	}
}

const usage = `snare — compromise detection for AI agents via deception

Quick start:
  snare arm --webhook <url>    arm this machine (init + plant precision canaries + test)
  snare disarm                 remove all canaries and clean up
  snare status                 show active canaries

Commands:
  snare arm [flags]            one-command setup: init + plant + test
  snare disarm [flags]         one-command teardown
  snare status                 show active canaries
  snare scan                   check canary integrity on disk
  snare events                 fetch recent alert events from snare.sh
  snare test                   fire a test alert to verify your webhook
  snare doctor                 validate configuration and canary health
  snare config                 show current config
  snare config set webhook <url>  update webhook URL
  snare serve [flags]          run self-hosted callback server (replaces snare.sh)

Advanced:
  snare init                   initialize snare on this machine
  snare plant [flags]          plant individual canary credentials
  snare teardown [flags]       remove specific canaries
  snare rotate                 rotate device secret (if leaked)
  snare uninstall [-y] [--force]  disarm + remove config + remove binary

Flags (arm):
  --webhook <url>              webhook URL (Discord, Slack, Telegram, or custom)
  --label <name>               prefix canary names (defaults to hostname)
  --all                        plant all canary types including dotenv-based ones
                               (openai, anthropic, huggingface, npm, mcp, github, stripe, generic, docker, azure)
  --dry-run                    show what would be planted without writing

Flags (plant):
  --label <name>               prefix canary names (defaults to hostname)
  --type <type>                canary type: aws, awsproc, gcp, github, stripe, openai, anthropic, ssh, k8s, npm, mcp, pypi, huggingface, docker, azure, generic
  --all                        plant all high-reliability canary types at once
  --dry-run                    show what would be planted without writing anything

Flags (disarm/teardown):
  --token <id>                 remove a single canary by ID
  --force                      remove even if content hash mismatches
  --purge                      also remove ~/.snare/ config directory
  --dry-run                    show what would be removed without writing anything

Flags (serve):
  --port <n>                   HTTP listen port (default: 8080)
  --db <path>                  SQLite database path (default: ~/.snare/serve/snare.db)
  --tls-domain <domain>        enable Let's Encrypt HTTPS for this domain
  --webhook-url <url>          global fallback webhook URL for alerts
  --dashboard-token <token>    required: token to protect the dashboard (min 16 chars)
                               also: SNARE_DASHBOARD_TOKEN env var
`

// Run dispatches the CLI command.
func Run(args []string, version string) {
	if len(args) == 0 {
		fmt.Print(usage)
		os.Exit(0)
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "arm":
		cmdArm(rest)
	case "disarm":
		cmdDisarm(rest)
	case "rotate":
		cmdRotate(rest)
	case "init":
		cmdInit(rest)
	case "plant":
		cmdPlant(rest)
	case "status":
		cmdStatus(rest)
	case "scan":
		cmdScan(rest)
	case "events":
		cmdEvents(rest)
	case "test":
		cmdTest(rest)
	case "teardown":
		cmdTeardown(rest)
	case "uninstall":
		cmdUninstall(rest)
	case "config":
		cmdConfig(rest)
	case "doctor":
		cmdDoctor(rest)
	case "serve":
		cmdServe(rest)
	case "help", "--help", "-h":
		fmt.Print(usage)
	case "version", "--version", "-v":
		fmt.Printf("snare %s\n", version)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", cmd, usage)
		os.Exit(1)
	}
}

// cmdArm is the one-command setup: init + plant all + test.
// This is the happy path for new machines.
// precisionTypes are the highest-signal canaries: near-zero false positives,
// fire only on active credential use or resolution. For environments where
// you want maximum signal-to-noise ratio.
var precisionTypes = []bait.Type{
	bait.TypeAWSProc, // fires at credential resolution — before any API call
	bait.TypeSSH,     // fires on SSH connection attempt via ProxyCommand
	bait.TypeK8s,     // fires on any kubectl/SDK call to fake cluster
	bait.TypeAzure,   // fires on Azure SDK token refresh via tokenEndpoint
}

func cmdArm(args []string) {
	if hasFlag(args, "--help") || hasFlag(args, "-h") {
		fmt.Print(`snare arm — initialize snare and plant canaries (precision mode by default)

Usage:
  snare arm [flags]

By default, snare arm plants only the highest-signal canaries (awsproc, ssh, k8s, azure).
These fire only on active credential use — zero false positives from your own tooling.
Running AI agents on this machine? The default precision mode won't fire on your own tooling.
Use --all to arm every canary type.

Flags:
  --webhook <url>    webhook URL (Discord, Slack, Telegram, PagerDuty, Teams)
  --label <name>     prefix canary names (defaults to hostname)
  --all              plant all canary types including dotenv-based ones
  --dry-run          show what would be planted without writing anything
  --help             show this help

Examples:
  snare arm --webhook https://discord.com/api/webhooks/...
  snare arm --webhook https://hooks.slack.com/... --label prod-server
  snare arm --all --webhook <url>
`)
		return
	}

	webhookURL := flagValue(args, "--webhook")
	label      := flagValue(args, "--label")
	dryRun     := hasFlag(args, "--dry-run")
	armAll     := hasFlag(args, "--all")

	if label == "" {
		if h, err := os.Hostname(); err == nil {
			label = strings.ToLower(strings.ReplaceAll(h, ".", "-"))
		} else {
			label = "snare"
		}
	}

	// Step 1: Initialize (or reuse existing config)
	// Dry-run skips config writes entirely
	cfg, err := config.Load()
	if err != nil {
		fatal(err)
	}

	if dryRun {
		if cfg == nil {
			fmt.Println("  [dry-run] would initialize config")
			// Create a temporary in-memory config for dry-run rendering
			cfg = &config.Config{
				DeviceID:     "dry-run",
				CallbackBase: "https://snare.sh/c",
				WebhookURL:   webhookURL,
			}
		} else {
			fmt.Printf("  ✓ already initialized (device: %s)\n", cfg.DeviceID)
		}
	} else if cfg == nil {
		// First time — need webhook URL
		if webhookURL == "" {
			// Try interactive init
			fmt.Println()
			guidedInit(false)
			// Reload config after guided init
			cfg, err = config.Load()
			if err != nil || cfg == nil {
				fatal(fmt.Errorf("init failed — run `snare init` manually"))
			}
		} else {
			cfg, err = config.Init("", webhookURL, false)
			if err != nil {
				fatal(err)
			}
			fmt.Printf("  ✓ initialized (device: %s)\n", cfg.DeviceID)
		}
	} else {
		// Already initialized — update webhook if provided
		if webhookURL != "" && webhookURL != cfg.WebhookURL {
			cfg.WebhookURL = webhookURL
			if err := cfg.Save(); err != nil {
				fatal(fmt.Errorf("updating webhook: %w", err))
			}
			fmt.Printf("  ✓ webhook updated\n")
		} else {
			fmt.Printf("  ✓ already initialized (device: %s)\n", cfg.DeviceID)
		}
	}

	// Step 2: Plant all high-reliability canaries
	m, err := manifest.Load()
	if err != nil {
		fatal(err)
	}

	fmt.Println()
	fmt.Println("  Planting canaries...")

	armTypes := precisionTypes
	if armAll {
		armTypes = highReliabilityTypes
		fmt.Println("  Full mode: planting all canary types (including dotenv-based)")
	} else {
		fmt.Println("  Precision mode: planting highest-signal canaries only (awsproc, ssh, k8s, azure)")
	}

	planted := 0
	skipped := 0
	for _, bt := range armTypes {
		params, err := buildParams(bt, label, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "    ✗ %s: %v\n", bt, err)
			continue
		}

		paths, err := bait.DefaultPaths(bt)
		if err != nil {
			fmt.Fprintf(os.Stderr, "    ✗ %s: %v\n", bt, err)
			continue
		}

		for _, path := range paths {
			if dryRun {
				fmt.Printf("    [dry-run] %s → %s\n", bt, path)
				planted++
				continue
			}

			// Check if this type is already planted at this path
			alreadyPlanted := false
			for _, c := range m.Active() {
				if c.Type == string(bt) && c.Path == path {
					alreadyPlanted = true
					break
				}
			}
			if alreadyPlanted {
				fmt.Printf("    ○ %-12s %s (already armed)\n", bt, path)
				skipped++
				continue
			}

			// Silent pre-render
			preview, err := bait.Plant(bt, params, path, true, true)
			if err != nil {
				fmt.Fprintf(os.Stderr, "    ✗ %-12s %v\n", bt, err)
				continue
			}

			// Write manifest
			c := manifest.Canary{
				ID:          params.TokenID,
				Type:        string(bt),
				Label:       label,
				Path:        preview.Path,
				Mode:        preview.Mode,
				Content:     preview.Content,
				ContentHash: manifest.HashContent(preview.Content),
				CallbackURL: params.CallbackURL,
				PlantedAt:   time.Now(),
			}
			if err := m.AddPending(c); err != nil {
				fmt.Fprintf(os.Stderr, "    ✗ %-12s manifest: %v\n", bt, err)
				continue
			}

			// Write bait
			if _, err := bait.Plant(bt, params, path, false); err != nil {
				_ = m.Deactivate(params.TokenID, "plant-failed")
				fmt.Fprintf(os.Stderr, "    ✗ %-12s %v\n", bt, err)
				continue
			}

			// Activate
			if err := m.Activate(params.TokenID); err != nil {
				fmt.Fprintf(os.Stderr, "    ⚠  %-12s planted but activation failed\n", bt)
				continue
			}

			// Register with snare.sh — always, so device owns the token for events auth.
			// registerToken uses "use-global" sentinel when no local webhook configured.
			if err := registerToken(cfg, params.TokenID, string(bt), label); err != nil {
				fmt.Fprintf(os.Stderr, "    ⚠  %-12s planted but registration failed: %v\n", bt, err)
				fmt.Fprintf(os.Stderr, "       Canary is active but alerts may not be delivered.\n")
				fmt.Fprintf(os.Stderr, "       Run `snare doctor` to diagnose.\n")
			}

			fmt.Printf("    ✓ %-12s %s\n", bt, path)
			planted++
		}
	}

	if dryRun {
		fmt.Printf("\n  [dry-run] would plant %d canaries\n", planted)
		return
	}

	// Step 3: Test the full alert pipeline — register test token first, then fire callback.
	fmt.Println()
	{
		shortID := cfg.DeviceID
		if len(shortID) > 8 {
			shortID = shortID[len(shortID)-8:]
		}
		testToken := "snare-test-" + shortID
		if err := registerToken(cfg, testToken, "test", "test"); err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠  test webhook registration failed: %v\n", err)
		}
		callbackURL := cfg.CallbackURL(testToken)
		if err := httpGet(callbackURL); err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠  webhook test failed: %v\n", err)
		} else {
			fmt.Println("  ✓ webhook test fired")
		}
	}

	// Summary
	fmt.Println()
	total := planted + skipped
	if total == 0 {
		fmt.Println("  No canaries planted. Check errors above.")
	} else {
		fmt.Printf("  🪤 %d canaries armed.", total)
		if skipped > 0 {
			fmt.Printf(" (%d new, %d already armed)", planted, skipped)
		}
		fmt.Println(" This machine is protected.")
		fmt.Println()
		fmt.Println("  Run `snare status` to check.")
		fmt.Println("  Run `snare disarm` to remove everything.")
	}
}

// cmdDisarm removes all canaries. Clean, fast, one command.
func cmdDisarm(args []string) {
	dryRun := hasFlag(args, "--dry-run")
	purge := hasFlag(args, "--purge")
	force := hasFlag(args, "--force")
	tokenID := flagValue(args, "--token")

	m, err := manifest.Load()
	if err != nil {
		if purge {
			// Manifest might be corrupt — just nuke ~/.snare/
			goto purgeDir
		}
		fatal(err)
	}

	{
		var targets []manifest.Canary
		if tokenID != "" {
			c := m.FindByID(tokenID)
			if c == nil {
				fatal(fmt.Errorf("canary %s not found", tokenID))
			}
			targets = []manifest.Canary{*c}
		} else {
			targets = m.Active()
		}

		if len(targets) == 0 && !purge {
			fmt.Println("  No active canaries. Machine is clean.")
			return
		}

		if dryRun {
			fmt.Printf("  [dry-run] would remove %d canary(s)\n", len(targets))
			for _, c := range targets {
				fmt.Printf("    %-12s %s\n", c.Type, c.Path)
			}
			if purge {
				fmt.Println("  [dry-run] would delete ~/.snare/")
			}
			return
		}

		if len(targets) > 0 {
			fmt.Printf("  Removing %d canaries...\n", len(targets))
		}

		removed := 0
		for _, c := range targets {
			if err := bait.Remove(c, force, false); err != nil {
				fmt.Fprintf(os.Stderr, "    ✗ %-12s %s: %v\n", c.Type, c.Path, err)
				continue
			}
			_ = m.Deactivate(c.ID, "disarm")

			// Deregister webhook (best-effort) — auth uses device secret, not webhook URL
			if cfg, err := config.Load(); err == nil && cfg != nil {
				_ = revokeToken(cfg, c.ID)
			}

			fmt.Printf("    ✓ %-12s %s\n", c.Type, c.Path)
			removed++
		}

		fmt.Printf("\n  ✓ %d canaries removed. Machine disarmed.\n", removed)
	}

purgeDir:
	if purge {
		dir, err := manifest.Dir()
		if err != nil {
			fatal(err)
		}
		if err := os.RemoveAll(dir); err != nil {
			fatal(fmt.Errorf("removing ~/.snare: %w", err))
		}
		fmt.Println("  ✓ ~/.snare/ removed.")
	} else {
		fmt.Println("  Config preserved at ~/.snare/ — run `snare arm` to re-arm.")
		fmt.Println("  Run `snare disarm --purge` to also remove config.")
	}
}

// cmdConfig shows or updates configuration.
func cmdConfig(args []string) {
	if len(args) == 0 {
		// Show current config
		cfg, err := config.Load()
		if err != nil || cfg == nil {
			fmt.Fprintln(os.Stderr, "  snare is not initialized. Run `snare arm` to get started.")
			os.Exit(1)
		}
		fmt.Println()
		fmt.Printf("  Device ID:     %s\n", cfg.DeviceID)
		fmt.Printf("  Callback base: %s\n", cfg.CallbackBase)
		if cfg.WebhookURL != "" {
			fmt.Printf("  Webhook URL:   %s\n", cfg.WebhookURL)
		} else {
			fmt.Printf("  Webhook URL:   (using global snare.sh fallback)\n")
		}
		fmt.Printf("  Config file:   ~/.snare/config.json\n")
		fmt.Println()
		return
	}

	// snare config set webhook <url>
	if len(args) >= 3 && args[0] == "set" && args[1] == "webhook" {
		url := args[2]
		cfg, err := config.Load()
		if err != nil || cfg == nil {
			fmt.Fprintln(os.Stderr, "  snare is not initialized. Run `snare arm` to get started.")
			os.Exit(1)
		}
		cfg.WebhookURL = url
		if err := cfg.Save(); err != nil {
			fatal(fmt.Errorf("failed to save config: %w", err))
		}
		fmt.Printf("  ✓ Webhook URL updated: %s\n", url)
		fmt.Println("  Run `snare test` to verify the new webhook works.")
		// Re-register active tokens with new webhook
		mfst, _ := manifest.Load()
		if mfst != nil {
			active := mfst.Active()
			if len(active) > 0 {
				fmt.Printf("  Updating %d token registrations...\n", len(active))
				ok := 0
				for _, c := range active {
					if err := registerToken(cfg, c.ID, string(c.Type), c.Label); err == nil {
						ok++
					}
				}
				fmt.Printf("  ✓ %d/%d tokens re-registered.\n", ok, len(active))
			}
		}
		return
	}

	fmt.Fprintf(os.Stderr, "unknown config subcommand\n\nUsage:\n  snare config\n  snare config set webhook <url>\n")
	os.Exit(1)
}

// cmdDoctor validates that snare is properly configured and canaries are healthy.
func cmdDoctor(args []string) {
	fmt.Println()
	fmt.Println("  snare doctor — checking your setup")
	fmt.Println()

	pass := 0
	fail := 0
	warn := 0

	check := func(label, status, detail string) {
		switch status {
		case "ok":
			fmt.Printf("  ✓ %-30s %s\n", label, detail)
			pass++
		case "warn":
			fmt.Printf("  ⚠ %-30s %s\n", label, detail)
			warn++
		case "fail":
			fmt.Printf("  ✗ %-30s %s\n", label, detail)
			fail++
		}
	}

	// 1. Config exists and is valid
	cfg, err := config.Load()
	if err != nil || cfg == nil {
		check("Config", "fail", "~/.snare/config.json missing — run `snare arm`")
		fmt.Println()
		fmt.Printf("  0 passed, 0 warned, 1 failed\n\n")
		os.Exit(1)
	}
	check("Config", "ok", "~/.snare/config.json loaded")
	check("Device ID", "ok", cfg.DeviceID)

	// 2. Callback base is reachable
	healthURL := strings.Replace(cfg.CallbackBase, "/c", "/health", 1)
	resp, err := http.Get(healthURL) //nolint:gosec
	if err != nil {
		check("Callback server", "fail", fmt.Sprintf("unreachable (%s)", healthURL))
	} else {
		resp.Body.Close()
		if resp.StatusCode == 200 {
			check("Callback server", "ok", healthURL)
		} else {
			check("Callback server", "warn", fmt.Sprintf("HTTP %d at %s", resp.StatusCode, healthURL))
		}
	}

	// 3. Webhook configured
	if cfg.WebhookURL != "" {
		check("Webhook", "ok", cfg.WebhookURL[:min(40, len(cfg.WebhookURL))]+"...")
	} else {
		check("Webhook", "warn", "no local webhook (using global snare.sh fallback)")
	}

	// 4. Manifest exists and has active canaries
	mfst, err := manifest.Load()
	if err != nil || mfst == nil {
		check("Manifest", "fail", "~/.snare/manifest.json missing or unreadable")
	} else {
		active := mfst.Active()
		if len(active) == 0 {
			check("Active canaries", "fail", "none found — run `snare arm`")
		} else {
			check("Active canaries", "ok", fmt.Sprintf("%d armed", len(active)))

			// 5. Verify each canary file still exists and hash matches
			mismatched := 0
			missing := 0
			for _, c := range active {
				data, err := os.ReadFile(c.Path)
				if err != nil {
					missing++
					continue
				}
				h := sha256.Sum256(data)
				fileHash := hex.EncodeToString(h[:])
				if string(c.Mode) == "append" {
					// For append mode, check the planted block is still present
					if !strings.Contains(string(data), c.ID) {
						mismatched++
					}
				} else {
					// For new-file mode, check full hash
					if fileHash != c.ContentHash {
						mismatched++
					}
				}
			}
			if missing > 0 {
				check("Canary files", "fail", fmt.Sprintf("%d missing from disk — run `snare arm` to replant", missing))
			} else if mismatched > 0 {
				check("Canary integrity", "warn", fmt.Sprintf("%d files modified since planting", mismatched))
			} else {
				check("Canary files", "ok", "all present and unmodified")
			}
		}
	}

	// 6. Fire test alert (optional, only if --test flag provided or interactive)
	if hasFlag(args, "--test") {
		fmt.Println()
		fmt.Println("  Firing test alert...")
		testURL := strings.Replace(cfg.CallbackBase, "/c", "/c/snare-test-"+cfg.DeviceID[len(cfg.DeviceID)-8:], 1)
		resp, err := http.Get(testURL) //nolint:gosec
		if err != nil {
			check("Test alert", "fail", err.Error())
		} else {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				check("Test alert", "ok", "fired — check your webhook")
			} else {
				check("Test alert", "warn", fmt.Sprintf("HTTP %d", resp.StatusCode))
			}
		}
	}

	// Summary
	fmt.Println()
	if fail > 0 {
		fmt.Printf("  %d passed, %d warned, %d failed\n\n", pass, warn, fail)
		os.Exit(1)
	} else if warn > 0 {
		fmt.Printf("  %d passed, %d warned — looks mostly good\n\n", pass, warn)
	} else {
		fmt.Printf("  %d passed — all good 🪤\n\n", pass)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// cmdRotate generates a new device secret and re-registers all active tokens.
// Use this if your device secret was leaked (e.g., ~/.snare/config.json exposed).
func cmdRotate(args []string) {
	cfg, err := config.Load()
	if err != nil || cfg == nil {
		fatal(fmt.Errorf("snare not initialized — run `snare arm` first"))
	}

	fmt.Println("  Rotating device secret...")
	fmt.Printf("  Old secret: %s...%s\n", cfg.DeviceSecret[:4], cfg.DeviceSecret[len(cfg.DeviceSecret)-4:])

	// Generate new secret
	newSecret, err := config.NewDeviceSecret()
	if err != nil {
		fatal(fmt.Errorf("generating new secret: %w", err))
	}

	// Update config
	cfg.DeviceSecret = newSecret
	if err := cfg.Save(); err != nil {
		fatal(fmt.Errorf("saving config: %w", err))
	}
	fmt.Println("  ✓ New secret saved to ~/.snare/config.json")

	// Re-register all active tokens with new secret
	m, err := manifest.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ⚠  could not load manifest: %v\n", err)
		return
	}

	active := m.Active()
	if len(active) == 0 {
		fmt.Println("  No active tokens to re-register.")
		return
	}

	// Tell the server to update the stored secret hash for this device.
	// This is the critical step — without it, all subsequent API calls will 401.
	fmt.Println("  Updating server-side secret hash...")
	rotateResp, err := authedPost(cfg.RotateURL(), map[string]string{
		"device_id":  cfg.DeviceID,
		"new_secret": newSecret,
	}, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ✗ server rotation failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "  Config saved locally — run `snare rotate` again once connectivity is restored.\n")
		return
	}
	defer rotateResp.Body.Close()
	if rotateResp.StatusCode != 200 {
		body, _ := io.ReadAll(rotateResp.Body)
		fmt.Fprintf(os.Stderr, "  ✗ server rotation failed (HTTP %d): %s\n", rotateResp.StatusCode, strings.TrimSpace(string(body)))
		fmt.Fprintf(os.Stderr, "  Config saved locally — run `snare rotate` again once the issue is resolved.\n")
		return
	}
	fmt.Println("  ✓ Server secret hash updated")

	// Re-register all active tokens with new secret
	if len(active) > 0 {
		fmt.Printf("  Re-registering %d tokens...\n", len(active))
		ok := 0
		for _, c := range active {
			if err := registerToken(cfg, c.ID, c.Type, c.Label); err != nil {
				fmt.Fprintf(os.Stderr, "    ✗ %s: %v\n", c.ID[:16], err)
			} else {
				ok++
			}
		}
		fmt.Printf("  ✓ %d/%d tokens re-registered with new secret.\n", ok, len(active))
	}
	fmt.Println()
	fmt.Println("  ✓ Rotation complete. Old secret is now invalid.")
}

// cmdInit sets up snare for this machine.
// With --webhook: non-interactive. Without: guided setup.
func cmdInit(args []string) {
	force      := hasFlag(args, "--force")
	webhookURL := flagValue(args, "--webhook")

	// Non-interactive path: --webhook provided (CI, scripting)
	if webhookURL != "" {
		cfg, err := config.Init("", webhookURL, force)
		if err != nil {
			fatal(err)
		}
		fmt.Printf("✓ snare initialized\n")
		fmt.Printf("  Device ID: %s\n", cfg.DeviceID)
		fmt.Printf("  Webhook:   configured\n")
		fmt.Printf("\nRun `snare plant` to deploy your first canaries.\n")
		return
	}

	// Interactive guided setup
	guidedInit(force)
}

func guidedInit(force bool) {
	scanner := bufio.NewScanner(os.Stdin)

	fmt.Println()
	fmt.Println("  Welcome to Snare — compromise detection for AI agents.")
	fmt.Println("  Let's get you set up. This takes about 2 minutes.")
	fmt.Println()

	// Initialize config (generate device ID)
	cfg, err := config.Init("", "", force)
	if err != nil {
		fatal(err)
	}

	fmt.Printf("  Device ID: %s\n", cfg.DeviceID)
	fmt.Println()

	// Choose platform
	fmt.Println("  Where would you like to receive alerts?")
	fmt.Println()
	fmt.Println("    1. Discord")
	fmt.Println("    2. Slack")
	fmt.Println("    3. Telegram")
	fmt.Println("    4. Custom webhook")
	fmt.Println()
	fmt.Print("  Choice [1]: ")

	choice := "1"
	if scanner.Scan() {
		if t := strings.TrimSpace(scanner.Text()); t != "" {
			choice = t
		}
	}

	// Show platform-specific instructions
	fmt.Println()
	switch choice {
	case "1", "discord":
		fmt.Println("  Discord setup:")
		fmt.Println("    1. Open your Discord server → Server Settings → Integrations")
		fmt.Println("    2. Click Webhooks → New Webhook")
		fmt.Println("    3. Name it \"Snare\", pick a channel (e.g. #alerts)")
		fmt.Println("    4. Click Copy Webhook URL")
		fmt.Println()
		fmt.Println("  The URL looks like: https://discord.com/api/webhooks/123.../abc...")
	case "2", "slack":
		fmt.Println("  Slack setup:")
		fmt.Println("    1. Go to https://api.slack.com/apps → Create New App → From scratch")
		fmt.Println("    2. Features → Incoming Webhooks → Activate Incoming Webhooks")
		fmt.Println("    3. Add New Webhook to Workspace → pick a channel → Allow")
		fmt.Println("    4. Copy the webhook URL")
		fmt.Println()
		fmt.Println("  The URL looks like: https://hooks.slack.com/services/T.../B.../xxx")
	case "3", "telegram":
		fmt.Println("  Telegram setup:")
		fmt.Println("    1. Message @BotFather → /newbot → follow prompts → copy the token")
		fmt.Println("    2. Add your bot to a group or send it a message")
		fmt.Println("    3. Get your chat ID:")
		fmt.Println("       curl https://api.telegram.org/bot<TOKEN>/getUpdates")
		fmt.Println("    4. Your webhook URL is:")
		fmt.Println("       https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<CHAT_ID>")
	case "4", "custom":
		fmt.Println("  Custom webhook:")
		fmt.Println("  Snare will POST a JSON payload to your URL when a canary fires.")
		fmt.Println("  See ARCHITECTURE.md for the event schema.")
	default:
		fmt.Println("  Custom webhook:")
	}

	fmt.Println()
	fmt.Print("  Paste your webhook URL: ")

	var webhookURL string
	for {
		if !scanner.Scan() {
			// EOF or stdin closed — non-interactive environment
			fmt.Fprintln(os.Stderr, "\n  error: no webhook URL provided")
			fmt.Fprintln(os.Stderr, "  Use: snare arm --webhook <url>")
			os.Exit(1)
		}
		webhookURL = strings.TrimSpace(scanner.Text())
		if webhookURL == "" {
			fmt.Print("  URL cannot be empty. Try again: ")
			continue
		}
		if !strings.HasPrefix(webhookURL, "https://") {
			fmt.Print("  URL must start with https://. Try again: ")
			continue
		}
		break
	}

	// Save webhook URL
	cfg.WebhookURL = webhookURL
	if err := cfg.Save(); err != nil {
		fatal(fmt.Errorf("saving config: %w", err))
	}

	// Fire test alert
	fmt.Println()
	fmt.Println("  Firing a test alert to verify your webhook...")

	shortID := cfg.DeviceID
	if len(shortID) > 8 {
		shortID = shortID[len(shortID)-8:]
	}
	testToken := "snare-test-" + shortID
	callbackURL := cfg.CallbackURL(testToken)

	if err := httpGet(callbackURL); err != nil {
		fmt.Fprintf(os.Stderr, "\n  ⚠️  Test alert failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "  Check your internet connection and try again.\n\n")
	} else {
		fmt.Print("  Did you receive the alert? [Y/n]: ")
		if scanner.Scan() {
			resp := strings.ToLower(strings.TrimSpace(scanner.Text()))
			if resp == "n" || resp == "no" {
				fmt.Println()
				fmt.Println("  No alert received. A few things to check:")
				switch choice {
				case "1", "discord":
					fmt.Println("    • Make sure the webhook URL is correct (copy it again from Discord)")
					fmt.Println("    • Check that the bot has permission to post in that channel")
				case "2", "slack":
					fmt.Println("    • Make sure Incoming Webhooks is activated in your Slack app")
					fmt.Println("    • Verify the webhook URL was copied fully")
				case "3", "telegram":
					fmt.Println("    • Make sure your bot has sent or received at least one message")
					fmt.Println("    • Double-check your chat_id (use getUpdates to confirm)")
				}
				fmt.Println()
				fmt.Println("  You can update your webhook later:")
				fmt.Println("  snare init --webhook <new-url> --force")
				fmt.Println()
			}
		}
	}

	fmt.Println()
	fmt.Println("  ✓ snare is ready.")
	fmt.Println()
	fmt.Println("  Next steps:")
	fmt.Println("    snare plant             plant AWS canary credentials")
	fmt.Println("    snare plant --type gcp  plant GCP service account canary")
	fmt.Println("    snare status            view active canaries")
	fmt.Println()
}

// armCanaryTypes are planted by default with `snare arm` — the full recommended set.
// High reliability types fire when the SDK actually uses the credential.
// Medium reliability types fire conditionally but are still valuable coverage.
var highReliabilityTypes = []bait.Type{
	bait.TypeAWS, bait.TypeAWSProc, bait.TypeGCP,
	bait.TypeSSH, bait.TypeK8s, bait.TypePyPI,
	bait.TypeOpenAI, bait.TypeAnthropic, bait.TypeNPM, bait.TypeMCP,
	bait.TypeHuggingFace, bait.TypeDocker, bait.TypeAzure,
}

// cmdPlant deploys canary credentials to this machine.
func cmdPlant(args []string) {
	label    := flagValue(args, "--label")
	baitType := flagValue(args, "--type")
	dryRun   := hasFlag(args, "--dry-run")
	plantAll := hasFlag(args, "--all")

	// Default label to hostname
	if label == "" {
		if h, err := os.Hostname(); err == nil {
			label = strings.ToLower(strings.ReplaceAll(h, ".", "-"))
		} else {
			label = "snare"
		}
	}

	cfg, err := requireConfig()
	if err != nil {
		fatal(err)
	}

	m, err := manifest.Load()
	if err != nil {
		fatal(err)
	}

	// --all plants all high-reliability types
	if plantAll {
		for _, bt := range highReliabilityTypes {
			plantOne(bt, label, cfg, m, dryRun)
		}
		return
	}

	if baitType == "" {
		baitType = "aws"
	}

	bt := bait.Type(baitType)
	plantOne(bt, label, cfg, m, dryRun)
}

func plantOne(bt bait.Type, label string, cfg *config.Config, m *manifest.Manifest, dryRun bool) {
	params, err := buildParams(bt, label, cfg)
	if err != nil {
		fatal(err)
	}

	paths, err := bait.DefaultPaths(bt)
	if err != nil {
		fatal(err)
	}

	if dryRun {
		fmt.Printf("[dry-run] would plant %s canary\n\n", bt)
		for _, path := range paths {
			bait.Plant(bt, params, path, true) //nolint
		}
		return
	}

	fmt.Printf("Planting %s canary...\n", bt)

	for _, path := range paths {
		// Step 1: silent dry-run render to get content without touching disk or printing
		preview, err := bait.Plant(bt, params, path, true, true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ cannot plant %s: %v\n", path, err)
			continue
		}

		// Step 2: write pending manifest record BEFORE touching disk
		c := manifest.Canary{
			ID:          params.TokenID,
			Type:        string(bt),
			Label:       label,
			Path:        preview.Path,
			Mode:        preview.Mode,
			Content:     preview.Content,
			ContentHash: manifest.HashContent(preview.Content),
			CallbackURL: params.CallbackURL,
			PlantedAt:   time.Now(),
		}
		if err := m.AddPending(c); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ manifest write failed, skipping %s: %v\n", path, err)
			continue
		}

		// Step 3: write bait to disk
		if _, err := bait.Plant(bt, params, path, false); err != nil {
			_ = m.Deactivate(params.TokenID, "plant-failed")
			fmt.Fprintf(os.Stderr, "  ✗ planting %s failed: %v\n", path, err)
			continue
		}

		// Step 4: activate
		if err := m.Activate(params.TokenID); err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠️  bait written but manifest activation failed for %s: %v\n", path, err)
			fmt.Fprintf(os.Stderr, "  ⚠️  Token ID: %s\n", params.TokenID)
			continue
		}

		// Step 5: register with snare.sh — always, so device owns the token for events auth.
		// Uses "use-global" sentinel when no local webhook configured.
		if !dryRun {
			if err := registerToken(cfg, params.TokenID, string(bt), label); err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠️  webhook registration failed (alerts may not arrive): %v\n", err)
			}
		}

		fmt.Printf("  ✓ planted at %s\n", path)
		fmt.Printf("    token:    %s\n", params.TokenID)
		fmt.Printf("    callback: %s\n", params.CallbackURL)
	}

	fmt.Printf("\nRun `snare status` to see active canaries.\n")
	fmt.Printf("Run `snare test` to verify your alert pipeline.\n")
}

// ScanStatus represents the result for a single canary check.
type ScanStatus int

const (
	ScanOK       ScanStatus = iota // canary present, hash matches
	ScanModified                   // canary present, hash mismatch
	ScanMissing                    // canary not on disk
)

// ScanResult holds the outcome of scanning one manifest entry.
type ScanResult struct {
	Canary manifest.Canary
	Status ScanStatus
	Detail string
}

// OrphanResult holds a discovered canary URL with no manifest record.
type OrphanResult struct {
	Path    string
	URL     string
}

// snareURLPattern is the substring we look for to detect canary content on disk.
const snareURLPattern = "snare.sh/c/"

// ScanManifest checks each active canary against disk and returns categorised results.
// It does NOT scan for orphans (that requires filesystem walking — see ScanForOrphans).
func ScanManifest(m *manifest.Manifest) []ScanResult {
	active := m.Active()
	results := make([]ScanResult, 0, len(active))
	for _, c := range active {
		r := ScanResult{Canary: c}
		data, err := os.ReadFile(c.Path)
		if err != nil {
			r.Status = ScanMissing
			r.Detail = "file not found"
			results = append(results, r)
			continue
		}

		if c.Mode == manifest.ModeAppend {
			// Append mode: check the planted block is still present by looking for the ID
			if !strings.Contains(string(data), c.ID) {
				r.Status = ScanMissing
				r.Detail = "canary block not found in file"
			} else {
				// Block present — check if content matches exactly
				if !strings.Contains(string(data), c.Content) {
					r.Status = ScanModified
					r.Detail = "canary block present but content has changed"
				} else {
					r.Status = ScanOK
				}
			}
		} else {
			// New-file mode: compare full content hash
			h := sha256.Sum256(data)
			fileHash := hex.EncodeToString(h[:])
			if fileHash != c.ContentHash {
				r.Status = ScanModified
				r.Detail = "content hash mismatch"
			} else {
				r.Status = ScanOK
			}
		}
		results = append(results, r)
	}
	return results
}

// pathID is a (path, id) pair used for orphan scanning.
type pathID struct{ path, id string }

// ScanForOrphans walks the known canary paths and looks for snare.sh/c/ URLs
// in files that have no matching manifest entry. Returns any found orphans.
func ScanForOrphans(m *manifest.Manifest) ([]OrphanResult, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	// Build a set of active canary (path, id) pairs for fast lookup
	active := m.Active()
	covered := make(map[pathID]bool, len(active))
	for _, c := range active {
		covered[pathID{c.Path, c.ID}] = true
	}

	// Directories to scan for orphaned canary content
	scanDirs := []string{
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".config"),
		filepath.Join(home, ".kube"),
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".npmrc"),
		filepath.Join(home, ".pip"),
		filepath.Join(home, ".env"),
		filepath.Join(home, ".env.local"),
		filepath.Join(home, ".env.production"),
	}

	var orphans []OrphanResult

	for _, scanPath := range scanDirs {
		info, err := os.Stat(scanPath)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			continue
		}

		if info.IsDir() {
			// Walk directory
			err := filepath.WalkDir(scanPath, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				// Skip large files
				fi, err := d.Info()
				if err != nil || fi.Size() > 1<<20 { // 1 MB cap
					return nil
				}
				orphans = append(orphans, checkFileForOrphans(path, covered, active)...)
				return nil
			})
			if err != nil {
				continue
			}
		} else {
			// Single file
			orphans = append(orphans, checkFileForOrphans(scanPath, covered, active)...)
		}
	}

	return orphans, nil
}

// checkFileForOrphans reads a file and returns any snare canary URLs found
// that don't correspond to a known active canary entry.
func checkFileForOrphans(path string, covered map[pathID]bool, active []manifest.Canary) []OrphanResult {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	content := string(data)
	if !strings.Contains(content, snareURLPattern) {
		return nil
	}

	// Check if any known active canary covers this file by ID
	for _, c := range active {
		if c.Path == path && strings.Contains(content, c.ID) {
			return nil // covered by manifest
		}
	}

	// Found snare URL in this file but no manifest entry — it's an orphan
	// Extract the URL for display
	url := extractSnareURL(content)
	return []OrphanResult{{Path: path, URL: url}}
}

// extractSnareURL pulls out the first snare.sh/c/... URL from content.
func extractSnareURL(content string) string {
	idx := strings.Index(content, snareURLPattern)
	if idx == -1 {
		return "(unknown)"
	}
	// Walk backwards to find https://
	start := idx
	for start > 0 && content[start-1] != '\n' && content[start-1] != '"' &&
		content[start-1] != ' ' && content[start-1] != '\t' {
		start--
	}
	// Walk forward to end of URL
	end := idx
	for end < len(content) && content[end] != '\n' && content[end] != '"' &&
		content[end] != ' ' && content[end] != '\t' {
		end++
	}
	return strings.TrimSpace(content[start:end])
}

// cmdScan checks each active canary against disk and reports status.
func cmdScan(args []string) {
	m, err := manifest.Load()
	if err != nil {
		fatal(err)
	}

	active := m.Active()
	if len(active) == 0 {
		fmt.Println("No active canaries. Run `snare arm` to deploy.")
		return
	}

	results := ScanManifest(m)

	// Count per status
	var nOK, nModified, nMissing int
	for _, r := range results {
		switch r.Status {
		case ScanOK:
			nOK++
		case ScanModified:
			nModified++
		case ScanMissing:
			nMissing++
		}
	}

	// Scan for orphans
	orphans, orphanErr := ScanForOrphans(m)
	if orphanErr != nil {
		fmt.Fprintf(os.Stderr, "  ⚠  orphan scan failed: %v\n", orphanErr)
	}

	fmt.Printf("Canary scan (%d active):\n\n", len(active))

	for _, r := range results {
		var icon, detail string
		switch r.Status {
		case ScanOK:
			icon = "✓"
		case ScanModified:
			icon = "⚠"
			detail = r.Detail
		case ScanMissing:
			icon = "✗"
			detail = r.Detail
		}
		short := r.Canary.ID
		if len(short) > 32 {
			short = short[:32] + "..."
		}
		if detail != "" {
			fmt.Printf("  %s  %-12s  %s\n", icon, r.Canary.Type, r.Canary.Path)
			fmt.Printf("     %-12s  %s  — %s\n", "", short, detail)
		} else {
			fmt.Printf("  %s  %-12s  %s\n", icon, r.Canary.Type, r.Canary.Path)
			fmt.Printf("     %-12s  %s\n", "", short)
		}
		fmt.Println()
	}

	if len(orphans) > 0 {
		fmt.Printf("Orphaned canaries (%d found):\n\n", len(orphans))
		for _, o := range orphans {
			fmt.Printf("  ?  %s\n", o.Path)
			if o.URL != "" && o.URL != "(unknown)" {
				fmt.Printf("     %s\n", o.URL)
			}
			fmt.Println()
		}
	}

	// Summary line
	parts := []string{}
	if nOK > 0 {
		parts = append(parts, fmt.Sprintf("%d OK", nOK))
	}
	if nModified > 0 {
		parts = append(parts, fmt.Sprintf("%d modified", nModified))
	}
	if nMissing > 0 {
		parts = append(parts, fmt.Sprintf("%d missing", nMissing))
	}
	if len(orphans) > 0 {
		parts = append(parts, fmt.Sprintf("%d orphaned", len(orphans)))
	}
	fmt.Println("  " + strings.Join(parts, ", "))
	fmt.Println()

	if nModified > 0 {
		fmt.Println("  ⚠  MODIFIED canaries may have been tampered with.")
		fmt.Println("     Run `snare teardown --force && snare arm` to replant.")
	}
	if nMissing > 0 {
		fmt.Println("  ✗  MISSING canaries are no longer protecting this machine.")
		fmt.Println("     Run `snare arm` to replant.")
	}
	if len(orphans) > 0 {
		fmt.Println("  ?  ORPHANED canaries have no manifest record.")
		fmt.Println("     These may be from a previous install. Run `snare disarm --purge && snare arm` to clean up.")
	}

	// Exit non-zero if anything is wrong
	if nModified > 0 || nMissing > 0 || len(orphans) > 0 {
		os.Exit(1)
	}
}

// cmdStatus shows active canaries on this machine.
// Fetches last-seen timestamps from snare.sh API for each canary.
func cmdStatus(args []string) {
	m, err := manifest.Load()
	if err != nil {
		fatal(err)
	}

	active := m.Active()
	if len(active) == 0 {
		fmt.Println("No active canaries. Run `snare arm` to deploy.")
		return
	}

	// Load config to build API base URL
	cfg, _ := config.Load()
	var apiBase string
	if cfg != nil {
		apiBase = strings.TrimSuffix(cfg.CallbackBase, "/c")
	}

	// Fetch last-seen from API (best-effort, don't fail status on network error)
	lastSeenMap := make(map[string]string) // tokenID → timestamp
	eventCountMap := make(map[string]int)
	if apiBase != "" {
		for _, c := range active {
			evURL := apiBase + "/api/events/" + c.ID
			req, _ := http.NewRequest("GET", evURL, nil)
			if cfg.DeviceSecret != "" {
				req.Header.Set("Authorization", "Bearer "+cfg.DeviceSecret)
				req.Header.Set("X-Snare-Device-Id", cfg.DeviceID)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil || resp.StatusCode != 200 {
				if resp != nil {
					resp.Body.Close()
				}
				continue
			}
			var result struct {
				Events []struct {
					Timestamp string `json:"timestamp"`
					IsTest    bool   `json:"is_test"`
				} `json:"events"`
			}
			data, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err := json.Unmarshal(data, &result); err != nil {
				continue
			}
			// Find most recent non-test event
			for _, e := range result.Events {
				if !e.IsTest {
					lastSeenMap[c.ID] = e.Timestamp
					break
				}
			}
			// Count non-test events
			count := 0
			for _, e := range result.Events {
				if !e.IsTest {
					count++
				}
			}
			eventCountMap[c.ID] = count
		}
	}

	fmt.Printf("Active canaries (%d):\n\n", len(active))
	for _, c := range active {
		age := time.Since(c.PlantedAt).Round(time.Minute)
		if age < time.Minute {
			age = time.Second
		}
		label := c.Label
		if label == "" {
			label = "-"
		}
		lastSeen := "never"
		if ts, ok := lastSeenMap[c.ID]; ok {
			lastSeen = ts
		} else if c.LastSeen != nil {
			lastSeen = c.LastSeen.Format("2006-01-02 15:04 UTC")
		}
		alerts := ""
		if count, ok := eventCountMap[c.ID]; ok && count > 0 {
			alerts = fmt.Sprintf(" ⚠ %d alert(s)", count)
		}
		rel := reliability(c.Type)
		relMark := "●" // high
		if rel == "medium" {
			relMark = "◐"
		}
		fmt.Printf("  %s  %s\n", relMark, c.ID)
		fmt.Printf("    type:        %s (%s reliability)\n", c.Type, rel)
		fmt.Printf("    label:       %s\n", label)
		fmt.Printf("    path:        %s\n", c.Path)
		fmt.Printf("    planted:     %s ago\n", age)
		fmt.Printf("    last seen:   %s%s\n", lastSeen, alerts)
		fmt.Println()
	}
	fmt.Println("  ● high reliability  ◐ medium reliability")
	fmt.Println()
	fmt.Println("  Run `snare events` to fetch recent alert history.")
}

// cmdEvents fetches recent alert events from snare.sh for active canaries.
func cmdEvents(args []string) {
	cfg, err := requireConfig()
	if err != nil {
		fatal(err)
	}

	m, err := manifest.Load()
	if err != nil {
		fatal(err)
	}

	active := m.Active()
	if len(active) == 0 {
		fmt.Println("No active canaries.")
		return
	}

	// Build API base from callback base
	apiBase := strings.TrimSuffix(cfg.CallbackBase, "/c")

	fmt.Printf("Fetching events for %d canary(s)...\n\n", len(active))

	found := 0
	for _, c := range active {
		url := apiBase + "/api/events/" + c.ID
		resp, err := authedGet(url, cfg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", c.ID, err)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			fmt.Fprintf(os.Stderr, "  ✗ auth failed — run `snare init --force` to re-register\n")
			break
		}

		if resp.StatusCode == 404 {
			continue // no events for this token
		}

		var result struct {
			Events []struct {
				Timestamp string `json:"timestamp"`
				IP        string `json:"ip"`
				City      string `json:"city"`
				Country   string `json:"country"`
				AsnOrg    string `json:"asnOrg"`
				UserAgent string `json:"userAgent"`
				Method    string `json:"method"`
			} `json:"events"`
		}

		data, _ := io.ReadAll(resp.Body)
		if err := json.Unmarshal(data, &result); err != nil {
			continue
		}

		if len(result.Events) == 0 {
			continue
		}

		found++
		label := c.Label
		if label == "" {
			label = c.Type
		}
		fmt.Printf("  🪤 %s (%s)\n", c.ID, label)
		for _, e := range result.Events {
			loc := strings.Join(filterEmpty(e.City, e.Country), ", ")
			if loc == "" {
				loc = "unknown location"
			}
			ua := e.UserAgent
			if len(ua) > 80 {
				ua = ua[:80] + "..."
			}
			fmt.Printf("    %s  %s  %s  %s\n", e.Timestamp, e.IP, loc, e.Method)
			fmt.Printf("    UA: %s\n", ua)
			fmt.Println()
		}
	}

	if found == 0 {
		fmt.Println("  No events recorded yet. Canaries are active and waiting.")
		fmt.Println("  Run `snare test` to verify your alert pipeline.")
	}
}

func filterEmpty(ss ...string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// cmdTest fires a synthetic callback to verify the full alert pipeline.
// It registers the test token with snare.sh first so the worker knows where
// to deliver the alert, then fires the callback and waits briefly to confirm.
func cmdTest(args []string) {
	cfg, err := requireConfig()
	if err != nil {
		fatal(err)
	}

	// Derive a stable per-device test token
	shortID := cfg.DeviceID
	if len(shortID) > 8 {
		shortID = shortID[len(shortID)-8:]
	}
	testTokenID := "snare-test-" + shortID

	// Register the test token so the worker routes alerts to this device's webhook.
	// This is what actually proves the full pipeline works end-to-end.
	if err := registerToken(cfg, testTokenID, "test", "test"); err != nil {
		fmt.Fprintf(os.Stderr, "  ⚠  webhook registration failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "  The callback will still fire but your webhook may not receive the alert.\n\n")
	}

	callbackURL := cfg.CallbackURL(testTokenID)
	fmt.Printf("Firing test alert...\n  %s\n\n", callbackURL)

	err = httpGet(callbackURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
		fmt.Fprintf(os.Stderr, "  check your internet connection and snare.sh status\n")
		os.Exit(1)
	}

	fmt.Println("✓ Test alert fired — check your webhook destination.")
	fmt.Println("  If no alert arrives within 30 seconds, verify your webhook is configured correctly.")
}

// cmdTeardown removes planted canaries.
func cmdTeardown(args []string) {
	tokenID := flagValue(args, "--token")
	force := hasFlag(args, "--force")
	dryRun := hasFlag(args, "--dry-run")

	m, err := manifest.Load()
	if err != nil {
		fatal(err)
	}

	var targets []manifest.Canary

	if tokenID != "" {
		c := m.FindByID(tokenID)
		if c == nil {
			fatal(fmt.Errorf("canary %s not found in manifest", tokenID))
		}
		targets = []manifest.Canary{*c}
	} else {
		targets = m.Active()
		if len(targets) == 0 {
			fmt.Println("No active canaries to remove.")
			return
		}
	}

	if dryRun {
		fmt.Printf("[dry-run] would remove %d canary(s):\n\n", len(targets))
	} else {
		fmt.Printf("Removing %d canary(s)...\n\n", len(targets))
	}

	var failed []string
	for _, c := range targets {
		if err := bait.Remove(c, force, dryRun); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", c.ID, err)
			failed = append(failed, c.ID)
			continue
		}
		if !dryRun {
			if err := m.Deactivate(c.ID, "teardown"); err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠️  removed from disk but manifest update failed for %s: %v\n", c.ID, err)
			}
			// Best-effort webhook deregistration — auth uses device secret, not webhook URL
			if cfg, err := config.Load(); err == nil && cfg != nil {
				_ = revokeToken(cfg, c.ID)
			}
		}
	}

	if len(failed) > 0 {
		fmt.Fprintf(os.Stderr, "\n%d canary(s) failed to remove. Use --force to skip safety checks.\n", len(failed))
		os.Exit(1)
	}

	if !dryRun {
		fmt.Printf("\n✓ Done. Run `snare status` to confirm.\n")
	}
}

// cmdUninstall completely removes snare: disarm + purge config + remove binary.
// Does NOT require a separate disarm step — handles everything.
// Does NOT corrupt files we appended to — uses the same content-matching removal.
func cmdUninstall(args []string) {
	dryRun := hasFlag(args, "--dry-run")
	yes := hasFlag(args, "--yes") || hasFlag(args, "-y")

	if !dryRun && !yes {
		fmt.Println("  This will:")
		fmt.Println("    1. Remove all planted canaries (safely, without corrupting your files)")
		fmt.Println("    2. Delete ~/.snare/ (config + manifest)")
		fmt.Println("    3. Remove the snare binary")
		fmt.Println()
		fmt.Print("  Continue? [y/N] ")
		var resp string
		fmt.Scanln(&resp)
		if strings.ToLower(strings.TrimSpace(resp)) != "y" {
			fmt.Println("  Aborted.")
			return
		}
	}

	// Step 1: Disarm all canaries (force mode, skip confirmation)
	m, err := manifest.Load()
	if err != nil && !dryRun {
		// Manifest might be corrupt — continue with purge
		fmt.Fprintf(os.Stderr, "  ⚠  manifest load failed: %v (continuing with cleanup)\n", err)
	}

	if m != nil {
		active := m.Active()
		if len(active) > 0 {
			if dryRun {
				fmt.Printf("  [dry-run] would remove %d canary(s):\n", len(active))
				for _, c := range active {
					fmt.Printf("    %-12s %s\n", c.Type, c.Path)
				}
			} else {
				fmt.Printf("  Removing %d canaries...\n", len(active))
				forceRemove := hasFlag(args, "--force")
				for _, c := range active {
					if err := bait.Remove(c, forceRemove, false); err != nil {
						if strings.Contains(err.Error(), "content has changed") {
							fmt.Fprintf(os.Stderr, "    ⚠  %-12s %s: content changed since planting — skipping (use --force to override)\n", c.Type, c.Path)
						} else {
							fmt.Fprintf(os.Stderr, "    ✗  %-12s %s: %v\n", c.Type, c.Path, err)
						}
						continue
					}
					_ = m.Deactivate(c.ID, "uninstall")
					// Deregister webhook (best-effort)
					if cfg, loadErr := config.Load(); loadErr == nil && cfg != nil {
						_ = revokeToken(cfg, c.ID)
					}
					fmt.Printf("    ✓ %-12s %s\n", c.Type, c.Path)
				}
			}
		} else {
			fmt.Println("  No active canaries to remove.")
		}
	}

	// Step 2: Remove ~/.snare/
	dir, err := manifest.Dir()
	if err != nil {
		fatal(err)
	}
	if dryRun {
		fmt.Printf("  [dry-run] would delete %s\n", dir)
	} else {
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠  could not remove %s: %v\n", dir, err)
		} else {
			fmt.Printf("  ✓ %s removed\n", dir)
		}
	}

	// Step 3: Remove the binary itself
	binPath, _ := os.Executable()
	if binPath != "" {
		if dryRun {
			fmt.Printf("  [dry-run] would delete %s\n", binPath)
		} else {
			if err := os.Remove(binPath); err != nil {
				fmt.Fprintf(os.Stderr, "  ⚠  could not remove binary %s: %v\n", binPath, err)
			} else {
				fmt.Printf("  ✓ %s removed\n", binPath)
			}
		}
	}

	if !dryRun {
		fmt.Println()
		fmt.Println("  ✓ snare completely uninstalled. No traces left.")
	}
}

// cmdServe starts the self-hosted snare HTTP server.
func cmdServe(args []string) {
	portStr    := flagValue(args, "--port")
	dbPath     := flagValue(args, "--db")
	tlsDomain  := flagValue(args, "--tls-domain")
	webhookURL := flagValue(args, "--webhook-url")
	dashToken  := flagValue(args, "--dashboard-token")

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

// buildParams generates all template parameters for a canary.
func buildParams(bt bait.Type, label string, cfg *config.Config) (bait.Params, error) {
	tokenID, err := token.NewID(label)
	if err != nil {
		return bait.Params{}, err
	}

	callbackURL := cfg.CallbackURL(tokenID)
	callbackNoProto := strings.TrimPrefix(callbackURL, "https://")
	callbackNoProto = strings.TrimPrefix(callbackNoProto, "http://")

	p := bait.Params{
		TokenID:            tokenID,
		CallbackURL:        callbackURL,
		CallbackURLNoProto: callbackNoProto,
		Label:              label,
	}

	switch bt {
	case bait.TypeAWS:
		p.FakeKeyID, err = token.NewAWSKeyID()
		if err != nil {
			return p, err
		}
		p.FakeSecret, err = token.NewAWSSecretKey()
		if err != nil {
			return p, err
		}
		p.ProfileName = token.NewProfileName(label)

	case bait.TypeGCP:
		p.FakeProjID = token.NewGCPProjectID()
		p.FakeKeyID, err = token.NewGCPPrivateKeyID()
		if err != nil {
			return p, err
		}
		p.FakeSecret = token.NewGCPClientID()
		p.FakePrivateKey, err = token.NewFakeRSAPrivateKey()
		if err != nil {
			return p, err
		}

	case bait.TypeStripe:
		p.FakeToken, err = token.NewStripeKey()
		if err != nil {
			return p, err
		}
		// test_mode_api_key needs a short alphanumeric suffix
		keyID, err2 := token.NewGCPPrivateKeyID()
		if err2 != nil {
			return p, err2
		}
		p.FakeKeyID = keyID[:24] // 24 hex chars
		p.ProfileName = token.NewProfileName(label)

	case bait.TypeGitHub:
		p.FakeToken, err = token.NewGitHubToken()
		if err != nil {
			return p, err
		}
		// ProfileName used as the fake GitHub Enterprise hostname component
		// e.g. git.acme-internal.io — use label or generate a plausible corp name
		if label != "" {
			p.ProfileName = label + "-internal"
		} else {
			p.ProfileName = "corp-internal"
		}

	case bait.TypeOpenAI:
		p.FakeToken, err = token.NewOpenAIKey()
		if err != nil {
			return p, err
		}

	case bait.TypeAnthropic:
		p.FakeToken, err = token.NewAnthropicKey()
		if err != nil {
			return p, err
		}

	case bait.TypePyPI:
		// ProfileName is the fake package scope/org
		scopes := []string{"internal", "corp", "platform", "infra", "data", "ml"}
		sc := scopes[token.MustRandInt(len(scopes))]
		if label != "" {
			p.ProfileName = label + "-" + sc
		} else {
			p.ProfileName = sc + "-packages"
		}

	case bait.TypeAWSProc:
		// Two-profile pattern: visible assume-role + hidden credential_process source
		p.FakeKeyID, err = token.NewAWSKeyID()
		if err != nil {
			return p, err
		}
		// FakeToken used as the SecretAccessKey in credential_process output
		p.FakeSecret = token.NewGCPClientID() // 12-digit account ID for role_arn
		p.FakeToken, err = token.NewAWSSecretKey()
		if err != nil {
			return p, err
		}
		// Profile name for the visible assume-role profile
		envs := []string{"prod", "staging", "infra", "platform", "data"}
		roles := []string{"admin", "deploy", "readonly", "power-user"}
		e := envs[token.MustRandInt(len(envs))]
		r := roles[token.MustRandInt(len(roles))]
		if label != "" {
			p.ProfileName = label + "-" + e + "-" + r
		} else {
			p.ProfileName = e + "-" + r
		}

	case bait.TypeMCP:
		// ProfileName used as the org/team prefix for fake MCP server names
		orgs := []string{"platform", "infra", "backend", "data", "core", "internal"}
		o := orgs[token.MustRandInt(len(orgs))]
		if label != "" {
			p.ProfileName = label + "-" + o
		} else {
			p.ProfileName = o
		}
		p.FakeToken, err = token.NewGitHubToken() // JWT-like token for DB_TOKEN
		if err != nil {
			return p, err
		}
		p.FakeSecret = token.NewGCPClientID() // numeric for VAULT_TOKEN

	case bait.TypeSSH:
		// ProfileName is the fake hostname — looks like a bastion/jump box
		hosts := []string{"bastion", "jump", "gateway", "relay", "vpn"}
		envs := []string{"prod", "staging", "internal", "legacy", "corp"}
		h := hosts[token.MustRandInt(len(hosts))]
		e := envs[token.MustRandInt(len(envs))]
		if label != "" {
			p.ProfileName = h + "-" + label + "-" + e
		} else {
			p.ProfileName = h + "-" + e
		}

	case bait.TypeK8s:
		// ProfileName is the fake cluster name
		clusters := []string{"staging", "prod-us", "prod-eu", "dev", "infra", "platform"}
		suffixes := []string{"deploy", "legacy", "backup", "readonly", "migrate"}
		c := clusters[token.MustRandInt(len(clusters))]
		s := suffixes[token.MustRandInt(len(suffixes))]
		if label != "" {
			p.ProfileName = c + "-" + label + "-" + s
		} else {
			p.ProfileName = c + "-" + s
		}
		// Fake k8s service account token (looks like a JWT)
		p.FakeToken, err = token.NewK8sToken()
		if err != nil {
			return p, err
		}

	case bait.TypeNPM:
		// ProfileName is the npm scope (without @)
		scopes := []string{"internal", "corp", "platform", "infra", "backend", "core"}
		sc := scopes[token.MustRandInt(len(scopes))]
		if label != "" {
			p.ProfileName = label + "-" + sc
		} else {
			p.ProfileName = sc + "-pkg"
		}
		p.FakeToken, err = token.NewNPMToken()
		if err != nil {
			return p, err
		}

	case bait.TypeGeneric:
		p.FakeToken, err = token.NewGitHubToken() // reuse format
		if err != nil {
			return p, err
		}
		p.ProfileName = label

	case bait.TypeHuggingFace:
		p.FakeToken, err = token.NewHuggingFaceToken()
		if err != nil {
			return p, err
		}
		// ProfileName used as a comment label in the .env.hf file
		if label != "" {
			p.ProfileName = label + "-hf"
		} else {
			p.ProfileName = "ml-team"
		}

	case bait.TypeDocker:
		p.FakeRegistry = token.NewDockerRegistryName()
		// FakeToken used as a base64-encoded "auth" value (username:password)
		// Docker stores base64(user:pass) in the auths section
		rawToken, err2 := token.NewNPMToken() // reuse a random token format
		if err2 != nil {
			return p, err2
		}
		p.FakeToken = rawToken
		p.ProfileName = label

	case bait.TypeAzure:
		// FakeKeyID = client ID (UUID)
		p.FakeKeyID, err = token.NewAzureClientID()
		if err != nil {
			return p, err
		}
		// FakeTenantID = tenant ID (UUID)
		p.FakeTenantID, err = token.NewAzureClientID()
		if err != nil {
			return p, err
		}
		// FakeSecret = client secret
		p.FakeSecret, err = token.NewAzureClientSecret()
		if err != nil {
			return p, err
		}
		// FakeProjID = subscription ID (UUID, reusing GCPClientID format for numeric look
		// — actually Azure subscription IDs are UUIDs, so generate one)
		p.FakeProjID, err = token.NewAzureClientID()
		if err != nil {
			return p, err
		}
		// ProfileName is a friendly name for the subscription
		envs := []string{"prod", "staging", "dev", "platform", "infra"}
		e := envs[token.MustRandInt(len(envs))]
		if label != "" {
			p.ProfileName = label + "-" + e
		} else {
			p.ProfileName = e
		}
	}

	return p, nil
}

// requireConfig loads config and gives a helpful error if not initialized.
func requireConfig() (*config.Config, error) {
	cfg, err := config.Load()
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("snare not initialized — run `snare init` first")
	}
	return cfg, nil
}

// authedPost sends a POST with Authorization: Bearer <device_secret>.
func authedGet(url string, cfg *config.Config) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if cfg != nil && cfg.DeviceSecret != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.DeviceSecret)
		req.Header.Set("X-Snare-Device-Id", cfg.DeviceID)
	}
	return http.DefaultClient.Do(req)
}

func authedPost(url string, payload interface{}, cfg *config.Config) (*http.Response, error) {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.DeviceSecret != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.DeviceSecret)
	}
	return http.DefaultClient.Do(req)
}

// registerToken registers a per-token webhook with snare.sh.
func registerToken(cfg *config.Config, tokenID, canaryType, label string) error {
	webhookURL := cfg.WebhookURL
	if webhookURL == "" {
		// No local webhook — register with sentinel to bind ownership for events auth
		webhookURL = "use-global"
	}
	resp, err := authedPost(cfg.RegisterURL(), map[string]string{
		"token_id":    tokenID,
		"webhook_url": webhookURL,
		"device_id":   cfg.DeviceID,
		"canary_type": canaryType,
		"label":       label,
	}, cfg)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		// Try to extract error message from JSON response
		var errResp struct{ Error string `json:"error"` }
		if json.Unmarshal(body, &errResp) == nil && errResp.Error != "" {
			return fmt.Errorf("registration failed: %s", errResp.Error)
		}
		return fmt.Errorf("registration failed: HTTP %d", resp.StatusCode)
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	return nil
}

// revokeToken deregisters a token webhook from snare.sh.
func revokeToken(cfg *config.Config, tokenID string) error {
	resp, err := authedPost(cfg.RevokeURL(), map[string]string{
		"token_id":  tokenID,
		"device_id": cfg.DeviceID,
	}, cfg)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	return nil
}

// httpGet fires a GET request to url using net/http.
func httpGet(url string) error {
	resp, err := http.Get(url) //nolint:noctx
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// Flag helpers

func hasFlag(args []string, flag string) bool {
	for _, a := range args {
		if a == flag {
			return true
		}
	}
	return false
}

func flagValue(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
