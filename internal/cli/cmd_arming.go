package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/peg/snare/internal/bait"
	"github.com/peg/snare/internal/config"
	"github.com/peg/snare/internal/manifest"
)

// cmdArm is the one-command setup: init + plant all + test.
// This is the happy path for new machines.
// precisionTypes are the highest-signal canaries: near-zero false positives,
// fire only on active credential use or resolution. For environments where
// you want maximum signal-to-noise ratio.
var precisionTypes = []bait.Type{
	bait.TypeAWSProc, // fires at credential resolution — before any API call
	bait.TypeSSH,     // fires on SSH connection attempt via ProxyCommand
	bait.TypeK8s,     // fires on any kubectl/SDK call to fake cluster
	// TypeGit excluded: credential.helper requires HTTP 401 from the fake host,
	// but the fake hostname has no DNS record so git errors at DNS resolution
	// before ever asking for credentials. Medium-high reliability at best.
	// TypeAzure excluded: service-principal-credentials.json not in standard
	// Azure SDK credential chain — requires agent to explicitly hunt the file.
}

// selectEntry describes one row in the --select TUI.
type selectEntry struct {
	t    bait.Type
	tier string // "precision", "high", "medium"
	path string // short description of where it plants
}

// allSelectEntries is the canonical ordered list for --select mode.
var allSelectEntries = []selectEntry{
	// Precision: fire via SDK/OS hooks, no DNS dependency, near-zero false positives
	{bait.TypeAWSProc, "precision", "~/.aws/config (credential_process)"},
	{bait.TypeSSH, "precision", "~/.ssh/config (ProxyCommand)"},
	{bait.TypeK8s, "precision", "~/.kube/<name>.yaml (server URL)"},
	// High: fires on active use, agent must find+use the credential
	{bait.TypeAWS, "high", "~/.aws/credentials (endpoint_url)"},
	{bait.TypeGCP, "high", "~/.config/gcloud/sa-*.json (token_uri)"},
	{bait.TypeNPM, "high", "~/.npmrc (scoped registry)"},
	{bait.TypeGit, "high", "~/.gitconfig (credential.helper)"},
	{bait.TypePyPI, "high", "~/.config/pip/pip.conf (extra-index-url) ⚠ side effect"},
	// Medium: dotenv-dependent, DNS-dependent, or needs explicit credential scanning
	{bait.TypeAzure, "medium", "~/.azure/service-principal-credentials.json"},
	{bait.TypeOpenAI, "medium", "~/.env (OPENAI_BASE_URL)"},
	{bait.TypeAnthropic, "medium", "~/.env.local (ANTHROPIC_BASE_URL)"},
	{bait.TypeMCP, "medium", "~/.config/mcp-servers*.json"},
	{bait.TypeGitHub, "medium", "~/.config/gh/hosts.yml"},
	{bait.TypeStripe, "medium", "~/.config/stripe/config.toml"},
	{bait.TypeHuggingFace, "medium", "~/.env.hf (HF_ENDPOINT)"},
	{bait.TypeDocker, "medium", "~/.docker/config.json"},
	{bait.TypeTerraform, "medium", "~/.terraformrc (network_mirror)"},
	{bait.TypeGeneric, "medium", "~/.env.production (API_BASE_URL)"},
}

// runSelectTUI shows an interactive checklist and returns the chosen types.
// Precision types are pre-checked. Space toggles, Enter confirms, q/Ctrl-C aborts.
func runSelectTUI() ([]bait.Type, error) {
	// Check for TTY — can't run interactive mode without one
	fi, err := os.Stdin.Stat()
	if err != nil || (fi.Mode()&os.ModeCharDevice) == 0 {
		return nil, fmt.Errorf("--select requires an interactive terminal")
	}

	// Build checked state: precision = on by default
	checked := make([]bool, len(allSelectEntries))
	for i, e := range allSelectEntries {
		checked[i] = e.tier == "precision"
	}

	cursor := 0
	tierColors := map[string]string{
		"precision": "\033[33m", // amber
		"high":      "\033[32m", // green
		"medium":    "\033[36m", // cyan
	}
	reset := "\033[0m"
	bold := "\033[1m"
	dim := "\033[2m"

	// Put terminal in raw mode
	oldState, err := makeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return nil, fmt.Errorf("setting raw mode: %w", err)
	}
	defer restoreTerminal(int(os.Stdin.Fd()), oldState)

	clearLines := func(n int) {
		for i := 0; i < n; i++ {
			fmt.Print("\033[A\033[2K") // up one line, clear it
		}
	}

	render := func() {
		fmt.Println()
		fmt.Printf("  %sSelect canaries to arm%s  %sSpace toggle · Enter confirm · q abort%s\n\n",
			bold, reset, dim, reset)
		lastTier := ""
		for i, e := range allSelectEntries {
			if e.tier != lastTier {
				lastTier = e.tier
				color := tierColors[e.tier]
				fmt.Printf("  %s%s%s\n", color, strings.ToUpper(e.tier), reset)
			}
			check := "○"
			if checked[i] {
				check = "✓"
			}
			pointer := "  "
			if i == cursor {
				pointer = "\033[7m→\033[27m "
			}
			fmt.Printf("  %s %s %-12s  %s%s%s\n",
				pointer, check, e.t, dim, e.path, reset)
		}
		fmt.Println()
	}

	// Count lines rendered so we can redraw in-place
	// header(3) + tier headers + entries + footer(1)
	countLines := func() int {
		tiers := map[string]bool{}
		for _, e := range allSelectEntries {
			tiers[e.tier] = true
		}
		return 3 + len(tiers) + len(allSelectEntries) + 1
	}

	render()
	buf := make([]byte, 4)

	for {
		n, err := os.Stdin.Read(buf)
		if err != nil {
			break
		}
		b := buf[:n]

		clearLines(countLines())

		switch {
		case n == 1 && b[0] == ' ':
			checked[cursor] = !checked[cursor]
		case n == 1 && (b[0] == '\r' || b[0] == '\n'):
			// confirm
			restoreTerminal(int(os.Stdin.Fd()), oldState)
			fmt.Println()
			var selected []bait.Type
			for i, e := range allSelectEntries {
				if checked[i] {
					selected = append(selected, e.t)
				}
			}
			if len(selected) == 0 {
				return nil, fmt.Errorf("no canaries selected")
			}
			return selected, nil
		case n == 1 && (b[0] == 'q' || b[0] == 3): // q or Ctrl-C
			restoreTerminal(int(os.Stdin.Fd()), oldState)
			fmt.Println()
			return nil, fmt.Errorf("aborted")
		case n == 3 && b[0] == 27 && b[1] == '[' && b[2] == 'A': // up arrow
			if cursor > 0 {
				cursor--
			}
		case n == 3 && b[0] == 27 && b[1] == '[' && b[2] == 'B': // down arrow
			if cursor < len(allSelectEntries)-1 {
				cursor++
			}
		case n == 1 && b[0] == 'j': // vim down
			if cursor < len(allSelectEntries)-1 {
				cursor++
			}
		case n == 1 && b[0] == 'k': // vim up
			if cursor > 0 {
				cursor--
			}
		case n == 1 && b[0] == 'a': // select all
			for i := range checked {
				checked[i] = true
			}
		case n == 1 && b[0] == 'n': // select none
			for i := range checked {
				checked[i] = false
			}
		case n == 1 && b[0] == 'p': // select precision only
			for i, e := range allSelectEntries {
				checked[i] = e.tier == "precision"
			}
		}

		render()
	}

	return nil, fmt.Errorf("interrupted")
}

func cmdArm(args []string) {
	if hasFlag(args, "--help") || hasFlag(args, "-h") {
		fmt.Print(`snare arm — initialize snare and plant canaries (precision mode by default)

Usage:
  snare arm [flags]

By default, snare arm plants only the highest-signal canaries (awsproc, ssh, k8s).
These fire only on active credential use — near-zero false-positive risk.
Running AI agents on this machine? Precision mode stays quiet during normal work
unless the planted fake AWS profile, SSH host, or kube context is actively used.
Use --all to arm every canary type, or --select to pick interactively.

Flags:
  --webhook <url>    webhook URL (Discord, Slack, Telegram, or custom JSON endpoint)
  --label <name>     name your canary (e.g. prod-admin-legacy-2024) — defaults to hostname
  --all              plant all canary types including dotenv-based ones
  --select           interactive checklist to pick which canaries to arm
  --dry-run          show what would be planted without writing anything
  --help             show this help

Examples:
  snare arm --webhook https://discord.com/api/webhooks/...
  snare arm --webhook https://hooks.slack.com/... --label prod-admin-legacy-2024
  snare arm --all --webhook <url>
  snare arm --select --webhook <url>

Naming tip:
  Use --label to make canaries look like real dormant infrastructure credentials.
  A name like "prod-admin-legacy-2024" looks plausible to a compromised agent
  and is something you'd never invoke yourself — maximizing signal quality.
`)
		return
	}

	webhookURL := flagValue(args, "--webhook")
	label := flagValue(args, "--label")
	dryRun := hasFlag(args, "--dry-run")
	armAll := hasFlag(args, "--all")
	armSelect := hasFlag(args, "--select")

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

	// Step 2: Plant selected canaries
	m, err := manifest.Load()
	if err != nil {
		fatal(err)
	}

	fmt.Println()
	fmt.Println("  Planting canaries...")

	armTypes := precisionTypes
	armMode := "precision"
	switch {
	case armSelect:
		selected, err := runSelectTUI()
		if err != nil {
			fatal(err)
		}
		armTypes = selected
		names := make([]string, len(selected))
		for i, t := range selected {
			names[i] = string(t)
		}
		armMode = "custom"
		fmt.Printf("  Custom mode: planting %s\n", strings.Join(names, ", "))
	case armAll:
		armTypes = allCanaryTypes
		armMode = "full"
		fmt.Println("  Full mode: planting all 18 canary types (including dotenv-based)")
	default:
		fmt.Println("  Precision mode: planting active-use canaries only (awsproc, ssh, k8s)")
		fmt.Println("  These stay quiet unless the fake AWS profile, SSH host, or kube context is used.")
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
		fmt.Println("  [dry-run] no files were written and no webhook test was fired.")
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
	}
	fmt.Println()
	if armMode == "precision" {
		fmt.Println("  Precision mode is safe for first run: alerts require active use of the fake")
		fmt.Println("  AWS profile, SSH host, or kube context. Passive file reads do not fire them.")
	} else {
		fmt.Println("  Canaries are now waiting for a real hit. No event is recorded until bait is used.")
	}
	fmt.Println()
	fmt.Println("  Next checks:")
	fmt.Println("    snare status   show event state; `never fired` is normal at first")
	fmt.Println("    snare scan     verify planted files are present and unchanged")
	fmt.Println("    snare doctor   check config, callback health, and canary files")
	fmt.Println("    snare events   view real hits when one arrives")
	fmt.Println("  Run `snare disarm` to remove everything.")
}
