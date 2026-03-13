// Package cli implements the snare command-line interface.
package cli

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/peg/snare/internal/bait"
	"github.com/peg/snare/internal/config"
	"github.com/peg/snare/internal/manifest"
	"github.com/peg/snare/internal/token"
)

// reliability returns a human-readable reliability label per canary type.
func reliability(t string) string {
	switch bait.Type(t) {
	case bait.TypeAWS, bait.TypeGCP, bait.TypeOpenAI, bait.TypeAnthropic,
		bait.TypeSSH, bait.TypeK8s, bait.TypeNPM, bait.TypeMCP,
		bait.TypePyPI, bait.TypeAWSProc:
		return "high"
	default:
		return "medium"
	}
}

const usage = `snare — compromise detection for AI agents via deception

Quick start:
  snare arm --webhook <url>    arm this machine (init + plant all + test)
  snare disarm                 remove all canaries and clean up
  snare status                 show active canaries

Commands:
  snare arm [flags]            one-command setup: init + plant + test
  snare disarm [flags]         one-command teardown
  snare status                 show active canaries
  snare events                 fetch recent alert events from snare.sh
  snare test                   fire a test alert to verify your webhook

Advanced:
  snare init                   initialize snare on this machine
  snare plant [flags]          plant individual canary credentials
  snare teardown [flags]       remove specific canaries
  snare uninstall              teardown + remove all snare state

Flags (arm):
  --webhook <url>              webhook URL (Discord, Slack, Telegram, or custom)
  --label <name>               prefix canary names (defaults to hostname)
  --dry-run                    show what would be planted without writing

Flags (plant):
  --label <name>               prefix canary names (defaults to hostname)
  --type <type>                canary type: aws, awsproc, gcp, github, stripe, openai, anthropic, ssh, k8s, npm, mcp, pypi, generic
  --all                        plant all high-reliability canary types at once
  --dry-run                    show what would be planted without writing anything

Flags (disarm/teardown):
  --token <id>                 remove a single canary by ID
  --force                      remove even if content hash mismatches
  --purge                      also remove ~/.snare/ config directory
  --dry-run                    show what would be removed without writing anything
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
	case "init":
		cmdInit(rest)
	case "plant":
		cmdPlant(rest)
	case "status":
		cmdStatus(rest)
	case "events":
		cmdEvents(rest)
	case "test":
		cmdTest(rest)
	case "teardown":
		cmdTeardown(rest)
	case "uninstall":
		cmdUninstall(rest)
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
func cmdArm(args []string) {
	webhookURL := flagValue(args, "--webhook")
	label := flagValue(args, "--label")
	dryRun := hasFlag(args, "--dry-run")

	if label == "" {
		if h, err := os.Hostname(); err == nil {
			label = strings.ToLower(strings.ReplaceAll(h, ".", "-"))
		} else {
			label = "snare"
		}
	}

	// Step 1: Initialize (or reuse existing config)
	cfg, err := config.Load()
	if err != nil {
		fatal(err)
	}

	if cfg == nil {
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

	planted := 0
	skipped := 0
	for _, bt := range highReliabilityTypes {
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

			// Register webhook (best-effort)
			if cfg.WebhookURL != "" {
				_ = registerToken(cfg, params.TokenID, string(bt), label)
			}

			fmt.Printf("    ✓ %-12s %s\n", bt, path)
			planted++
		}
	}

	if dryRun {
		fmt.Printf("\n  [dry-run] would plant %d canaries\n", planted)
		return
	}

	// Step 3: Test webhook
	fmt.Println()
	if cfg.WebhookURL != "" {
		shortID := cfg.DeviceID
		if len(shortID) > 8 {
			shortID = shortID[len(shortID)-8:]
		}
		testToken := "snare-test-" + shortID
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
			if err := bait.Remove(c, force || true, false); err != nil {
				// force during disarm — we want clean removal
				fmt.Fprintf(os.Stderr, "    ✗ %-12s %s: %v\n", c.Type, c.Path, err)
				continue
			}
			_ = m.Deactivate(c.ID, "disarm")

			// Deregister webhook (best-effort)
			if cfg, err := config.Load(); err == nil && cfg != nil && cfg.WebhookURL != "" {
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
		if scanner.Scan() {
			webhookURL = strings.TrimSpace(scanner.Text())
		}
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

// highReliabilityTypes returns all high-reliability canary types.
var highReliabilityTypes = []bait.Type{
	bait.TypeAWS, bait.TypeGCP, bait.TypeOpenAI, bait.TypeAnthropic,
	bait.TypeSSH, bait.TypeK8s, bait.TypeNPM, bait.TypeMCP,
	bait.TypePyPI, bait.TypeAWSProc,
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

		// Step 5: register webhook with snare.sh (best-effort — don't fail plant on network error)
		if cfg.WebhookURL != "" && !dryRun {
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

// cmdStatus shows active canaries on this machine.
func cmdStatus(args []string) {
	m, err := manifest.Load()
	if err != nil {
		fatal(err)
	}

	active := m.Active()
	if len(active) == 0 {
		fmt.Println("No active canaries. Run `snare plant` to deploy.")
		return
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
		if c.LastSeen != nil {
			lastSeen = c.LastSeen.Format("2006-01-02 15:04 UTC")
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
		fmt.Printf("    last seen:   %s\n", lastSeen)
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
		resp, err := http.Get(url) //nolint:noctx
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %s: %v\n", c.ID, err)
			continue
		}
		defer resp.Body.Close()

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

// cmdTest fires a synthetic callback to verify the alert pipeline.
func cmdTest(args []string) {
	cfg, err := requireConfig()
	if err != nil {
		fatal(err)
	}

	// Use last 8 chars of device ID to keep token compact in alerts
	shortID := cfg.DeviceID
	if len(shortID) > 8 {
		shortID = shortID[len(shortID)-8:]
	}
	testTokenID := "snare-test-" + shortID
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
			// Best-effort webhook deregistration — ignore errors
			if cfg, err := config.Load(); err == nil && cfg != nil && cfg.WebhookURL != "" {
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

// cmdUninstall removes all canaries then wipes ~/.snare.
func cmdUninstall(args []string) {
	dryRun := hasFlag(args, "--dry-run")

	fmt.Println("This will remove all planted canaries and delete ~/.snare entirely.")
	if !dryRun {
		fmt.Print("Continue? [y/N] ")
		var resp string
		fmt.Scanln(&resp)
		if strings.ToLower(strings.TrimSpace(resp)) != "y" {
			fmt.Println("Aborted.")
			return
		}
	}

	// Teardown all active canaries — always force since we're uninstalling
	if dryRun {
		cmdTeardown([]string{"--dry-run"})
		fmt.Println("[dry-run] would delete ~/.snare/")
		return
	}
	cmdTeardown([]string{"--force"})

	dir, err := manifest.Dir()
	if err != nil {
		fatal(err)
	}

	if err := os.RemoveAll(dir); err != nil {
		fatal(fmt.Errorf("removing ~/.snare: %w", err))
	}

	fmt.Println("✓ snare uninstalled. ~/.snare removed.")
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

// registerToken registers a per-token webhook with snare.sh.
func registerToken(cfg *config.Config, tokenID, canaryType, label string) error {
	body, _ := json.Marshal(map[string]string{
		"token_id":     tokenID,
		"webhook_url":  cfg.WebhookURL,
		"device_id":    cfg.DeviceID,
		"canary_type":  canaryType,
		"label":        label,
	})
	resp, err := http.Post(cfg.RegisterURL(), "application/json", bytes.NewReader(body)) //nolint:noctx
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	if resp.StatusCode >= 400 {
		return fmt.Errorf("registration failed: HTTP %d", resp.StatusCode)
	}
	return nil
}

// revokeToken deregisters a token webhook from snare.sh.
func revokeToken(cfg *config.Config, tokenID string) error {
	body, _ := json.Marshal(map[string]string{"token_id": tokenID})
	resp, err := http.Post(cfg.RevokeURL(), "application/json", bytes.NewReader(body)) //nolint:noctx
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
