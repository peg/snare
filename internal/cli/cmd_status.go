package cli

import (
	"bufio"
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
)

// cmdDisarm removes all canaries. Clean, fast, one command.
func cmdDisarm(args []string) {
	dryRun := hasFlag(args, "--dry-run")
	purge := hasFlag(args, "--purge")
	force := hasFlag(args, "--force")
	tokenID := flagValue(args, "--token")
	typeFilter := flagValue(args, "--type")

	if tokenID != "" && typeFilter != "" {
		fatal(fmt.Errorf("use either --token or --type, not both"))
	}
	if typeFilter != "" && !isKnownCanaryType(typeFilter) {
		fatal(fmt.Errorf("unknown canary type %q", typeFilter))
	}

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
		} else if typeFilter != "" {
			for _, c := range m.Active() {
				if c.Type == typeFilter {
					targets = append(targets, c)
				}
			}
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

// cmdRotate generates a new device secret and re-registers all active tokens.
// Use this if your device secret was leaked (e.g., ~/.snare/config.json exposed).
func cmdRotate(args []string) {
	cfg, err := config.Load()
	if err != nil || cfg == nil {
		fatal(fmt.Errorf("snare not initialized — run `snare arm` first"))
	}

	fmt.Println("  Rotating device secret...")
	fmt.Printf("  Old secret: %s...%s\n", cfg.DeviceSecret[:4], cfg.DeviceSecret[len(cfg.DeviceSecret)-4:])
	oldSecret := cfg.DeviceSecret

	// Generate new secret
	newSecret, err := config.NewDeviceSecret()
	if err != nil {
		fatal(fmt.Errorf("generating new secret: %w", err))
	}

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
	rotateResp, err := rotateDeviceSecretOnServer(cfg, oldSecret, newSecret)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  ✗ server rotation failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "  Local config unchanged — old secret still active.\n")
		return
	}
	defer rotateResp.Body.Close()
	if rotateResp.StatusCode != 200 {
		body, _ := io.ReadAll(rotateResp.Body)
		fmt.Fprintf(os.Stderr, "  ✗ server rotation failed (HTTP %d): %s\n", rotateResp.StatusCode, strings.TrimSpace(string(body)))
		fmt.Fprintf(os.Stderr, "  Local config unchanged — old secret still active.\n")
		return
	}
	fmt.Println("  ✓ Server secret hash updated")

	// Update local config only after the server accepted the new secret.
	cfg.DeviceSecret = newSecret
	if err := cfg.Save(); err != nil {
		fatal(fmt.Errorf("saving config: %w", err))
	}
	fmt.Println("  ✓ New secret saved to ~/.snare/config.json")

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

func rotateDeviceSecretOnServer(cfg *config.Config, oldSecret, newSecret string) (*http.Response, error) {
	rotateCfg := *cfg
	rotateCfg.DeviceSecret = oldSecret
	return authedPost(cfg.RotateURL(), map[string]string{
		"device_id":  cfg.DeviceID,
		"new_secret": newSecret,
	}, &rotateCfg)
}

// cmdInit sets up snare for this machine.
// With --webhook: non-interactive. Without: guided setup.
func cmdInit(args []string) {
	force := hasFlag(args, "--force")
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

type canaryEventState struct {
	available bool
	lastSeen  string
	count     int
}

// cmdStatus shows active canaries on this machine.
// Fetches real, non-test event timestamps from snare.sh API for each canary.
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
		apiBase = cfg.APIBase()
	}

	// Fetch last event from API (best-effort, don't fail status on network error).
	// A 404 with an empty events array means "registered, but no events yet".
	eventStates := make(map[string]canaryEventState)
	if apiBase != "" {
		for _, c := range active {
			state := canaryEventState{}
			evURL := apiBase + "/api/events/" + c.ID
			req, _ := http.NewRequest("GET", evURL, nil)
			if cfg.DeviceSecret != "" {
				req.Header.Set("Authorization", "Bearer "+cfg.DeviceSecret)
				req.Header.Set("X-Snare-Device-Id", cfg.DeviceID)
			}
			resp, err := httpClient.Do(req)
			if err != nil {
				eventStates[c.ID] = state
				continue
			}
			if resp.StatusCode != 200 && resp.StatusCode != 404 {
				if resp != nil {
					resp.Body.Close()
				}
				eventStates[c.ID] = state
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
			if resp.StatusCode == 404 {
				// Registered tokens with no events return {"events":[]}.
				// Other 404s (for example token-not-owned responses from older/self-hosted
				// servers) are unavailable, not "never fired".
				if err := json.Unmarshal(data, &result); err == nil && result.Events != nil {
					state.available = true
				}
				eventStates[c.ID] = state
				continue
			}
			state.available = true
			if err := json.Unmarshal(data, &result); err != nil {
				state.available = false
				eventStates[c.ID] = state
				continue
			}
			// Find most recent non-test event
			for _, e := range result.Events {
				if !e.IsTest {
					state.lastSeen = e.Timestamp
					break
				}
			}
			// Count non-test events
			for _, e := range result.Events {
				if !e.IsTest {
					state.count++
				}
			}
			eventStates[c.ID] = state
		}
	}

	fmt.Printf("Active canaries (%d):\n\n", len(active))
	anyNever := false
	anyUnknown := false
	for _, c := range active {
		age := time.Since(c.PlantedAt).Round(time.Minute)
		if age < time.Minute {
			age = time.Second
		}
		label := c.Label
		if label == "" {
			label = "-"
		}
		lastEvent := "unknown (events unavailable; run `snare doctor`)"
		alerts := ""
		if state, ok := eventStates[c.ID]; ok && state.available {
			if state.lastSeen != "" {
				lastEvent = state.lastSeen
			} else {
				lastEvent = "never fired"
				anyNever = true
			}
			if state.count > 0 {
				alerts = fmt.Sprintf(" ⚠ %d alert(s)", state.count)
			}
		} else if c.LastSeen != nil {
			lastEvent = c.LastSeen.Format("2006-01-02 15:04 UTC") + " (cached)"
		} else {
			anyUnknown = true
		}
		rel := reliabilityDetailsFor(c.Type)
		fmt.Printf("  %s  %s\n", rel.marker, c.ID)
		fmt.Printf("    type:        %s (%s reliability)\n", c.Type, rel.tier)
		fmt.Printf("    label:       %s\n", label)
		fmt.Printf("    path:        %s\n", c.Path)
		fmt.Printf("    planted:     %s ago\n", age)
		fmt.Printf("    last event:  %s%s\n", lastEvent, alerts)
		fmt.Println()
	}
	fmt.Println("  ◆ precision reliability — active-use only; near-zero false positives")
	fmt.Println("  ● high reliability      — fires on credential use")
	fmt.Println("  ◐ medium reliability    — conditional trigger path")
	fmt.Println()
	if anyNever {
		fmt.Println("  `never fired` means no real callback has been recorded for that canary yet.")
		fmt.Println("  On a fresh install, that is expected until someone tries the fake credential.")
		fmt.Println()
	}
	if anyUnknown {
		fmt.Println("  Some event states were unavailable. Run `snare doctor` to check callback/API health.")
		fmt.Println()
	}
	fmt.Println("  Run `snare scan` to verify local canary files are still present.")
	fmt.Println("  Run `snare events` to fetch recent alert history.")
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
	fmt.Println("Firing test alert...")

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
	typeFilter := flagValue(args, "--type")
	force := hasFlag(args, "--force")
	dryRun := hasFlag(args, "--dry-run")

	if tokenID != "" && typeFilter != "" {
		fatal(fmt.Errorf("use either --token or --type, not both"))
	}
	if typeFilter != "" && !isKnownCanaryType(typeFilter) {
		fatal(fmt.Errorf("unknown canary type %q", typeFilter))
	}

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
	} else if typeFilter != "" {
		for _, c := range m.Active() {
			if c.Type == typeFilter {
				targets = append(targets, c)
			}
		}
		if len(targets) == 0 {
			fmt.Printf("No active %s canaries to remove.\n", typeFilter)
			return
		}
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
