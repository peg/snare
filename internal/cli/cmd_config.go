package cli

import (
	"fmt"
	"os"

	"github.com/peg/snare/internal/config"
	"github.com/peg/snare/internal/manifest"
)

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
		fmt.Printf("  Webhook:       %s\n", webhookSummary(cfg.WebhookURL))
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
		fmt.Printf("  ✓ Webhook URL updated: %s\n", webhookSummary(url))
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
	healthURL := cfg.APIBase() + "/health"
	resp, err := httpClient.Get(healthURL) //nolint:gosec
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
		check("Webhook", "ok", webhookSummary(cfg.WebhookURL))
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

			// 5. Verify each canary file still exists and its planted content matches.
			modified := 0
			missing := 0
			for _, result := range ScanManifest(mfst) {
				switch result.Status {
				case ScanMissing:
					missing++
				case ScanModified:
					modified++
				}
			}
			if missing > 0 {
				check("Canary files", "fail", fmt.Sprintf("%d missing from disk — run `snare arm` to replant", missing))
			} else if modified > 0 {
				check("Canary integrity", "warn", fmt.Sprintf("%d files modified since planting", modified))
			} else {
				check("Canary files", "ok", "all present and unmodified")
			}
		}
	}

	// 6. Fire test alert (optional, only if --test flag provided or interactive)
	if hasFlag(args, "--test") {
		fmt.Println()
		fmt.Println("  Firing test alert...")
		shortID := cfg.DeviceID
		if len(shortID) > 8 {
			shortID = shortID[len(shortID)-8:]
		}
		testToken := "snare-test-" + shortID
		if err := registerToken(cfg, testToken, "test", "test"); err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠  webhook registration failed: %v\n", err)
			fmt.Fprintf(os.Stderr, "     The callback will still fire but your webhook may not receive the alert.\n")
		}
		testURL := cfg.CallbackURL(testToken)
		resp, err := httpClient.Get(testURL) //nolint:gosec
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
