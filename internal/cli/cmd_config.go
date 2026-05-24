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
