// Package cli implements the snare command-line interface.
package cli

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/peg/snare/internal/bait"
	"github.com/peg/snare/internal/config"
	"github.com/peg/snare/internal/manifest"
	"github.com/peg/snare/internal/token"
)

const usage = `snare — compromise detection for AI agents via deception

Usage:
  snare init                   initialize snare on this machine
  snare plant [flags]          plant canary credentials
  snare status                 show active canaries
  snare test                   fire a test alert to verify your webhook
  snare teardown [flags]       remove planted canaries
  snare uninstall              teardown + remove all snare state

Flags (plant):
  --label <name>               prefix canary names (e.g. "openclaw", "myapp")
  --type <type>                canary type: aws, gcp, github, stripe, generic (default: aws)
  --dry-run                    show what would be planted without writing anything

Flags (teardown):
  --token <id>                 remove a single canary by ID
  --force                      remove even if content hash mismatches
  --dry-run                    show what would be removed without writing anything
`

// Run dispatches the CLI command.
func Run(args []string) {
	if len(args) == 0 {
		fmt.Print(usage)
		os.Exit(0)
	}

	cmd := args[0]
	rest := args[1:]

	switch cmd {
	case "init":
		cmdInit(rest)
	case "plant":
		cmdPlant(rest)
	case "status":
		cmdStatus(rest)
	case "test":
		cmdTest(rest)
	case "teardown":
		cmdTeardown(rest)
	case "uninstall":
		cmdUninstall(rest)
	case "help", "--help", "-h":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", cmd, usage)
		os.Exit(1)
	}
}

// cmdInit sets up snare for this machine.
func cmdInit(args []string) {
	force := hasFlag(args, "--force")

	cfg, err := config.Init("", force)
	if err != nil {
		fatal(err)
	}

	fmt.Printf("✓ snare initialized\n")
	fmt.Printf("  Device ID:    %s\n", cfg.DeviceID)
	fmt.Printf("  Callback:     %s/<token>\n", cfg.CallbackBase)
	fmt.Printf("\nRun `snare plant` to deploy your first canaries.\n")
}

// cmdPlant deploys canary credentials to this machine.
func cmdPlant(args []string) {
	label := flagValue(args, "--label")
	baitType := flagValue(args, "--type")
	dryRun := hasFlag(args, "--dry-run")

	if baitType == "" {
		baitType = "aws"
	}

	cfg, err := requireConfig()
	if err != nil {
		fatal(err)
	}

	m, err := manifest.Load()
	if err != nil {
		fatal(err)
	}

	bt := bait.Type(baitType)
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
		age := time.Since(c.PlantedAt).Round(time.Hour)
		label := c.Label
		if label == "" {
			label = "-"
		}
		lastSeen := "never"
		if c.LastSeen != nil {
			lastSeen = c.LastSeen.Format("2006-01-02 15:04 UTC")
		}
		fmt.Printf("  %s\n", c.ID)
		fmt.Printf("    type:      %s\n", c.Type)
		fmt.Printf("    label:     %s\n", label)
		fmt.Printf("    path:      %s\n", c.Path)
		fmt.Printf("    planted:   %s ago\n", age)
		fmt.Printf("    last seen: %s\n", lastSeen)
		fmt.Println()
	}
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

	// Use curl to fire the callback (avoids import of net/http for now)
	err = execCurl(callbackURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "  error: %v\n", err)
		fmt.Fprintf(os.Stderr, "  check your internet connection and snare.sh status\n")
		os.Exit(1)
	}

	fmt.Println("✓ Test alert fired — check your webhook destination.")
	fmt.Println("  If no alert arrives within 30 seconds, check your WEBHOOK_URLS secret on Cloudflare.")
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

	// Teardown all active canaries first
	cmdTeardown(append(args, "--force"))

	if dryRun {
		fmt.Println("[dry-run] would delete ~/.snare/")
		return
	}

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

	p := bait.Params{
		TokenID:     tokenID,
		CallbackURL: cfg.CallbackURL(tokenID),
		Label:       label,
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

// execCurl fires a GET request to url using the system curl binary.
func execCurl(url string) error {
	c := exec.Command("curl", "-sf", "-o", "/dev/null", url)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
}

func runShell(cmd string) error {
	c := exec.Command("sh", "-c", cmd)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	return c.Run()
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
