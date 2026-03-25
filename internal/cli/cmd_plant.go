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

// armCanaryTypes are planted by default with `snare arm` — the full recommended set.
// High reliability types fire when the SDK actually uses the credential.
// Medium reliability types fire conditionally but are still valuable coverage.
var highReliabilityTypes = []bait.Type{
	bait.TypeAWS, bait.TypeAWSProc, bait.TypeGCP,
	bait.TypeSSH, bait.TypeK8s, bait.TypePyPI,
	bait.TypeOpenAI, bait.TypeAnthropic, bait.TypeNPM, bait.TypeMCP,
	bait.TypeHuggingFace, bait.TypeDocker, bait.TypeAzure, bait.TypeTerraform,
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
