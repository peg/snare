package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/peg/snare/internal/config"
	"github.com/peg/snare/internal/manifest"
)

type apiEvent struct {
	Timestamp string `json:"timestamp"`
	IsTest    bool   `json:"is_test"`
}

type tokenProbeResult struct {
	TokenID       string
	StatusCode    int
	OwnedReadable bool
	Unregistered  bool
	AuthFailed    bool
	Unavailable   bool
	APIError      string
	Err           error
	Events        []apiEvent
}

type probeSummary struct {
	Total        int
	Readable     int
	Unregistered int
	AuthFailed   int
	Unavailable  int
}

type webhookTestResult struct {
	RegisterErr error
	FireErr     error
	ObserveErr  error
	ObservedAt  string
}

type proofRecipe struct {
	Canary   manifest.Canary
	Tier     string
	Command  string
	Expected string
	Binary   string
}

type proofReport struct {
	Version              int                `json:"version"`
	GeneratedAt          string             `json:"generated_at"`
	DeviceID             string             `json:"device_id"`
	Mode                 string             `json:"mode"`
	RanProofs            bool               `json:"ran_proofs"`
	Redacted             bool               `json:"redacted"`
	Summary              proofReportSummary `json:"summary"`
	Proofs               []proofReportEntry `json:"proofs"`
	WhatThisProves       []string           `json:"what_this_proves"`
	WhatThisDoesNotProve []string           `json:"what_this_does_not_prove"`
	NextSteps            []string           `json:"next_steps"`
}

type proofReportSummary struct {
	Total  int `json:"total"`
	Passed int `json:"passed"`
	Failed int `json:"failed"`
	NotRun int `json:"not_run"`
}

type proofReportEntry struct {
	Type            string `json:"type"`
	Tier            string `json:"tier"`
	TokenID         string `json:"token_id"`
	Label           string `json:"label,omitempty"`
	Path            string `json:"path"`
	Command         string `json:"command"`
	Expected        string `json:"expected"`
	Trigger         string `json:"trigger"`
	Status          string `json:"status"`
	EventVisibility string `json:"event_visibility"`
	ObservedAt      string `json:"observed_at,omitempty"`
	ObservedAfterMS int64  `json:"observed_after_ms,omitempty"`
	Error           string `json:"error,omitempty"`
	NextCommand     string `json:"next_command"`
}

func cmdDoctor(args []string) {
	if hasFlag(args, "--help") || hasFlag(args, "-h") {
		fmt.Print(`snare doctor — confidence checks for first-run trust

Usage:
  snare doctor [--test]

Checks:
  - Config presence + device auth fields
  - Callback/API health
  - Local canary file integrity
  - Token registration ownership
  - Events API readability/auth
  - Webhook test history

Flags:
  --test    fire a live test callback and confirm it is readable via events API
`)
		return
	}

	runLiveTest := hasFlag(args, "--test")

	fmt.Println()
	fmt.Println("  snare doctor — confidence checks")
	fmt.Println()

	pass := 0
	warn := 0
	fail := 0

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

	cfg, err := config.Load()
	if err != nil || cfg == nil {
		check("Config", "fail", "~/.snare/config.json missing — run `snare arm`")
		fmt.Println()
		fmt.Printf("  %d passed, %d warned, %d failed\n\n", pass, warn, fail)
		os.Exit(1)
	}

	check("Config", "ok", "~/.snare/config.json loaded")
	if cfg.DeviceID != "" && len(cfg.DeviceSecret) >= 32 {
		check("Device auth", "ok", "device ID + secret present")
	} else {
		check("Device auth", "fail", "device ID/secret missing or invalid")
	}

	healthURL := cfg.APIBase() + "/health"
	resp, err := httpClient.Get(healthURL) //nolint:gosec
	if err != nil {
		check("Callback health", "fail", "callback/API unreachable")
	} else {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			check("Callback health", "ok", "API reachable")
		} else {
			check("Callback health", "warn", fmt.Sprintf("API returned HTTP %d", resp.StatusCode))
		}
	}

	if cfg.WebhookURL == "" {
		check("Webhook config", "warn", "no local webhook (using global fallback)")
	} else {
		check("Webhook config", "ok", webhookSummary(cfg.WebhookURL))
	}

	m, err := manifest.Load()
	if err != nil || m == nil {
		check("Manifest", "fail", "~/.snare/manifest.json missing or unreadable")
		fmt.Println()
		fmt.Printf("  %d passed, %d warned, %d failed\n\n", pass, warn, fail)
		os.Exit(1)
	}

	active := m.Active()
	if len(active) == 0 {
		check("Active canaries", "fail", "none found — run `snare arm`")
	} else {
		check("Active canaries", "ok", fmt.Sprintf("%d armed", len(active)))

		results := ScanManifest(m)
		missing := 0
		modified := 0
		for _, r := range results {
			switch r.Status {
			case ScanMissing:
				missing++
			case ScanModified:
				modified++
			}
		}

		switch {
		case missing > 0:
			check("Local canary files", "fail", fmt.Sprintf("%d missing from disk — run `snare arm` to replant", missing))
		case modified > 0:
			check("Local canary files", "warn", fmt.Sprintf("%d modified since planting", modified))
		default:
			check("Local canary files", "ok", "all present and unmodified")
		}

		orphans, orphanErr := ScanForOrphans(m)
		if orphanErr != nil {
			check("Orphan scan", "warn", "could not scan for orphaned canaries")
		} else if len(orphans) > 0 {
			check("Orphan scan", "warn", fmt.Sprintf("%d orphaned canary file(s) found", len(orphans)))
		} else {
			check("Orphan scan", "ok", "no orphaned canary files found")
		}
	}

	if len(active) > 0 {
		probes := make([]tokenProbeResult, 0, len(active))
		neverFired := 0
		for _, c := range active {
			p := probeTokenEvents(cfg, c.ID)
			if p.OwnedReadable && countEventsByKind(p.Events, false) == 0 {
				neverFired++
			}
			probes = append(probes, p)
		}
		sum := summarizeProbes(probes)

		switch {
		case sum.AuthFailed > 0:
			check("Token ownership", "fail", fmt.Sprintf("auth rejected for %d/%d token(s)", sum.AuthFailed, sum.Total))
		case sum.Unregistered > 0:
			check("Token ownership", "fail", fmt.Sprintf("%d/%d token(s) not registered — run `snare repair`", sum.Unregistered, sum.Total))
		case sum.Readable == sum.Total:
			check("Token ownership", "ok", fmt.Sprintf("%d/%d token(s) owned by this device", sum.Readable, sum.Total))
		default:
			check("Token ownership", "warn", fmt.Sprintf("%d/%d token(s) unavailable from events API", sum.Unavailable, sum.Total))
		}

		switch {
		case sum.AuthFailed > 0:
			check("Events API", "fail", "device auth failed")
		case sum.Unavailable > 0:
			check("Events API", "warn", fmt.Sprintf("%d/%d token(s) unreadable right now", sum.Unavailable, sum.Total))
		default:
			check("Events API", "ok", "readable for all active tokens")
		}

		if neverFired > 0 {
			check("Real event state", "ok", fmt.Sprintf("%d/%d token(s) are `never fired` (expected until active fake credential use)", neverFired, len(active)))
		}
	}

	testToken := deviceTestTokenID(cfg)
	testProbe := probeTokenEvents(cfg, testToken)
	switch {
	case testProbe.AuthFailed:
		check("Webhook test history", "fail", "auth failed reading test token history")
	case testProbe.OwnedReadable && countEventsByKind(testProbe.Events, true) > 0:
		check("Webhook test history", "ok", fmt.Sprintf("last test callback recorded at %s", latestEventTimestamp(testProbe.Events, true)))
	case testProbe.OwnedReadable:
		check("Webhook test history", "warn", "test token registered but no test callbacks recorded yet")
	case testProbe.Unregistered:
		check("Webhook test history", "warn", "no test token history yet — run `snare doctor --test`")
	default:
		check("Webhook test history", "warn", "test token state unavailable")
	}

	if runLiveTest {
		live := runWebhookTest(cfg)
		switch {
		case live.RegisterErr != nil:
			check("Live webhook test", "fail", fmt.Sprintf("test token registration failed: %v", live.RegisterErr))
		case live.FireErr != nil:
			check("Live webhook test", "fail", fmt.Sprintf("callback trigger failed: %v", live.FireErr))
		case live.ObserveErr != nil:
			check("Live webhook test", "fail", fmt.Sprintf("callback fired but event not readable: %v", live.ObserveErr))
		default:
			check("Live webhook test", "ok", fmt.Sprintf("callback recorded at %s", live.ObservedAt))
		}
	}

	fmt.Println()
	if fail > 0 {
		fmt.Printf("  %d passed, %d warned, %d failed\n\n", pass, warn, fail)
		os.Exit(1)
	}
	if warn > 0 {
		fmt.Printf("  %d passed, %d warned — mostly healthy\n\n", pass, warn)
		return
	}
	fmt.Printf("  %d passed — confidence is high\n\n", pass)
}

func cmdRepair(args []string) {
	if hasFlag(args, "--help") || hasFlag(args, "-h") {
		fmt.Print(`snare repair — safely re-sync token registrations and test health

Usage:
  snare repair [--dry-run]
  snare sync   [--dry-run]

What it does:
  - re-registers all active tokens (idempotent)
  - verifies post-repair ownership/readability via events API
  - fires a test callback and confirms it is readable

Safety:
  - does not modify canary files
  - does not print webhook URLs or secrets
`)
		return
	}

	dryRun := hasFlag(args, "--dry-run")

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
		fmt.Println("No active canaries. Run `snare arm` to deploy.")
		return
	}

	fmt.Println()
	fmt.Println("  snare repair — re-syncing registrations safely")
	fmt.Println()

	pre := make([]tokenProbeResult, 0, len(active))
	for _, c := range active {
		pre = append(pre, probeTokenEvents(cfg, c.ID))
	}
	preSum := summarizeProbes(pre)
	fmt.Printf("  Pre-check: %d/%d readable, %d unregistered, %d auth-failed, %d unavailable\n",
		preSum.Readable, preSum.Total, preSum.Unregistered, preSum.AuthFailed, preSum.Unavailable)

	if dryRun {
		fmt.Printf("  [dry-run] would re-register %d active token(s)\n", len(active))
		fmt.Println("  [dry-run] would run a live test callback and confirm event readability")
		fmt.Println()
		return
	}

	fmt.Printf("  Re-registering %d active token(s)...\n", len(active))
	regOK := 0
	regFail := 0
	for _, c := range active {
		if err := registerToken(cfg, c.ID, c.Type, c.Label); err != nil {
			regFail++
			fmt.Fprintf(os.Stderr, "    ✗ %-12s %s: %v\n", c.Type, shortTokenID(c.ID), err)
			continue
		}
		regOK++
	}
	fmt.Printf("  Registration refresh: %d ok, %d failed\n", regOK, regFail)

	post := make([]tokenProbeResult, 0, len(active))
	for _, c := range active {
		post = append(post, probeTokenEvents(cfg, c.ID))
	}
	postSum := summarizeProbes(post)

	fmt.Printf("  Post-check: %d/%d readable, %d unregistered, %d auth-failed, %d unavailable\n",
		postSum.Readable, postSum.Total, postSum.Unregistered, postSum.AuthFailed, postSum.Unavailable)

	improvedReadable := postSum.Readable - preSum.Readable
	if improvedReadable < 0 {
		improvedReadable = 0
	}
	fixedUnregistered := preSum.Unregistered - postSum.Unregistered
	if fixedUnregistered < 0 {
		fixedUnregistered = 0
	}

	live := runWebhookTest(cfg)
	switch {
	case live.RegisterErr != nil:
		fmt.Fprintf(os.Stderr, "  ✗ Test callback registration failed: %v\n", live.RegisterErr)
	case live.FireErr != nil:
		fmt.Fprintf(os.Stderr, "  ✗ Test callback trigger failed: %v\n", live.FireErr)
	case live.ObserveErr != nil:
		fmt.Fprintf(os.Stderr, "  ✗ Test callback not readable: %v\n", live.ObserveErr)
	default:
		fmt.Printf("  ✓ Test callback recorded at %s\n", live.ObservedAt)
	}

	fmt.Println()
	if improvedReadable > 0 || fixedUnregistered > 0 {
		fmt.Printf("  Drift repaired: %d token(s) regained readable ownership, %d token(s) re-registered.\n",
			improvedReadable, fixedUnregistered)
	} else {
		fmt.Println("  No registration drift detected; ownership mappings were refreshed.")
	}

	if regFail > 0 || postSum.Unregistered > 0 || postSum.AuthFailed > 0 || postSum.Unavailable > 0 ||
		live.RegisterErr != nil || live.FireErr != nil || live.ObserveErr != nil {
		fmt.Println("  Repair incomplete. Run `snare doctor --test` for detailed diagnostics.")
		fmt.Println()
		os.Exit(1)
	}

	fmt.Println("  ✓ Repair complete. Registrations and callback/event path look healthy.")
	fmt.Println()
}

func cmdProve(args []string) {
	if hasFlag(args, "--help") || hasFlag(args, "-h") {
		fmt.Print(`snare prove — guided canary proof commands

Usage:
  snare prove [--pack precision|mcp|all] [--type awsproc|ssh|k8s|git|npm|mcp] [--run] [--report] [--format text|json] [--output <path>] [--redact]

Default behavior:
  Prints exact safe trigger commands for active precision canaries.

MCP pack:
  snare prove --pack mcp prints a Streamable HTTP initialize probe for active MCP canaries.
  The probe uses the planted non-auto-loaded MCP config and does not modify active client configs.

With --run:
  Executes the trigger command and confirms a new real callback is readable.

With --report:
  Prints a first-success proof report with commands, observed callbacks, and next steps.

With --format json:
  Emits only the proof report as JSON. Implies --report.

With --output:
  Writes the same proof report artifact to a file.

With --redact:
  Redacts device IDs, token IDs, labels, cleanup tokens, and local absolute paths.
`)
		return
	}

	typeFilter := strings.ToLower(flagValue(args, "--type"))
	packFilterRaw := strings.ToLower(flagValue(args, "--pack"))
	run := hasFlag(args, "--run")
	reportRequested := hasFlag(args, "--report")
	redactReport := hasFlag(args, "--redact")
	outputPath := flagValue(args, "--output")
	if hasFlag(args, "--output") && (outputPath == "" || strings.HasPrefix(outputPath, "--")) {
		fatal(fmt.Errorf("--output requires a path"))
	}
	if outputPath != "" {
		reportRequested = true
	}
	format := flagValue(args, "--format")
	if format == "" {
		format = "text"
	}
	format = strings.ToLower(format)
	if format != "text" && format != "json" {
		fatal(fmt.Errorf("unsupported --format %q (expected text or json)", format))
	}
	jsonOutput := format == "json"
	if jsonOutput {
		reportRequested = true
	}

	if typeFilter != "" && !isProofCanaryType(typeFilter) {
		fatal(fmt.Errorf("unsupported --type %q (expected awsproc, ssh, k8s, git, npm, or mcp)", typeFilter))
	}

	packFilter := packFilterRaw
	if packFilter == "" {
		packFilter = "precision"
		if typeFilter == "mcp" {
			packFilter = "mcp"
		}
	}
	if !isProofPack(packFilter) {
		fatal(fmt.Errorf("unsupported --pack %q (expected precision, mcp, or all)", packFilter))
	}
	if typeFilter != "" && !proofTypeInPack(typeFilter, packFilter) {
		fatal(fmt.Errorf("--type %s is not part of --pack %s", typeFilter, packFilter))
	}

	cfg, err := requireConfig()
	if err != nil {
		fatal(err)
	}

	m, err := manifest.Load()
	if err != nil {
		fatal(err)
	}

	targets := selectProofCanaries(m.Active(), typeFilter, packFilter)
	if len(targets) == 0 {
		if typeFilter != "" {
			fmt.Printf("No active %s canary found. Run `snare arm --all` or `snare plant --type %s`.\n", typeFilter, typeFilter)
		} else if packFilter == "precision" {
			fmt.Println("No active precision canaries found. Run `snare arm` first.")
		} else if packFilter == "all" {
			fmt.Println("No active proof-capable canaries found. Run `snare arm` or `snare plant --type mcp`.")
		} else {
			fmt.Printf("No active %s canaries found. Run `snare arm --all` or `snare plant --type mcp`.\n", packFilter)
		}
		return
	}

	recipes := make([]proofRecipe, 0, len(targets))
	for _, c := range targets {
		recipe, err := buildProofRecipe(c)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠  skipping %s (%s): %v\n", c.Type, shortTokenID(c.ID), err)
			continue
		}
		recipes = append(recipes, recipe)
	}
	if len(recipes) == 0 {
		fatal(fmt.Errorf("no runnable %s canary proofs found", packFilter))
	}

	report := buildProofReport(cfg, recipes, run, packFilter)

	if !jsonOutput {
		fmt.Println()
		fmt.Printf("  snare prove — %s proof flow\n", proofModeLabel(report.Mode))
		fmt.Println()
		for _, recipe := range recipes {
			fmt.Printf("  %-8s %s\n", recipe.Canary.Type, shortTokenID(recipe.Canary.ID))
			fmt.Printf("    command: %s\n", recipe.Command)
			fmt.Printf("    expect:  %s\n", recipe.Expected)
			fmt.Println()
		}
	}

	if !run {
		if !jsonOutput {
			fmt.Println("  These commands intentionally trigger active canaries.")
			fmt.Println("  Add `--run` to execute them and verify callbacks end-to-end.")
			fmt.Println()
		}
		if reportRequested {
			emitProofReport(report, format, outputPath, redactReport)
		}
		return
	}

	failures := 0
	for i, recipe := range recipes {
		before := probeTokenEvents(cfg, recipe.Canary.ID)
		if before.AuthFailed {
			msg := "auth failed before proof — run `snare repair`"
			report.Proofs[i].Status = "failed"
			report.Proofs[i].EventVisibility = "events API auth failed before trigger"
			report.Proofs[i].Error = msg
			fmt.Fprintf(os.Stderr, "  ✗ %-8s %s\n", recipe.Canary.Type, msg)
			failures++
			continue
		}
		if before.Unregistered {
			msg := "token is unregistered — run `snare repair`"
			report.Proofs[i].Status = "failed"
			report.Proofs[i].EventVisibility = "token is not registered or readable by this device"
			report.Proofs[i].Error = msg
			fmt.Fprintf(os.Stderr, "  ✗ %-8s %s\n", recipe.Canary.Type, msg)
			failures++
			continue
		}
		if before.Unavailable {
			msg := "events API unavailable — run `snare doctor`"
			report.Proofs[i].Status = "failed"
			report.Proofs[i].EventVisibility = "events API unavailable before trigger"
			report.Proofs[i].Error = msg
			fmt.Fprintf(os.Stderr, "  ✗ %-8s %s\n", recipe.Canary.Type, msg)
			failures++
			continue
		}

		if _, err := exec.LookPath(recipe.Binary); err != nil {
			msg := fmt.Sprintf("missing `%s` binary; run the printed command manually when installed", recipe.Binary)
			report.Proofs[i].Status = "failed"
			report.Proofs[i].EventVisibility = "not checked because trigger binary is missing"
			report.Proofs[i].Error = msg
			fmt.Fprintf(os.Stderr, "  ✗ %-8s %s\n", recipe.Canary.Type, msg)
			failures++
			continue
		}

		baseline := countEventsByKind(before.Events, false)
		report.Proofs[i].EventVisibility = "events API readable before trigger"
		if !jsonOutput {
			fmt.Printf("  Running %-8s proof...\n", recipe.Canary.Type)
		}
		startedAt := time.Now()
		if err := runProofCommand(recipe.Command, 15*time.Second); err != nil {
			msg := fmt.Sprintf("trigger command failed: %v", err)
			report.Proofs[i].Status = "failed"
			report.Proofs[i].EventVisibility = "events API readable before trigger; callback observation skipped because trigger command failed"
			report.Proofs[i].Error = msg
			fmt.Fprintf(os.Stderr, "    ✗ %s\n", msg)
			failures++
			continue
		}

		ts, err := waitForEventCountAbove(cfg, recipe.Canary.ID, baseline, false, 8*time.Second)
		if err != nil {
			msg := fmt.Sprintf("callback not observed: %v", err)
			report.Proofs[i].Status = "failed"
			report.Proofs[i].EventVisibility = "events API readable before trigger; no new callback observed after trigger"
			report.Proofs[i].Error = msg
			fmt.Fprintf(os.Stderr, "    ✗ %s\n", msg)
			failures++
			continue
		}
		if ts == "" {
			ts = "just now"
		}
		report.Proofs[i].Status = "passed"
		report.Proofs[i].EventVisibility = "callback observed through events API after trigger"
		report.Proofs[i].ObservedAt = ts
		report.Proofs[i].ObservedAfterMS = time.Since(startedAt).Milliseconds()
		if !jsonOutput {
			fmt.Printf("    ✓ callback observed at %s\n", ts)
		}
	}
	finalizeProofReport(&report)

	if reportRequested {
		emitProofReport(report, format, outputPath, redactReport)
	}

	if !jsonOutput {
		fmt.Println()
	}
	if failures > 0 {
		if !jsonOutput {
			fmt.Printf("  %d proof step(s) failed. Use `snare doctor --test` and `snare repair` for diagnostics.\n\n", failures)
		}
		os.Exit(1)
	}
	if !jsonOutput {
		fmt.Printf("  ✓ %s. Alerts are firing as expected.\n", proofCompletionLabel(report.Mode))
		fmt.Println()
	}
}

func buildProofReport(cfg *config.Config, recipes []proofRecipe, run bool, mode string) proofReport {
	status := "not-run"
	if run {
		status = "pending"
	}

	proofs := make([]proofReportEntry, 0, len(recipes))
	for _, recipe := range recipes {
		eventVisibility := "not checked yet"
		if !run {
			eventVisibility = "not checked; run with --run to verify callback visibility through events API"
		}
		proofs = append(proofs, proofReportEntry{
			Type:            recipe.Canary.Type,
			Tier:            recipe.Tier,
			TokenID:         recipe.Canary.ID,
			Label:           recipe.Canary.Label,
			Path:            recipe.Canary.Path,
			Command:         recipe.Command,
			Expected:        recipe.Expected,
			Trigger:         proofTriggerDescription(recipe.Canary.Type),
			Status:          status,
			EventVisibility: eventVisibility,
			NextCommand:     "snare teardown --token " + recipe.Canary.ID,
		})
	}

	report := proofReport{
		Version:              1,
		GeneratedAt:          time.Now().UTC().Format(time.RFC3339),
		DeviceID:             cfg.DeviceID,
		Mode:                 mode,
		RanProofs:            run,
		Redacted:             false,
		Proofs:               proofs,
		WhatThisProves:       proofReportProves(run, mode),
		WhatThisDoesNotProve: proofReportLimitations(run, mode),
		NextSteps: []string{
			"snare events",
			"snare doctor",
			"snare disarm",
		},
	}
	finalizeProofReport(&report)
	return report
}

func finalizeProofReport(report *proofReport) {
	report.Summary = proofReportSummary{Total: len(report.Proofs)}
	for _, proof := range report.Proofs {
		switch proof.Status {
		case "passed":
			report.Summary.Passed++
		case "failed":
			report.Summary.Failed++
		case "not-run", "pending":
			report.Summary.NotRun++
		}
	}
}

func emitProofReport(report proofReport, format, outputPath string, redact bool) {
	if redact {
		report = redactProofReport(report)
	} else {
		report.Redacted = false
	}
	finalizeProofReport(&report)

	rendered, err := renderProofReport(report, format)
	if err != nil {
		fatal(err)
	}
	if outputPath != "" {
		if err := writeProofReportFile(outputPath, rendered); err != nil {
			fatal(err)
		}
	}
	fmt.Print(rendered)
}

func renderProofReport(report proofReport, format string) (string, error) {
	switch format {
	case "json":
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return "", fmt.Errorf("encoding proof report: %w", err)
		}
		return b.String(), nil
	case "text":
		return formatProofReport(report), nil
	default:
		return "", fmt.Errorf("unsupported proof report format %q", format)
	}
}

func writeProofReportFile(path, rendered string) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("creating proof report directory: %w", err)
		}
	}
	if err := os.WriteFile(path, []byte(rendered), 0600); err != nil {
		return fmt.Errorf("writing proof report: %w", err)
	}
	return nil
}

func formatProofReport(report proofReport) string {
	var b strings.Builder
	b.WriteString("  Proof report\n")
	fmt.Fprintf(&b, "    device:    %s\n", report.DeviceID)
	fmt.Fprintf(&b, "    mode:      %s\n", report.Mode)
	fmt.Fprintf(&b, "    generated: %s\n", report.GeneratedAt)
	fmt.Fprintf(&b, "    redacted:  %t\n", report.Redacted)
	fmt.Fprintf(&b, "    summary:   %d total, %d passed, %d failed, %d not run\n",
		report.Summary.Total, report.Summary.Passed, report.Summary.Failed, report.Summary.NotRun)
	b.WriteString("\n")

	for _, proof := range report.Proofs {
		fmt.Fprintf(&b, "    %-8s %-7s %s\n", proof.Type, proof.Status, shortTokenID(proof.TokenID))
		fmt.Fprintf(&b, "      tier:       %s\n", proof.Tier)
		fmt.Fprintf(&b, "      trigger:    %s\n", proof.Trigger)
		fmt.Fprintf(&b, "      path:       %s\n", proof.Path)
		fmt.Fprintf(&b, "      command:    %s\n", proof.Command)
		fmt.Fprintf(&b, "      expect:     %s\n", proof.Expected)
		if proof.EventVisibility != "" {
			fmt.Fprintf(&b, "      visibility: %s\n", proof.EventVisibility)
		}
		if proof.ObservedAt != "" {
			if proof.ObservedAfterMS > 0 {
				fmt.Fprintf(&b, "      observed:   %s (%d ms after trigger)\n", proof.ObservedAt, proof.ObservedAfterMS)
			} else {
				fmt.Fprintf(&b, "      observed:   %s\n", proof.ObservedAt)
			}
		}
		if proof.Error != "" {
			fmt.Fprintf(&b, "      error:      %s\n", proof.Error)
		}
		fmt.Fprintf(&b, "      cleanup:    %s\n", proof.NextCommand)
		b.WriteString("\n")
	}

	writeProofReportSection(&b, "what this proves", report.WhatThisProves)
	writeProofReportSection(&b, "what this does not prove", report.WhatThisDoesNotProve)
	writeProofReportSection(&b, "next", report.NextSteps)
	return b.String()
}

func writeProofReportSection(b *strings.Builder, title string, lines []string) {
	if len(lines) == 0 {
		return
	}
	fmt.Fprintf(b, "    %s:\n", title)
	for _, line := range lines {
		fmt.Fprintf(b, "      %s\n", line)
	}
	b.WriteString("\n")
}

func proofReportProves(run bool, mode string) []string {
	label := proofModeLabel(mode)
	if run {
		return []string{
			fmt.Sprintf("Snare found active %s canaries and executed their safe trigger commands.", label),
			"Passed proofs produced real non-test callbacks that were readable through Snare's events API.",
		}
	}
	return []string{
		fmt.Sprintf("Snare found active %s canaries and generated safe trigger commands for them.", label),
		"No callbacks were fired because --run was not provided.",
	}
}

func proofReportLimitations(run bool, mode string) []string {
	limitations := []string{
		fmt.Sprintf("It covers only the selected active %s canaries, not every planted token or canary type.", proofModeLabel(mode)),
		"It does not prove downstream notification delivery unless alerts are also observed outside this report.",
	}
	if !run {
		limitations = append(limitations, "It does not prove callback delivery until rerun with --run.")
	}
	return limitations
}

type redactionPair struct {
	Old string
	New string
}

func redactProofReport(report proofReport) proofReport {
	report.Redacted = true
	pairs := make([]redactionPair, 0, 2+len(report.Proofs)*4)

	if report.DeviceID != "" {
		pairs = append(pairs, redactionPair{Old: report.DeviceID, New: "<redacted-device>"})
		report.DeviceID = "<redacted-device>"
	}

	tokenRedactions := map[string]string{}
	labelRedactions := map[string]string{}
	tokenIndex := 1
	labelIndex := 1
	for i := range report.Proofs {
		proof := &report.Proofs[i]
		if proof.TokenID != "" {
			redacted := numberedRedaction(tokenRedactions, proof.TokenID, "token", &tokenIndex)
			pairs = append(pairs, redactionPair{Old: proof.TokenID, New: redacted})
			proof.TokenID = redacted
		}
		if proof.Label != "" {
			redacted := numberedRedaction(labelRedactions, proof.Label, "label", &labelIndex)
			pairs = append(pairs, redactionPair{Old: proof.Label, New: redacted})
			proof.Label = redacted
		}
		if proof.Path != "" {
			redacted := redactLocalPath(proof.Path)
			if redacted != proof.Path {
				pairs = append(pairs,
					redactionPair{Old: shellQuote(proof.Path), New: shellQuote(redacted)},
					redactionPair{Old: proof.Path, New: redacted},
				)
				proof.Path = redacted
			}
		}
	}

	sort.SliceStable(pairs, func(i, j int) bool {
		return len(pairs[i].Old) > len(pairs[j].Old)
	})

	for i := range report.Proofs {
		proof := &report.Proofs[i]
		proof.Command = applyRedactions(proof.Command, pairs)
		proof.Expected = applyRedactions(proof.Expected, pairs)
		proof.Trigger = applyRedactions(proof.Trigger, pairs)
		proof.EventVisibility = applyRedactions(proof.EventVisibility, pairs)
		proof.Error = applyRedactions(proof.Error, pairs)
		proof.NextCommand = applyRedactions(proof.NextCommand, pairs)
	}
	report.WhatThisProves = applyRedactionsToSlice(report.WhatThisProves, pairs)
	report.WhatThisDoesNotProve = applyRedactionsToSlice(report.WhatThisDoesNotProve, pairs)
	report.NextSteps = applyRedactionsToSlice(report.NextSteps, pairs)
	return report
}

func numberedRedaction(seen map[string]string, value, kind string, next *int) string {
	if redacted, ok := seen[value]; ok {
		return redacted
	}
	redacted := fmt.Sprintf("<redacted-%s-%d>", kind, *next)
	*next = *next + 1
	seen[value] = redacted
	return redacted
}

func redactLocalPath(path string) string {
	if path == "" {
		return path
	}
	if filepath.IsAbs(path) || strings.HasPrefix(path, "~/") {
		base := filepath.Base(path)
		if base == "." || base == string(os.PathSeparator) || base == "" {
			return "<redacted-path>"
		}
		return filepath.ToSlash(filepath.Join("<redacted-path>", base))
	}
	return path
}

func applyRedactionsToSlice(lines []string, pairs []redactionPair) []string {
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = applyRedactions(line, pairs)
	}
	return out
}

func applyRedactions(s string, pairs []redactionPair) string {
	for _, pair := range pairs {
		if pair.Old == "" || pair.Old == pair.New {
			continue
		}
		s = strings.ReplaceAll(s, pair.Old, pair.New)
	}
	return s
}

func proofTriggerDescription(t string) string {
	switch t {
	case "awsproc":
		return "AWS credential_process executes during SDK credential resolution before an AWS API call"
	case "ssh":
		return "SSH ProxyCommand executes before the fake host connection is established"
	case "k8s":
		return "kubeconfig API server is contacted by kubectl or a Kubernetes SDK using a static fake token"
	case "git":
		return "Git URL rewriting directs explicit use of the planted fake host to the callback"
	case "npm":
		return "npm scoped-registry resolution directs the planted fake package scope to the callback"
	case "mcp":
		return "MCP client sends a Streamable HTTP initialize request to the planted fake server URL"
	default:
		return "active canary use"
	}
}

func probeTokenEvents(cfg *config.Config, tokenID string) tokenProbeResult {
	result := tokenProbeResult{
		TokenID:     tokenID,
		Unavailable: true,
	}

	resp, err := authedGet(cfg.APIBase()+"/api/events/"+tokenID, cfg)
	if err != nil {
		result.Err = err
		return result
	}
	defer resp.Body.Close()

	result.StatusCode = resp.StatusCode
	body, _ := io.ReadAll(resp.Body)

	var payload struct {
		Events []apiEvent `json:"events"`
	}
	if (resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound) &&
		json.Unmarshal(body, &payload) == nil && payload.Events != nil {
		result.OwnedReadable = true
		result.Unavailable = false
		result.Events = payload.Events
		return result
	}

	var errPayload struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &errPayload)
	result.APIError = strings.TrimSpace(errPayload.Error)
	lowerErr := strings.ToLower(result.APIError)

	switch resp.StatusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		if strings.Contains(lowerErr, "token not registered") {
			result.Unregistered = true
			result.Unavailable = false
			return result
		}
		if containsAny(lowerErr, "invalid device secret", "unknown device", "missing authorization", "missing device_id") {
			result.AuthFailed = true
			result.Unavailable = false
			return result
		}
	case http.StatusNotFound:
		// Older servers may use 404 for token-not-registered states.
		if strings.Contains(lowerErr, "token") && strings.Contains(lowerErr, "registered") {
			result.Unregistered = true
			result.Unavailable = false
			return result
		}
	}

	return result
}

func summarizeProbes(probes []tokenProbeResult) probeSummary {
	sum := probeSummary{Total: len(probes)}
	for _, p := range probes {
		switch {
		case p.OwnedReadable:
			sum.Readable++
		case p.Unregistered:
			sum.Unregistered++
		case p.AuthFailed:
			sum.AuthFailed++
		default:
			sum.Unavailable++
		}
	}
	return sum
}

func runWebhookTest(cfg *config.Config) webhookTestResult {
	testToken := deviceTestTokenID(cfg)
	before := probeTokenEvents(cfg, testToken)
	baseline := 0
	if before.OwnedReadable {
		baseline = countEventsByKind(before.Events, true)
	}

	res := webhookTestResult{}
	if err := registerToken(cfg, testToken, "test", "test"); err != nil {
		res.RegisterErr = err
	}
	if err := httpGet(cfg.CallbackURL(testToken)); err != nil {
		res.FireErr = err
		return res
	}

	ts, err := waitForEventCountAbove(cfg, testToken, baseline, true, 8*time.Second)
	if err != nil {
		res.ObserveErr = err
		return res
	}
	res.ObservedAt = ts
	return res
}

func waitForEventCountAbove(cfg *config.Config, tokenID string, baseline int, testOnly bool, timeout time.Duration) (string, error) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		probe := probeTokenEvents(cfg, tokenID)
		if probe.AuthFailed {
			return "", fmt.Errorf("events API auth failed")
		}
		if probe.OwnedReadable {
			n := countEventsByKind(probe.Events, testOnly)
			if n > baseline {
				return latestEventTimestamp(probe.Events, testOnly), nil
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	return "", fmt.Errorf("no new callback observed within %s", timeout.Round(time.Second))
}

func countEventsByKind(events []apiEvent, testOnly bool) int {
	n := 0
	for _, e := range events {
		if testOnly {
			if e.IsTest {
				n++
			}
			continue
		}
		if !e.IsTest {
			n++
		}
	}
	return n
}

func latestEventTimestamp(events []apiEvent, testOnly bool) string {
	var latest time.Time
	latestRaw := ""
	for _, e := range events {
		if testOnly && !e.IsTest {
			continue
		}
		if !testOnly && e.IsTest {
			continue
		}
		if e.Timestamp == "" {
			continue
		}
		parsed, err := time.Parse(time.RFC3339, e.Timestamp)
		if err != nil {
			if latestRaw == "" {
				latestRaw = e.Timestamp
			}
			continue
		}
		if latestRaw == "" || parsed.After(latest) {
			latest = parsed
			latestRaw = e.Timestamp
		}
	}
	return latestRaw
}

func deviceTestTokenID(cfg *config.Config) string {
	shortID := cfg.DeviceID
	if len(shortID) > 8 {
		shortID = shortID[len(shortID)-8:]
	}
	return "snare-test-" + shortID
}

func containsAny(s string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(s, n) {
			return true
		}
	}
	return false
}

func shortTokenID(tokenID string) string {
	if len(tokenID) <= 20 {
		return tokenID
	}
	return tokenID[:20] + "..."
}

func isPrecisionCanaryType(t string) bool {
	switch t {
	case "awsproc", "ssh", "k8s", "git", "npm":
		return true
	default:
		return false
	}
}

func isProofCanaryType(t string) bool {
	return isPrecisionCanaryType(t) || t == "mcp"
}

func isProofPack(pack string) bool {
	switch pack {
	case "precision", "mcp", "all":
		return true
	default:
		return false
	}
}

func proofTypeInPack(t, pack string) bool {
	if pack == "all" {
		return isProofCanaryType(t)
	}
	if pack == "precision" {
		return isPrecisionCanaryType(t)
	}
	return pack == "mcp" && t == "mcp"
}

func proofTypeOrder(pack string) []string {
	switch pack {
	case "mcp":
		return []string{"mcp"}
	case "all":
		return []string{"awsproc", "ssh", "k8s", "git", "npm", "mcp"}
	default:
		return []string{"awsproc", "ssh", "k8s", "git", "npm"}
	}
}

func proofModeLabel(mode string) string {
	switch mode {
	case "mcp":
		return "MCP"
	case "all":
		return "combined"
	default:
		return "precision"
	}
}

func proofCompletionLabel(mode string) string {
	switch mode {
	case "mcp":
		return "MCP proof complete"
	case "all":
		return "Proof complete"
	default:
		return "Precision proof complete"
	}
}

func selectProofCanaries(active []manifest.Canary, typeFilter, packFilter string) []manifest.Canary {
	latestByType := map[string]manifest.Canary{}
	for _, c := range active {
		if !isProofCanaryType(c.Type) {
			continue
		}
		if typeFilter != "" && c.Type != typeFilter {
			continue
		}
		if typeFilter == "" && !proofTypeInPack(c.Type, packFilter) {
			continue
		}
		prev, ok := latestByType[c.Type]
		if !ok || c.PlantedAt.After(prev.PlantedAt) {
			latestByType[c.Type] = c
		}
	}

	order := proofTypeOrder(packFilter)
	out := make([]manifest.Canary, 0, len(order))
	if typeFilter != "" {
		order = []string{typeFilter}
	}
	for _, typ := range order {
		if c, ok := latestByType[typ]; ok {
			out = append(out, c)
		}
	}
	return out
}

func buildProofRecipe(c manifest.Canary) (proofRecipe, error) {
	if isPrecisionCanaryType(c.Type) {
		return buildPrecisionProofRecipe(c)
	}
	if c.Type == "mcp" {
		return buildMCPProofRecipe(c)
	}
	return proofRecipe{}, fmt.Errorf("unsupported proof type %q", c.Type)
}

func buildPrecisionProofRecipe(c manifest.Canary) (proofRecipe, error) {
	switch c.Type {
	case "awsproc":
		profile := extractAWSProcProfile(c.Content)
		if profile == "" {
			return proofRecipe{}, fmt.Errorf("could not parse profile name from canary content")
		}
		return proofRecipe{
			Canary:   c,
			Tier:     "precision",
			Binary:   "aws",
			Command:  "AWS_EC2_METADATA_DISABLED=true AWS_CONFIG_FILE=" + shellQuote(c.Path) + " AWS_SHARED_CREDENTIALS_FILE=/dev/null aws sts get-caller-identity --profile " + shellQuote(profile) + " --no-cli-pager",
			Expected: "AWS CLI may fail auth, but callback should fire immediately during credential resolution",
		}, nil
	case "ssh":
		host := extractSSHHost(c.Content)
		if host == "" {
			return proofRecipe{}, fmt.Errorf("could not parse ssh host from canary content")
		}
		return proofRecipe{
			Canary:   c,
			Tier:     "precision",
			Binary:   "ssh",
			Command:  "ssh -F " + shellQuote(c.Path) + " -o BatchMode=yes -o ConnectTimeout=3 " + shellQuote(host) + " true",
			Expected: "SSH connection fails quickly, but ProxyCommand callback should fire",
		}, nil
	case "k8s":
		return proofRecipe{
			Canary:   c,
			Tier:     "precision",
			Binary:   "kubectl",
			Command:  "kubectl --kubeconfig " + shellQuote(c.Path) + " get namespaces --request-timeout=5s",
			Expected: "kubectl request should fail, but the API-server callback should fire without executing a credential plugin",
		}, nil
	case "git":
		host := extractGitHost(c.Content)
		if host == "" {
			return proofRecipe{}, fmt.Errorf("could not parse Git host from canary content")
		}
		return proofRecipe{
			Canary:   c,
			Tier:     "precision",
			Binary:   "git",
			Command:  "GIT_CONFIG_GLOBAL=" + shellQuote(c.Path) + " GIT_CONFIG_NOSYSTEM=1 GIT_TERMINAL_PROMPT=0 git ls-remote " + shellQuote("https://"+host+"/snare-proof/repo"),
			Expected: "Git request should fail, but the scoped URL rewrite callback should fire",
		}, nil
	case "npm":
		scope := extractNPMScope(c.Content)
		if scope == "" {
			return proofRecipe{}, fmt.Errorf("could not parse npm scope from canary content")
		}
		return proofRecipe{
			Canary:   c,
			Tier:     "precision",
			Binary:   "npm",
			Command:  "npm view " + shellQuote("@"+scope+"/snare-proof-does-not-exist") + " version --userconfig " + shellQuote(c.Path) + " --loglevel=silent --fetch-retries=0",
			Expected: "npm lookup should fail, but the scoped-registry callback should fire",
		}, nil
	default:
		return proofRecipe{}, fmt.Errorf("unsupported precision type %q", c.Type)
	}
}

func buildMCPProofRecipe(c manifest.Canary) (proofRecipe, error) {
	serverName, serverURL := extractMCPServerURL(c.Content)
	if serverURL == "" {
		return proofRecipe{}, fmt.Errorf("could not parse MCP server URL from canary content")
	}
	payload := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"snare-prove","version":"1.0"}}}`
	return proofRecipe{
		Canary: c,
		Tier:   "medium",
		Binary: "curl",
		Command: "curl -fsS --max-time 5 -X POST " + shellQuote(serverURL) +
			" -H " + shellQuote("Content-Type: application/json") +
			" -H " + shellQuote("Accept: application/json, text/event-stream") +
			" --data " + shellQuote(payload),
		Expected: fmt.Sprintf("MCP initialize probe for %s may receive a non-MCP response, but the callback should fire", serverName),
	}, nil
}

type mcpServerConfig struct {
	URL string `json:"url"`
}

func extractMCPServerURL(content string) (string, string) {
	var cfg struct {
		MCPServers map[string]mcpServerConfig `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(content), &cfg); err != nil || len(cfg.MCPServers) == 0 {
		return "", ""
	}
	names := make([]string, 0, len(cfg.MCPServers))
	for name := range cfg.MCPServers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		url := strings.TrimSpace(cfg.MCPServers[name].URL)
		if url != "" {
			return name, url
		}
	}
	return "", ""
}

func runProofCommand(command string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Do not start a login shell: login profiles can replace PATH, causing the
	// binary checked by LookPath above to differ from the one actually run.
	cmd := exec.CommandContext(ctx, "sh", "-c", command+" >/dev/null 2>&1 || true")
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return fmt.Errorf("timed out after %s", timeout.Round(time.Second))
		}
		return err
	}
	return nil
}

func extractAWSProcProfile(content string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "[profile ") || !strings.HasSuffix(trimmed, "]") {
			continue
		}
		profile := strings.TrimSuffix(strings.TrimPrefix(trimmed, "[profile "), "]")
		if profile == "" || strings.HasSuffix(profile, "-source") {
			continue
		}
		return profile
	}
	return ""
}

func extractSSHHost(content string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "Host ") {
			continue
		}
		fields := strings.Fields(trimmed)
		if len(fields) >= 2 {
			return fields[1]
		}
	}
	return ""
}

func extractGitHost(content string) string {
	const prefix = "insteadOf = https://"
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, prefix) {
			continue
		}
		hostAndPath := strings.TrimPrefix(trimmed, prefix)
		if host, _, ok := strings.Cut(hostAndPath, "/"); ok {
			return host
		}
	}
	return ""
}

func extractNPMScope(content string) string {
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "@") {
			continue
		}
		if scope, _, ok := strings.Cut(strings.TrimPrefix(trimmed, "@"), ":registry="); ok {
			return scope
		}
	}
	return ""
}

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
