package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
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

type precisionProofRecipe struct {
	Canary   manifest.Canary
	Command  string
	Expected string
	Binary   string
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
		fmt.Print(`snare prove — guided precision canary proof commands

Usage:
  snare prove [--type awsproc|ssh|k8s] [--run]

Default behavior:
  Prints exact safe trigger commands for active precision canaries.

With --run:
  Executes the trigger command and confirms a new real callback is readable.
`)
		return
	}

	typeFilter := flagValue(args, "--type")
	run := hasFlag(args, "--run")

	if typeFilter != "" && !isPrecisionCanaryType(typeFilter) {
		fatal(fmt.Errorf("unsupported --type %q (expected awsproc, ssh, or k8s)", typeFilter))
	}

	cfg, err := requireConfig()
	if err != nil {
		fatal(err)
	}

	m, err := manifest.Load()
	if err != nil {
		fatal(err)
	}

	targets := selectPrecisionCanaries(m.Active(), typeFilter)
	if len(targets) == 0 {
		if typeFilter != "" {
			fmt.Printf("No active %s precision canary found. Run `snare arm` or `snare arm --all`.\n", typeFilter)
		} else {
			fmt.Println("No active precision canaries found. Run `snare arm` first.")
		}
		return
	}

	recipes := make([]precisionProofRecipe, 0, len(targets))
	for _, c := range targets {
		recipe, err := buildPrecisionProofRecipe(c)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  ⚠  skipping %s (%s): %v\n", c.Type, shortTokenID(c.ID), err)
			continue
		}
		recipes = append(recipes, recipe)
	}
	if len(recipes) == 0 {
		fatal(fmt.Errorf("no runnable precision canary proofs found"))
	}

	fmt.Println()
	fmt.Println("  snare prove — precision proof flow")
	fmt.Println()
	for _, recipe := range recipes {
		fmt.Printf("  %-8s %s\n", recipe.Canary.Type, shortTokenID(recipe.Canary.ID))
		fmt.Printf("    command: %s\n", recipe.Command)
		fmt.Printf("    expect:  %s\n", recipe.Expected)
		fmt.Println()
	}

	if !run {
		fmt.Println("  These commands intentionally trigger active precision canaries.")
		fmt.Println("  Add `--run` to execute them and verify callbacks end-to-end.")
		fmt.Println()
		return
	}

	failures := 0
	for _, recipe := range recipes {
		before := probeTokenEvents(cfg, recipe.Canary.ID)
		if before.AuthFailed {
			fmt.Fprintf(os.Stderr, "  ✗ %-8s auth failed before proof — run `snare repair`\n", recipe.Canary.Type)
			failures++
			continue
		}
		if before.Unregistered {
			fmt.Fprintf(os.Stderr, "  ✗ %-8s token is unregistered — run `snare repair`\n", recipe.Canary.Type)
			failures++
			continue
		}
		if before.Unavailable {
			fmt.Fprintf(os.Stderr, "  ✗ %-8s events API unavailable — run `snare doctor`\n", recipe.Canary.Type)
			failures++
			continue
		}

		if _, err := exec.LookPath(recipe.Binary); err != nil {
			fmt.Fprintf(os.Stderr, "  ✗ %-8s missing `%s` binary; run the printed command manually when installed\n", recipe.Canary.Type, recipe.Binary)
			failures++
			continue
		}

		baseline := countEventsByKind(before.Events, false)
		fmt.Printf("  Running %-8s proof...\n", recipe.Canary.Type)
		if err := runProofCommand(recipe.Command, 15*time.Second); err != nil {
			fmt.Fprintf(os.Stderr, "    ✗ trigger command failed: %v\n", err)
			failures++
			continue
		}

		ts, err := waitForEventCountAbove(cfg, recipe.Canary.ID, baseline, false, 8*time.Second)
		if err != nil {
			fmt.Fprintf(os.Stderr, "    ✗ callback not observed: %v\n", err)
			failures++
			continue
		}
		if ts == "" {
			ts = "just now"
		}
		fmt.Printf("    ✓ callback observed at %s\n", ts)
	}

	fmt.Println()
	if failures > 0 {
		fmt.Printf("  %d proof step(s) failed. Use `snare doctor --test` and `snare repair` for diagnostics.\n\n", failures)
		os.Exit(1)
	}
	fmt.Println("  ✓ Precision proof complete. Alerts are firing as expected.")
	fmt.Println()
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
	case "awsproc", "ssh", "k8s":
		return true
	default:
		return false
	}
}

func selectPrecisionCanaries(active []manifest.Canary, typeFilter string) []manifest.Canary {
	latestByType := map[string]manifest.Canary{}
	for _, c := range active {
		if !isPrecisionCanaryType(c.Type) {
			continue
		}
		if typeFilter != "" && c.Type != typeFilter {
			continue
		}
		prev, ok := latestByType[c.Type]
		if !ok || c.PlantedAt.After(prev.PlantedAt) {
			latestByType[c.Type] = c
		}
	}

	order := []string{"awsproc", "ssh", "k8s"}
	out := make([]manifest.Canary, 0, len(order))
	for _, typ := range order {
		if c, ok := latestByType[typ]; ok {
			out = append(out, c)
		}
	}
	return out
}

func buildPrecisionProofRecipe(c manifest.Canary) (precisionProofRecipe, error) {
	switch c.Type {
	case "awsproc":
		profile := extractAWSProcProfile(c.Content)
		if profile == "" {
			return precisionProofRecipe{}, fmt.Errorf("could not parse profile name from canary content")
		}
		return precisionProofRecipe{
			Canary:   c,
			Binary:   "aws",
			Command:  "AWS_EC2_METADATA_DISABLED=true AWS_CONFIG_FILE=" + shellQuote(c.Path) + " AWS_SHARED_CREDENTIALS_FILE=/dev/null aws sts get-caller-identity --profile " + shellQuote(profile) + " --no-cli-pager",
			Expected: "AWS CLI may fail auth, but callback should fire immediately during credential resolution",
		}, nil
	case "ssh":
		host := extractSSHHost(c.Content)
		if host == "" {
			return precisionProofRecipe{}, fmt.Errorf("could not parse ssh host from canary content")
		}
		return precisionProofRecipe{
			Canary:   c,
			Binary:   "ssh",
			Command:  "ssh -F " + shellQuote(c.Path) + " -o BatchMode=yes -o ConnectTimeout=3 " + shellQuote(host) + " true",
			Expected: "SSH connection fails quickly, but ProxyCommand callback should fire",
		}, nil
	case "k8s":
		return precisionProofRecipe{
			Canary:   c,
			Binary:   "kubectl",
			Command:  "kubectl --kubeconfig " + shellQuote(c.Path) + " get namespaces --request-timeout=5s",
			Expected: "kubectl request should fail/timeout, but kube API callback should fire",
		}, nil
	default:
		return precisionProofRecipe{}, fmt.Errorf("unsupported precision type %q", c.Type)
	}
}

func runProofCommand(command string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "sh", "-lc", command+" >/dev/null 2>&1 || true")
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

func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}
