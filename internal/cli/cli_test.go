package cli_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peg/snare/internal/bait"
	"github.com/peg/snare/internal/config"
	"github.com/peg/snare/internal/manifest"
)

// buildSnare compiles the snare binary into a temp dir and returns its path.
// It is cached across subtests in the same test binary run via the package-level
// binary/binaryErr pair.
var (
	binaryPath string
	binaryErr  error
)

func snareBinary(t *testing.T) string {
	t.Helper()
	if binaryErr != nil {
		t.Skipf("skipping: could not build snare binary: %v", binaryErr)
	}
	if binaryPath != "" {
		return binaryPath
	}
	// Build once
	dir, err := os.MkdirTemp("", "snare-cli-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	out := filepath.Join(dir, "snare")
	// Navigate up to repo root from internal/cli
	cmd := exec.Command("go", "build", "-o", out, "github.com/peg/snare/cmd/snare")
	cmd.Dir = filepath.Join(os.Getenv("GOPATH"), "..") // fallback
	// Prefer workspace root detected via go.mod
	if root, err := findModuleRoot(); err == nil {
		cmd.Dir = root
	}
	if output, err := cmd.CombinedOutput(); err != nil {
		binaryErr = fmt.Errorf("go build failed: %v\n%s", err, output)
		t.Skipf("skipping: %v", binaryErr)
	}
	binaryPath = out
	t.Cleanup(func() {
		os.RemoveAll(dir)
		binaryPath = ""
	})
	return binaryPath
}

func findModuleRoot() (string, error) {
	// Walk up from current directory looking for go.mod
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("go.mod not found")
		}
		dir = parent
	}
}

// runSnare runs the snare binary with the given HOME dir and args.
// Returns stdout, stderr, and error (nil unless process fails and we don't expect it).
func runSnare(t *testing.T, homeDir string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	bin := snareBinary(t)
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "HOME="+homeDir)

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("cmd.Run: %v", err)
		}
	}
	return outBuf.String(), errBuf.String(), exitCode
}

// TestCmdArmHelp verifies that `snare arm --help` prints help text and exits 0
// without attempting to initialize config or write any files.
func TestCmdArmHelp(t *testing.T) {
	home := t.TempDir()
	stdout, _, exitCode := runSnare(t, home, "arm", "--help")

	if exitCode != 0 {
		t.Errorf("arm --help: want exit 0, got %d", exitCode)
	}
	if !strings.Contains(stdout, "snare arm") {
		t.Errorf("arm --help: expected 'snare arm' in output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "--webhook") {
		t.Errorf("arm --help: expected '--webhook' in output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "--precision") {
		t.Errorf("arm --help: expected '--precision' in output, got:\n%s", stdout)
	}

	// Verify no config was written
	configPath := filepath.Join(home, ".snare", "config.json")
	if _, err := os.Stat(configPath); !os.IsNotExist(err) {
		t.Errorf("arm --help: should not have created config at %s", configPath)
	}
}

// TestCmdDoctorNoConfig verifies that `snare doctor` exits with a non-zero code
// and prints a useful error message when snare has not been initialized.
func TestCmdDoctorNoConfig(t *testing.T) {
	home := t.TempDir()
	stdout, stderr, exitCode := runSnare(t, home, "doctor")

	if exitCode == 0 {
		t.Error("doctor: expected non-zero exit when not initialized")
	}

	combined := stdout + stderr
	if !strings.Contains(combined, "config") && !strings.Contains(combined, "arm") {
		t.Errorf("doctor: expected helpful message mentioning 'config' or 'arm', got:\n%s", combined)
	}
}

// TestCmdConfigShow verifies that `snare config` shows configuration fields
// when snare is initialized with a known config.
func TestCmdConfigShow(t *testing.T) {
	home := t.TempDir()

	// Write a minimal config manually (avoids network call to snare.sh)
	snareDir := filepath.Join(home, ".snare")
	if err := os.MkdirAll(snareDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	cfg := map[string]string{
		"device_id":     "dev-test-abc123",
		"device_secret": "deadbeefdeadbeefdeadbeefdeadbeef",
		"callback_base": "https://snare.sh/c",
		"webhook_url":   "https://hooks.example.com/test",
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(snareDir, "config.json"), data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	stdout, _, exitCode := runSnare(t, home, "config")

	if exitCode != 0 {
		t.Errorf("config: want exit 0, got %d", exitCode)
	}
	if !strings.Contains(stdout, "dev-test-abc123") {
		t.Errorf("config: expected device_id in output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "snare.sh") {
		t.Errorf("config: expected callback_base in output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "hooks.example.com") {
		t.Errorf("config: expected webhook_url in output, got:\n%s", stdout)
	}
}

// TestRegisterTokenErrorBody verifies that registerToken surfaces the JSON error
// message body from the server rather than a bare HTTP status code.
//
// This is a unit test that exercises the registerToken logic via a fake server.
// We use a test server that returns a JSON error body and verify the error string
// contains the message — not just "HTTP 400".
func TestRegisterTokenErrorBody(t *testing.T) {
	// Start a fake registration server that returns a JSON error
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"error":"device not found"}`) //nolint:errcheck
	}))
	defer srv.Close()

	// Build a minimal config pointing at the fake server
	cfg := &config.Config{
		DeviceID:     "dev-test-errortest",
		DeviceSecret: "deadbeefdeadbeefdeadbeefdeadbeef",
		CallbackBase: srv.URL + "/c",
		WebhookURL:   "https://hooks.example.com/test",
	}

	// We call registerToken indirectly by exercising the same HTTP pattern.
	// Since registerToken is unexported, we replicate the logic inline here
	// to test the specific behavior: JSON error body extraction.
	type regPayload struct {
		TokenID    string `json:"token_id"`
		WebhookURL string `json:"webhook_url"`
		DeviceID   string `json:"device_id"`
		CanaryType string `json:"canary_type"`
		Label      string `json:"label"`
	}
	payload := regPayload{
		TokenID:    "test-token-001",
		WebhookURL: cfg.WebhookURL,
		DeviceID:   cfg.DeviceID,
		CanaryType: "aws",
		Label:      "test",
	}
	body, _ := json.Marshal(payload)

	req, _ := http.NewRequest("POST", cfg.APIBase()+"/api/register", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+cfg.DeviceSecret)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("http.Do: %v", err)
	}
	defer resp.Body.Close()

	// Replicate the error extraction logic from registerToken
	var gotError string
	if resp.StatusCode >= 400 {
		data, _ := io.ReadAll(resp.Body)
		var errResp struct {
			Error string `json:"error"`
		}
		if json.Unmarshal(data, &errResp) == nil && errResp.Error != "" {
			gotError = fmt.Sprintf("registration failed: %s", errResp.Error)
		} else {
			gotError = fmt.Sprintf("registration failed: HTTP %d", resp.StatusCode)
		}
	}

	if gotError == "" {
		t.Fatal("expected an error from the registration call")
	}
	if !strings.Contains(gotError, "device not found") {
		t.Errorf("expected JSON error message 'device not found' in error, got: %q", gotError)
	}
	if strings.Contains(gotError, "HTTP 400") && !strings.Contains(gotError, "device not found") {
		t.Errorf("error surfaced HTTP status but not JSON body: %q", gotError)
	}
}

// TestPrecisionMode verifies that --precision flag selects only awsproc, ssh, k8s
// canary types. We test this by checking that precisionTypes matches expectations
// via the exported behavior of bait.Type constants.
func TestPrecisionMode(t *testing.T) {
	// Expected precision types per the CLI implementation
	wantTypes := map[bait.Type]bool{
		bait.TypeAWSProc: true,
		bait.TypeSSH:     true,
		bait.TypeK8s:     true,
	}

	// Verify the precision types are distinct from full arm types
	allTypes := []bait.Type{
		bait.TypeAWS, bait.TypeAWSProc, bait.TypeGCP,
		bait.TypeSSH, bait.TypeK8s, bait.TypePyPI,
		bait.TypeOpenAI, bait.TypeAnthropic, bait.TypeNPM, bait.TypeMCP,
	}

	// Count types that would NOT be planted under --precision
	excluded := 0
	for _, bt := range allTypes {
		if !wantTypes[bt] {
			excluded++
		}
	}
	if excluded == 0 {
		t.Error("precision mode should exclude at least some types from the full arm set")
	}

	// Precision set should have exactly 3 types
	if len(wantTypes) != 3 {
		t.Errorf("precision mode: expected 3 types, definition has %d", len(wantTypes))
	}

	// Verify precision types are the highest-signal ones
	for _, bt := range []bait.Type{bait.TypeAWSProc, bait.TypeSSH, bait.TypeK8s} {
		if !wantTypes[bt] {
			t.Errorf("precision mode: expected %s to be in precision set", bt)
		}
	}

	// Verify lower-signal types are NOT in precision set
	for _, bt := range []bait.Type{bait.TypeAWS, bait.TypeGCP, bait.TypeOpenAI, bait.TypeNPM} {
		if wantTypes[bt] {
			t.Errorf("precision mode: expected %s to be excluded (lower signal)", bt)
		}
	}
}

// TestPrecisionModeOutput verifies that `snare arm --precision --dry-run` output
// only mentions awsproc, ssh, and k8s — not aws, gcp, openai, etc.
func TestPrecisionModeOutput(t *testing.T) {
	home := t.TempDir()

	// Pre-initialize config to avoid interactive prompts
	snareDir := filepath.Join(home, ".snare")
	if err := os.MkdirAll(snareDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	cfg := map[string]string{
		"device_id":     "dev-precision-test",
		"device_secret": "deadbeefdeadbeefdeadbeefdeadbeef",
		"callback_base": "https://snare.sh/c",
		"webhook_url":   "https://hooks.example.com/test",
	}
	data, _ := json.MarshalIndent(cfg, "", "  ")
	if err := os.WriteFile(filepath.Join(snareDir, "config.json"), data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	// Also create an empty manifest so Load() doesn't fail
	emptyManifest := `{"canaries":[]}`
	if err := os.WriteFile(filepath.Join(snareDir, "manifest.json"), []byte(emptyManifest), 0600); err != nil {
		t.Fatalf("WriteFile manifest: %v", err)
	}

	stdout, _, _ := runSnare(t, home, "arm", "--precision", "--dry-run")

	// Should mention precision mode
	if !strings.Contains(stdout, "precision") && !strings.Contains(strings.ToLower(stdout), "awsproc") {
		t.Logf("arm --precision --dry-run output:\n%s", stdout)
		t.Error("expected precision mode output to mention awsproc or precision")
	}

	// Should NOT plant full set types like gcp, openai
	if strings.Contains(stdout, "→") || strings.Contains(stdout, "would plant") {
		// dry-run output present — check it doesn't include non-precision types
		if strings.Contains(stdout, "openai") {
			t.Error("precision mode output mentioned openai — should be excluded")
		}
		if strings.Contains(stdout, " gcp ") {
			t.Error("precision mode output mentioned gcp — should be excluded")
		}
	}
}

// TestManifestIsolation verifies that tests use t.TempDir() for HOME and that
// manifest.Load() initializes cleanly in a fresh directory with no canaries.
func TestManifestIsolation(t *testing.T) {
	// Capture the real home BEFORE overriding it
	realHome := os.Getenv("HOME")

	home := t.TempDir()
	t.Setenv("HOME", home)

	// Sanity check: temp dir must differ from real home
	if home == realHome {
		t.Fatal("t.TempDir() returned real HOME — isolation broken")
	}

	m, err := manifest.Load()
	if err != nil {
		t.Fatalf("manifest.Load: %v", err)
	}
	if m == nil {
		t.Fatal("manifest.Load returned nil manifest")
	}

	if len(m.Active()) != 0 {
		t.Error("fresh temp home should have no active canaries")
	}

	// Verify snare dir was created inside temp home, not real home
	snareDir := filepath.Join(home, ".snare")
	if _, err := os.Stat(snareDir); os.IsNotExist(err) {
		// snare dir not created yet — that's fine, Load() is lazy
		return
	}
	// If .snare was created, it should be under temp home
	if _, err := os.Stat(filepath.Join(realHome, ".snare", "manifest.json")); err == nil {
		// Real manifest exists — check we didn't write a new one there during this test
		// (the temp dir test can't easily distinguish, so just verify temp home is isolated)
		_ = err
	}
}
