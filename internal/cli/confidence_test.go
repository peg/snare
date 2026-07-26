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
	"sync"
	"testing"
	"time"

	"github.com/peg/snare/internal/manifest"
)

type fakeTokenReg struct {
	DeviceID string
}

type fakeEvent struct {
	Token     string `json:"token"`
	IsTest    bool   `json:"is_test"`
	Timestamp string `json:"timestamp"`
	IP        string `json:"ip"`
	UserAgent string `json:"userAgent"`
	Method    string `json:"method"`
	Path      string `json:"path"`
}

type fakeSnareAPI struct {
	mu      sync.Mutex
	devices map[string]string
	tokens  map[string]fakeTokenReg
	events  map[string][]fakeEvent
	nextDev int
	server  *httptest.Server
}

func newFakeSnareAPI(t *testing.T) *fakeSnareAPI {
	t.Helper()

	f := &fakeSnareAPI{
		devices: map[string]string{},
		tokens:  map[string]fakeTokenReg{},
		events:  map[string][]fakeEvent{},
	}

	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/health" && r.Method == http.MethodGet:
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
			return
		case r.URL.Path == "/api/devices" && r.Method == http.MethodPost:
			f.handleCreateDevice(w, r)
			return
		case r.URL.Path == "/api/register" && r.Method == http.MethodPost:
			f.handleRegister(w, r)
			return
		case r.URL.Path == "/api/revoke" && r.Method == http.MethodPost:
			f.handleRevoke(w, r)
			return
		case strings.HasPrefix(r.URL.Path, "/api/events/") && r.Method == http.MethodGet:
			f.handleEvents(w, r)
			return
		case strings.HasPrefix(r.URL.Path, "/c/"):
			f.handleCallback(w, r)
			return
		default:
			http.NotFound(w, r)
			return
		}
	}))

	return f
}

func (f *fakeSnareAPI) URL() string {
	return f.server.URL
}

func (f *fakeSnareAPI) Close() {
	f.server.Close()
}

func (f *fakeSnareAPI) AddDevice(deviceID, secret string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.devices[deviceID] = secret
}

func (f *fakeSnareAPI) ClearRegistrations() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.tokens = map[string]fakeTokenReg{}
}

func (f *fakeSnareAPI) TokenCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.tokens)
}

func (f *fakeSnareAPI) HasToken(tokenID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.tokens[tokenID]
	return ok
}

func (f *fakeSnareAPI) handleCreateDevice(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DeviceSecret string `json:"device_secret"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || len(body.DeviceSecret) < 32 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}

	f.mu.Lock()
	f.nextDev++
	deviceID := fmt.Sprintf("dev-fake-%d", f.nextDev)
	f.devices[deviceID] = body.DeviceSecret
	f.mu.Unlock()

	writeJSON(w, http.StatusOK, map[string]string{
		"status":    "created",
		"device_id": deviceID,
	})
}

func (f *fakeSnareAPI) handleRegister(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TokenID    string `json:"token_id"`
		WebhookURL string `json:"webhook_url"`
		DeviceID   string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if body.TokenID == "" || body.WebhookURL == "" || body.DeviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing fields"})
		return
	}
	if !f.validateAuth(r, body.DeviceID) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid device secret"})
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if existing, ok := f.tokens[body.TokenID]; ok && existing.DeviceID != body.DeviceID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "token already registered to another device"})
		return
	}
	f.tokens[body.TokenID] = fakeTokenReg{DeviceID: body.DeviceID}
	writeJSON(w, http.StatusOK, map[string]string{"status": "registered", "token_id": body.TokenID})
}

func (f *fakeSnareAPI) handleRevoke(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TokenID  string `json:"token_id"`
		DeviceID string `json:"device_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON"})
		return
	}
	if body.TokenID == "" || body.DeviceID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing fields"})
		return
	}
	if !f.validateAuth(r, body.DeviceID) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid device secret"})
		return
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if reg, ok := f.tokens[body.TokenID]; ok && reg.DeviceID != body.DeviceID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "device_id mismatch"})
		return
	}
	delete(f.tokens, body.TokenID)
	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked", "token_id": body.TokenID})
}

func (f *fakeSnareAPI) handleEvents(w http.ResponseWriter, r *http.Request) {
	tokenID := strings.TrimPrefix(r.URL.Path, "/api/events/")
	tokenID = strings.TrimSuffix(tokenID, "/")
	if tokenID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid token"})
		return
	}

	f.mu.Lock()
	reg, ok := f.tokens[tokenID]
	events := append([]fakeEvent(nil), f.events[tokenID]...)
	f.mu.Unlock()

	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "token not registered"})
		return
	}
	if !f.validateAuth(r, reg.DeviceID) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid device secret"})
		return
	}
	if len(events) == 0 {
		writeJSON(w, http.StatusNotFound, map[string]interface{}{"token": tokenID, "events": []fakeEvent{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"token": tokenID, "events": events})
}

func (f *fakeSnareAPI) handleCallback(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/c/")
	if idx := strings.Index(token, "/"); idx >= 0 {
		token = token[:idx]
	}
	if token == "" {
		http.NotFound(w, r)
		return
	}

	e := fakeEvent{
		Token:     token,
		IsTest:    strings.HasPrefix(token, "snare-test-"),
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		IP:        "127.0.0.1",
		UserAgent: "snare-cli-test",
		Method:    r.Method,
		Path:      r.URL.Path,
	}

	f.mu.Lock()
	f.events[token] = append([]fakeEvent{e}, f.events[token]...)
	f.mu.Unlock()

	// GCP SDK token refresh expects OAuth-style JSON on POST to token_uri.
	if r.Method == http.MethodPost {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"access_token": "snare-cli-test-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, "ok")
}

func (f *fakeSnareAPI) validateAuth(r *http.Request, deviceID string) bool {
	secret := bearerSecret(r.Header.Get("Authorization"))
	if secret == "" || deviceID == "" {
		return false
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	stored, ok := f.devices[deviceID]
	if !ok {
		return false
	}
	return stored == secret
}

func bearerSecret(authHeader string) string {
	if authHeader == "" {
		return ""
	}
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return strings.TrimSpace(parts[1])
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeTestConfig(t *testing.T, home, callbackBase, deviceID, deviceSecret, webhookURL string) {
	t.Helper()
	snareDir := filepath.Join(home, ".snare")
	if err := os.MkdirAll(snareDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	cfg := map[string]string{
		"device_id":     deviceID,
		"device_secret": deviceSecret,
		"callback_base": callbackBase,
		"webhook_url":   webhookURL,
	}
	if err := os.WriteFile(filepath.Join(snareDir, "config.json"), mustMarshalJSON(t, cfg), 0600); err != nil {
		t.Fatalf("WriteFile config: %v", err)
	}
}

func writeTestManifest(t *testing.T, home string, m manifest.Manifest) {
	t.Helper()
	snareDir := filepath.Join(home, ".snare")
	if err := os.MkdirAll(snareDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(snareDir, "manifest.json"), mustMarshalJSON(t, m), 0600); err != nil {
		t.Fatalf("WriteFile manifest: %v", err)
	}
}

func runSnareWithEnv(t *testing.T, homeDir string, extraEnv map[string]string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	bin := snareBinary(t)
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "HOME="+homeDir)
	for k, v := range extraEnv {
		cmd.Env = append(cmd.Env, k+"="+v)
	}

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

func writeExecutable(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0700); err != nil {
		t.Fatalf("WriteFile executable %s: %v", path, err)
	}
}

func TestConfidenceSmokeFlow(t *testing.T) {
	home := t.TempDir()
	api := newFakeSnareAPI(t)
	defer api.Close()

	deviceID := "dev-smoke-flow"
	deviceSecret := strings.Repeat("a", 64)
	api.AddDevice(deviceID, deviceSecret)

	writeTestConfig(t, home, api.URL()+"/c", deviceID, deviceSecret, "")
	writeTestManifest(t, home, manifest.Manifest{Version: 2, DeviceID: deviceID, Canaries: []manifest.Canary{}})

	stdout, stderr, exitCode := runSnare(t, home, "arm", "--webhook", "https://hooks.example.test/snare")
	if exitCode != 0 {
		t.Fatalf("arm failed:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(stdout, "webhook test fired") {
		t.Fatalf("arm output should include webhook test, got:\n%s", stdout)
	}
	if api.TokenCount() < 4 { // precision tokens plus the callback-test token
		t.Fatalf("expected at least 4 registered tokens after arm, got %d", api.TokenCount())
	}

	stdout, stderr, exitCode = runSnare(t, home, "status")
	if exitCode != 0 {
		t.Fatalf("status failed:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(stdout, "never fired") {
		t.Fatalf("status should mark fresh precision canaries as never fired, got:\n%s", stdout)
	}

	stdout, stderr, exitCode = runSnare(t, home, "scan")
	if exitCode != 0 {
		t.Fatalf("scan failed:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(stdout, "All active canary files are present and unchanged") {
		t.Fatalf("scan should show healthy files, got:\n%s", stdout)
	}

	stdout, stderr, exitCode = runSnare(t, home, "events")
	if exitCode != 0 {
		t.Fatalf("events failed:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(stdout, "No real events recorded yet") {
		t.Fatalf("events should explain quiet first-run state, got:\n%s", stdout)
	}

	stdout, stderr, exitCode = runSnare(t, home, "doctor")
	if exitCode != 0 {
		t.Fatalf("doctor failed:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(stdout, "Token ownership") || !strings.Contains(stdout, "Events API") {
		t.Fatalf("doctor output missing confidence checks, got:\n%s", stdout)
	}

	api.ClearRegistrations()

	stdout, stderr, exitCode = runSnare(t, home, "repair")
	if exitCode != 0 {
		t.Fatalf("repair failed:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(stdout, "Repair complete") {
		t.Fatalf("repair should finish successfully, got:\n%s", stdout)
	}

	stdout, stderr, exitCode = runSnare(t, home, "disarm")
	if exitCode != 0 {
		t.Fatalf("disarm failed:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !strings.Contains(stdout, "Machine disarmed") {
		t.Fatalf("disarm output missing completion message, got:\n%s", stdout)
	}
}

func TestDoctorDetectsUnregisteredWithoutLeakingSecrets(t *testing.T) {
	home := t.TempDir()
	api := newFakeSnareAPI(t)
	defer api.Close()

	deviceID := "dev-doctor-unregistered"
	deviceSecret := strings.Repeat("b", 64)
	webhookURL := "https://hooks.example.test/very-secret-webhook"
	api.AddDevice(deviceID, deviceSecret)
	writeTestConfig(t, home, api.URL()+"/c", deviceID, deviceSecret, webhookURL)

	tokenID := "doctor-token-abc12345"
	canaryPath := filepath.Join(home, "canary-doctor.txt")
	canaryContent := "token=" + tokenID + "\n"
	if err := os.WriteFile(canaryPath, []byte(canaryContent), 0600); err != nil {
		t.Fatalf("WriteFile canary: %v", err)
	}
	writeTestManifest(t, home, manifest.Manifest{
		Version:  2,
		DeviceID: deviceID,
		Canaries: []manifest.Canary{
			{
				ID:          tokenID,
				Type:        "awsproc",
				Label:       "doctor",
				Path:        canaryPath,
				Mode:        manifest.ModeNewFile,
				Content:     canaryContent,
				ContentHash: manifest.HashContent(canaryContent),
				PlantedAt:   time.Now(),
				Active:      true,
			},
		},
	})

	stdout, stderr, exitCode := runSnare(t, home, "doctor")
	if exitCode == 0 {
		t.Fatalf("doctor should fail when active token is unregistered:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "not registered") || !strings.Contains(combined, "snare repair") {
		t.Fatalf("doctor should explain unregistered drift and repair path, got:\n%s", combined)
	}
	if strings.Contains(combined, webhookURL) {
		t.Fatalf("doctor leaked webhook URL:\n%s", combined)
	}
	if strings.Contains(combined, deviceSecret) {
		t.Fatalf("doctor leaked device secret:\n%s", combined)
	}
}

func TestRepairReRegistersTokenAndRunsTest(t *testing.T) {
	home := t.TempDir()
	api := newFakeSnareAPI(t)
	defer api.Close()

	deviceID := "dev-repair-flow"
	deviceSecret := strings.Repeat("c", 64)
	webhookURL := "https://hooks.example.test/repair-hook"
	api.AddDevice(deviceID, deviceSecret)
	writeTestConfig(t, home, api.URL()+"/c", deviceID, deviceSecret, webhookURL)

	tokenID := "repair-token-abc12345"
	canaryPath := filepath.Join(home, "canary-repair.txt")
	canaryContent := "token=" + tokenID + "\n"
	if err := os.WriteFile(canaryPath, []byte(canaryContent), 0600); err != nil {
		t.Fatalf("WriteFile canary: %v", err)
	}
	writeTestManifest(t, home, manifest.Manifest{
		Version:  2,
		DeviceID: deviceID,
		Canaries: []manifest.Canary{
			{
				ID:          tokenID,
				Type:        "ssh",
				Label:       "repair",
				Path:        canaryPath,
				Mode:        manifest.ModeNewFile,
				Content:     canaryContent,
				ContentHash: manifest.HashContent(canaryContent),
				PlantedAt:   time.Now(),
				Active:      true,
			},
		},
	})

	stdout, stderr, exitCode := runSnare(t, home, "repair")
	if exitCode != 0 {
		t.Fatalf("repair should succeed:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if !api.HasToken(tokenID) {
		t.Fatalf("repair should register active token %s", tokenID)
	}
	if !strings.Contains(stdout, "Repair complete") {
		t.Fatalf("repair output missing completion message, got:\n%s", stdout)
	}
	if strings.Contains(stdout+stderr, webhookURL) {
		t.Fatalf("repair leaked webhook URL:\n%s\n%s", stdout, stderr)
	}
	if strings.Contains(stdout+stderr, deviceSecret) {
		t.Fatalf("repair leaked device secret:\n%s\n%s", stdout, stderr)
	}
}

func TestProveShowsGuidedPrecisionCommands(t *testing.T) {
	home := t.TempDir()
	deviceID := "dev-prove-flow"
	deviceSecret := strings.Repeat("d", 64)
	writeTestConfig(t, home, "https://snare.sh/c", deviceID, deviceSecret, "https://hooks.example.test/prove")

	awsPath := filepath.Join(home, ".aws", "config")
	sshPath := filepath.Join(home, ".ssh", "config")
	kubePath := filepath.Join(home, ".kube", "proof.yaml")
	gitPath := filepath.Join(home, ".gitconfig")
	npmPath := filepath.Join(home, ".npmrc")
	for _, p := range []string{awsPath, sshPath, kubePath, gitPath, npmPath} {
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatalf("MkdirAll(%s): %v", p, err)
		}
	}

	awsContent := `
[profile prod-admin-proof]
role_arn = arn:aws:iam::123456789012:role/OrganizationAccountAccessRole
source_profile = prod-admin-proof-source

[profile prod-admin-proof-source]
credential_process = sh -c 'curl -sf https://snare.sh/c/awsproof'
`
	sshContent := `
Host proof-bastion
    HostName proof-bastion.internal
    ProxyCommand curl -sf https://snare.sh/c/sshproof -o /dev/null && nc %h %p
`
	k8sContent := "apiVersion: v1\nkind: Config\n"
	gitContent := `[url "https://snare.sh/c/gitproof/git/"]
    insteadOf = https://git.proof-internal.io/
`
	npmContent := "@proof-internal:registry=https://snare.sh/c/npmproof/\n"
	if err := os.WriteFile(awsPath, []byte(awsContent), 0600); err != nil {
		t.Fatalf("WriteFile aws: %v", err)
	}
	if err := os.WriteFile(sshPath, []byte(sshContent), 0600); err != nil {
		t.Fatalf("WriteFile ssh: %v", err)
	}
	if err := os.WriteFile(kubePath, []byte(k8sContent), 0600); err != nil {
		t.Fatalf("WriteFile kube: %v", err)
	}
	if err := os.WriteFile(gitPath, []byte(gitContent), 0600); err != nil {
		t.Fatalf("WriteFile git: %v", err)
	}
	if err := os.WriteFile(npmPath, []byte(npmContent), 0600); err != nil {
		t.Fatalf("WriteFile npm: %v", err)
	}

	writeTestManifest(t, home, manifest.Manifest{
		Version:  2,
		DeviceID: deviceID,
		Canaries: []manifest.Canary{
			{
				ID:          "prove-awsproc-token1234",
				Type:        "awsproc",
				Path:        awsPath,
				Mode:        manifest.ModeAppend,
				Content:     awsContent,
				ContentHash: manifest.HashContent(awsContent),
				PlantedAt:   time.Now(),
				Active:      true,
			},
			{
				ID:          "prove-ssh-token123456",
				Type:        "ssh",
				Path:        sshPath,
				Mode:        manifest.ModeAppend,
				Content:     sshContent,
				ContentHash: manifest.HashContent(sshContent),
				PlantedAt:   time.Now(),
				Active:      true,
			},
			{
				ID:          "prove-k8s-token123456",
				Type:        "k8s",
				Path:        kubePath,
				Mode:        manifest.ModeNewFile,
				Content:     k8sContent,
				ContentHash: manifest.HashContent(k8sContent),
				PlantedAt:   time.Now(),
				Active:      true,
			},
			{
				ID:          "prove-git-token1234567",
				Type:        "git",
				Path:        gitPath,
				Mode:        manifest.ModeAppend,
				Content:     gitContent,
				ContentHash: manifest.HashContent(gitContent),
				PlantedAt:   time.Now(),
				Active:      true,
			},
			{
				ID:          "prove-npm-token1234567",
				Type:        "npm",
				Path:        npmPath,
				Mode:        manifest.ModeAppend,
				Content:     npmContent,
				ContentHash: manifest.HashContent(npmContent),
				PlantedAt:   time.Now(),
				Active:      true,
			},
		},
	})

	stdout, stderr, exitCode := runSnare(t, home, "prove")
	if exitCode != 0 {
		t.Fatalf("prove should succeed:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	for _, want := range []string{
		"AWS_CONFIG_FILE=" + shellQuoteForTest(awsPath),
		"aws sts get-caller-identity --profile",
		"ssh -F " + shellQuoteForTest(sshPath),
		"kubectl --kubeconfig",
		"GIT_CONFIG_GLOBAL=" + shellQuoteForTest(gitPath),
		"git ls-remote",
		"npm view",
		"--userconfig " + shellQuoteForTest(npmPath),
		"Add `--run`",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("prove output missing %q:\n%s", want, stdout)
		}
	}

	stdout, stderr, exitCode = runSnare(t, home, "prove", "--format", "json")
	if exitCode != 0 {
		t.Fatalf("prove --format json should succeed:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if strings.Contains(stdout, "snare prove — precision proof flow") {
		t.Fatalf("json report should not include human proof output:\n%s", stdout)
	}
	var report struct {
		Version   int    `json:"version"`
		DeviceID  string `json:"device_id"`
		Mode      string `json:"mode"`
		RanProofs bool   `json:"ran_proofs"`
		Summary   struct {
			Total  int `json:"total"`
			Passed int `json:"passed"`
			Failed int `json:"failed"`
			NotRun int `json:"not_run"`
		} `json:"summary"`
		Proofs []struct {
			Type        string `json:"type"`
			Tier        string `json:"tier"`
			Status      string `json:"status"`
			Command     string `json:"command"`
			Trigger     string `json:"trigger"`
			NextCommand string `json:"next_command"`
		} `json:"proofs"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("json report did not parse: %v\n%s", err, stdout)
	}
	if report.Version != 1 || report.DeviceID != deviceID || report.Mode != "precision" || report.RanProofs {
		t.Fatalf("unexpected report header: %+v", report)
	}
	if report.Summary.Total != 5 || report.Summary.NotRun != 5 || report.Summary.Passed != 0 || report.Summary.Failed != 0 {
		t.Fatalf("unexpected report summary: %+v", report.Summary)
	}
	if len(report.Proofs) != 5 {
		t.Fatalf("expected 5 proof entries, got %d", len(report.Proofs))
	}
	for _, proof := range report.Proofs {
		if proof.Tier != "precision" || proof.Status != "not-run" || proof.Command == "" || proof.Trigger == "" || !strings.HasPrefix(proof.NextCommand, "snare teardown --token ") {
			t.Fatalf("unexpected proof entry: %+v", proof)
		}
	}
}

func TestProveRedactedJSONReportAndOutput(t *testing.T) {
	home := t.TempDir()
	deviceID := "dev-sensitive-proof-123"
	deviceSecret := strings.Repeat("f", 64)
	writeTestConfig(t, home, "https://snare.sh/c", deviceID, deviceSecret, "https://hooks.example.test/prove-redact")

	tokenID := "prove-sensitive-token-123456"
	label := "sensitive-prod-label"
	awsPath := filepath.Join(home, ".aws", "sensitive-config")
	if err := os.MkdirAll(filepath.Dir(awsPath), 0700); err != nil {
		t.Fatalf("MkdirAll aws dir: %v", err)
	}
	awsContent := `
[profile sensitive-prod]
role_arn = arn:aws:iam::123456789012:role/OrganizationAccountAccessRole
source_profile = sensitive-prod-source

[profile sensitive-prod-source]
credential_process = sh -c 'curl -sf https://snare.sh/c/prove-sensitive-token-123456'
`
	if err := os.WriteFile(awsPath, []byte(awsContent), 0600); err != nil {
		t.Fatalf("WriteFile aws: %v", err)
	}
	writeTestManifest(t, home, manifest.Manifest{
		Version:  2,
		DeviceID: deviceID,
		Canaries: []manifest.Canary{
			{
				ID:          tokenID,
				Type:        "awsproc",
				Label:       label,
				Path:        awsPath,
				Mode:        manifest.ModeAppend,
				Content:     awsContent,
				ContentHash: manifest.HashContent(awsContent),
				PlantedAt:   time.Now(),
				Active:      true,
			},
		},
	})

	reportPath := filepath.Join(home, "reports", "proof.json")
	stdout, stderr, exitCode := runSnare(t, home, "prove", "--format", "json", "--redact", "--output", reportPath)
	if exitCode != 0 {
		t.Fatalf("prove --format json --redact --output should succeed:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	fileData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("ReadFile report: %v", err)
	}
	if stdout != string(fileData) {
		t.Fatalf("stdout report and output artifact should match:\nstdout:\n%s\nfile:\n%s", stdout, string(fileData))
	}

	var redactedReport struct {
		DeviceID             string   `json:"device_id"`
		Redacted             bool     `json:"redacted"`
		WhatThisProves       []string `json:"what_this_proves"`
		WhatThisDoesNotProve []string `json:"what_this_does_not_prove"`
		Proofs               []struct {
			TokenID         string `json:"token_id"`
			Label           string `json:"label"`
			Path            string `json:"path"`
			Command         string `json:"command"`
			EventVisibility string `json:"event_visibility"`
			NextCommand     string `json:"next_command"`
		} `json:"proofs"`
	}
	if err := json.Unmarshal(fileData, &redactedReport); err != nil {
		t.Fatalf("redacted json report did not parse: %v\n%s", err, string(fileData))
	}
	if !redactedReport.Redacted || redactedReport.DeviceID != "<redacted-device>" {
		t.Fatalf("expected redacted device header, got %+v", redactedReport)
	}
	if len(redactedReport.WhatThisProves) == 0 || len(redactedReport.WhatThisDoesNotProve) == 0 {
		t.Fatalf("redacted report missing proof/limitation sections: %+v", redactedReport)
	}
	if len(redactedReport.Proofs) != 1 {
		t.Fatalf("expected one proof entry, got %d", len(redactedReport.Proofs))
	}
	proof := redactedReport.Proofs[0]
	if proof.TokenID != "<redacted-token-1>" || proof.Label != "<redacted-label-1>" || proof.Path != "<redacted-path>/sensitive-config" {
		t.Fatalf("unexpected redacted proof fields: %+v", proof)
	}
	if !strings.Contains(proof.Command, "<redacted-path>/sensitive-config") || !strings.Contains(proof.NextCommand, "<redacted-token-1>") {
		t.Fatalf("command fields were not redacted: %+v", proof)
	}
	if proof.EventVisibility == "" {
		t.Fatalf("expected event visibility detail: %+v", proof)
	}
	combined := stdout + string(fileData)
	for _, leaked := range []string{deviceID, tokenID, label, home, awsPath} {
		if strings.Contains(combined, leaked) {
			t.Fatalf("redacted report leaked %q:\n%s", leaked, combined)
		}
	}
}

func TestProveRunUsesManifestPathsAndObservesCallbacks(t *testing.T) {
	home := t.TempDir()
	api := newFakeSnareAPI(t)
	defer api.Close()

	deviceID := "dev-prove-run-flow"
	deviceSecret := strings.Repeat("e", 64)
	api.AddDevice(deviceID, deviceSecret)
	writeTestConfig(t, home, api.URL()+"/c", deviceID, deviceSecret, "")

	awsToken := "prove-run-awsproc-token"
	sshToken := "prove-run-ssh-token"
	k8sToken := "prove-run-k8s-token"
	awsPath := filepath.Join(home, ".aws", "snare-proof-config")
	sshPath := filepath.Join(home, ".ssh", "snare-proof-config")
	kubePath := filepath.Join(home, ".kube", "snare-proof.yaml")
	for _, p := range []string{awsPath, sshPath, kubePath} {
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatalf("MkdirAll(%s): %v", p, err)
		}
	}

	awsContent := fmt.Sprintf(`
[profile prod-admin-proof-run]
role_arn = arn:aws:iam::123456789012:role/OrganizationAccountAccessRole
source_profile = prod-admin-proof-run-source

[profile prod-admin-proof-run-source]
credential_process = sh -c 'curl -sf %s/c/%s'
`, api.URL(), awsToken)
	sshContent := fmt.Sprintf(`
Host proof-run-bastion
    HostName proof-run-bastion.internal
    ProxyCommand curl -sf %s/c/%s -o /dev/null && nc %%h %%p
`, api.URL(), sshToken)
	k8sContent := fmt.Sprintf("apiVersion: v1\nkind: Config\nclusters:\n- cluster:\n    server: %s/c/%s\n  name: proof\n", api.URL(), k8sToken)

	for path, content := range map[string]string{awsPath: awsContent, sshPath: sshContent, kubePath: k8sContent} {
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatalf("WriteFile %s: %v", path, err)
		}
	}

	writeTestManifest(t, home, manifest.Manifest{
		Version:  2,
		DeviceID: deviceID,
		Canaries: []manifest.Canary{
			{ID: awsToken, Type: "awsproc", Path: awsPath, Mode: manifest.ModeAppend, Content: awsContent, ContentHash: manifest.HashContent(awsContent), PlantedAt: time.Now(), Active: true},
			{ID: sshToken, Type: "ssh", Path: sshPath, Mode: manifest.ModeAppend, Content: sshContent, ContentHash: manifest.HashContent(sshContent), PlantedAt: time.Now(), Active: true},
			{ID: k8sToken, Type: "k8s", Path: kubePath, Mode: manifest.ModeNewFile, Content: k8sContent, ContentHash: manifest.HashContent(k8sContent), PlantedAt: time.Now(), Active: true},
		},
	})

	stdout, stderr, exitCode := runSnare(t, home, "repair")
	if exitCode != 0 {
		t.Fatalf("repair should register proof tokens:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}

	binDir := filepath.Join(home, "bin")
	if err := os.MkdirAll(binDir, 0700); err != nil {
		t.Fatalf("MkdirAll bin: %v", err)
	}
	logPath := filepath.Join(home, "proof-bin.log")
	writeExecutable(t, filepath.Join(binDir, "aws"), fmt.Sprintf(`#!/bin/sh
echo "aws AWS_CONFIG_FILE=$AWS_CONFIG_FILE $*" >> %s
url=$(grep -m1 -o 'http://[^"'"'"' ]*/c/%s' "$AWS_CONFIG_FILE")
[ -n "$url" ] && curl -sf "$url" >/dev/null 2>&1
exit 1
`, shellQuoteForShellScript(logPath), awsToken))
	writeExecutable(t, filepath.Join(binDir, "ssh"), fmt.Sprintf(`#!/bin/sh
echo "ssh $*" >> %s
config=""
while [ "$#" -gt 0 ]; do
  if [ "$1" = "-F" ]; then config="$2"; shift 2; continue; fi
  shift
done
url=$(grep -m1 -o 'http://[^ ]*/c/%s' "$config")
[ -n "$url" ] && curl -sf "$url" >/dev/null 2>&1
exit 1
`, shellQuoteForShellScript(logPath), sshToken))
	writeExecutable(t, filepath.Join(binDir, "kubectl"), fmt.Sprintf(`#!/bin/sh
echo "kubectl $*" >> %s
config=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --kubeconfig) config="$2"; shift 2 ;;
    --kubeconfig=*) config="${1#--kubeconfig=}"; shift ;;
    *) shift ;;
  esac
done
url=$(grep -m1 -o 'http://[^ ]*/c/%s' "$config")
[ -n "$url" ] && curl -sf "$url" >/dev/null 2>&1
exit 1
`, shellQuoteForShellScript(logPath), k8sToken))

	reportPath := filepath.Join(home, "proof-report.txt")
	stdout, stderr, exitCode = runSnareWithEnv(t, home, map[string]string{
		"PATH": binDir + string(os.PathListSeparator) + os.Getenv("PATH"),
	}, "prove", "--run", "--report", "--output", reportPath)
	if exitCode != 0 {
		t.Fatalf("prove --run --report --output should observe callbacks:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	for _, want := range []string{"Precision proof complete", "Proof report", "summary:   3 total, 3 passed, 0 failed, 0 not run", "visibility:", "observed:", "what this proves:", "awsproc", "ssh", "k8s"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("prove --run --report output missing %q:\n%s", want, stdout)
		}
	}
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("ReadFile report: %v", err)
	}
	reportText := string(reportData)
	for _, want := range []string{"Proof report", "summary:   3 total, 3 passed, 0 failed, 0 not run", "visibility:", "observed:", "what this does not prove:"} {
		if !strings.Contains(reportText, want) {
			t.Fatalf("output report missing %q:\n%s", want, reportText)
		}
	}

	logData, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("ReadFile log: %v", err)
	}
	logText := string(logData)
	for _, want := range []string{
		"AWS_CONFIG_FILE=" + awsPath,
		"ssh -F " + sshPath,
		"kubectl --kubeconfig " + kubePath,
	} {
		if !strings.Contains(logText, want) {
			t.Fatalf("fake binary log missing %q:\n%s", want, logText)
		}
	}
}

func TestProveMCPPackShowsAndRunsCallback(t *testing.T) {
	home := t.TempDir()
	api := newFakeSnareAPI(t)
	defer api.Close()

	deviceID := "dev-prove-mcp-pack"
	deviceSecret := strings.Repeat("f", 64)
	api.AddDevice(deviceID, deviceSecret)
	writeTestConfig(t, home, api.URL()+"/c", deviceID, deviceSecret, "")

	tokenID := "prove-run-mcp-token"
	mcpPath := filepath.Join(home, ".config", "mcp-servers.json")
	if err := os.MkdirAll(filepath.Dir(mcpPath), 0700); err != nil {
		t.Fatalf("MkdirAll mcp config: %v", err)
	}
	mcpContent := fmt.Sprintf(`{
  "mcpServers": {
    "internal-vault": {
      "url": "%s/c/%s/mcp",
      "description": "Internal vault — read-only production secrets",
      "env": {
        "VAULT_TOKEN": "not-a-real-token"
      }
    }
  }
}
`, api.URL(), tokenID)
	if err := os.WriteFile(mcpPath, []byte(mcpContent), 0600); err != nil {
		t.Fatalf("WriteFile mcp config: %v", err)
	}
	writeTestManifest(t, home, manifest.Manifest{
		Version:  2,
		DeviceID: deviceID,
		Canaries: []manifest.Canary{
			{ID: tokenID, Type: "mcp", Label: "mcp-proof", Path: mcpPath, Mode: manifest.ModeNewFile, Content: mcpContent, ContentHash: manifest.HashContent(mcpContent), PlantedAt: time.Now(), Active: true},
		},
	})

	stdout, stderr, exitCode := runSnare(t, home, "prove", "--pack", "mcp")
	if exitCode != 0 {
		t.Fatalf("prove --pack mcp should succeed:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	for _, want := range []string{"snare prove — MCP proof flow", "curl -fsS --max-time 5 -X POST", "/c/" + tokenID + "/mcp", "MCP initialize probe", "Add `--run`"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("prove --pack mcp output missing %q:\n%s", want, stdout)
		}
	}

	stdout, stderr, exitCode = runSnare(t, home, "prove", "--type", "mcp", "--format", "json")
	if exitCode != 0 {
		t.Fatalf("prove --type mcp --format json should succeed:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	var report struct {
		Mode    string `json:"mode"`
		Summary struct {
			Total  int `json:"total"`
			NotRun int `json:"not_run"`
		} `json:"summary"`
		Proofs []struct {
			Type    string `json:"type"`
			Tier    string `json:"tier"`
			Command string `json:"command"`
			Trigger string `json:"trigger"`
		} `json:"proofs"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("json report did not parse: %v\n%s", err, stdout)
	}
	if report.Mode != "mcp" || report.Summary.Total != 1 || report.Summary.NotRun != 1 || len(report.Proofs) != 1 {
		t.Fatalf("unexpected mcp report: %+v", report)
	}
	if report.Proofs[0].Type != "mcp" || report.Proofs[0].Tier != "medium" || !strings.Contains(report.Proofs[0].Command, "initialize") || !strings.Contains(report.Proofs[0].Trigger, "Streamable HTTP") {
		t.Fatalf("unexpected mcp proof entry: %+v", report.Proofs[0])
	}

	stdout, stderr, exitCode = runSnare(t, home, "repair")
	if exitCode != 0 {
		t.Fatalf("repair should register mcp token:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}

	stdout, stderr, exitCode = runSnare(t, home, "prove", "--pack", "mcp", "--run", "--report")
	if exitCode != 0 {
		t.Fatalf("prove --pack mcp --run --report should observe callback:\nstdout:\n%s\nstderr:\n%s", stdout, stderr)
	}
	for _, want := range []string{"MCP proof complete", "summary:   1 total, 1 passed, 0 failed, 0 not run", "observed:", "mcp"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("prove --pack mcp --run --report output missing %q:\n%s", want, stdout)
		}
	}
}

func shellQuoteForTest(s string) string {
	if s == "" {
		return "''"
	}
	return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'"
}

func shellQuoteForShellScript(s string) string {
	return shellQuoteForTest(s)
}
