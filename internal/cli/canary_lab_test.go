package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/peg/snare/internal/manifest"
)

func TestCanaryLabProofsPrecisionAndHigh(t *testing.T) {
	home := t.TempDir()
	api := newFakeSnareAPI(t)
	defer api.Close()

	deviceID := "dev-canary-lab"
	deviceSecret := strings.Repeat("f", 64)
	api.AddDevice(deviceID, deviceSecret)

	writeTestConfig(t, home, api.URL()+"/c", deviceID, deviceSecret, "")
	writeTestManifest(t, home, manifest.Manifest{
		Version:  2,
		DeviceID: deviceID,
		Canaries: []manifest.Canary{},
	})

	for _, canaryType := range []string{"awsproc", "k8s", "git", "gcp", "npm"} {
		stdout, stderr, exitCode := runSnare(t, home, "plant", "--type", canaryType, "--label", "canary-lab")
		if exitCode != 0 {
			t.Fatalf("plant --type %s failed:\nstdout:\n%s\nstderr:\n%s", canaryType, stdout, stderr)
		}
	}

	m := loadManifestForHome(t, home)

	t.Run("awsproc", func(t *testing.T) {
		requireBinary(t, "aws")
		c := mustLatestActiveCanaryByType(t, m, "awsproc")
		assertPathUnderHome(t, c.Path, home)

		profile := extractAWSProcProfileFromContent(c.Content)
		if profile == "" {
			t.Fatalf("could not extract aws profile from planted content:\n%s", c.Content)
		}

		baseline := realEventCount(api, c.ID)
		env := localOnlyEnv(home)
		env["AWS_EC2_METADATA_DISABLED"] = "true"
		env["AWS_CONFIG_FILE"] = c.Path
		env["AWS_SHARED_CREDENTIALS_FILE"] = "/dev/null"
		env["AWS_DEFAULT_REGION"] = "us-east-1"
		stdout, stderr, _ := runCommandAllowFailure(t, 20*time.Second, env, "aws", "sts", "get-caller-identity",
			"--profile", profile,
			"--endpoint-url", api.URL(),
			"--region", "us-east-1",
			"--no-cli-pager",
		)

		event, ok := waitForRealEvent(api, c.ID, baseline, 8*time.Second)
		if !ok {
			t.Fatalf("awsproc callback not observed for token %s (profile %s, path %s)\nstdout:\n%s\nstderr:\n%s", c.ID, profile, c.Path, stdout, stderr)
		}
		if !strings.HasPrefix(event.Path, "/c/"+c.ID) {
			t.Fatalf("awsproc callback path %q does not match token %s", event.Path, c.ID)
		}
	})

	t.Run("k8s", func(t *testing.T) {
		requireBinary(t, "kubectl")
		c := mustLatestActiveCanaryByType(t, m, "k8s")
		assertPathUnderHome(t, c.Path, home)
		forceKubeServerHTTPSDeadEndpoint(t, c.Path, api.URL()+"/c/"+c.ID)

		baseline := realEventCount(api, c.ID)
		stdout, stderr, _ := runCommandAllowFailure(t, 20*time.Second, localOnlyEnv(home), "kubectl",
			"--kubeconfig", c.Path,
			"get", "namespaces",
			"--request-timeout=5s",
		)

		event, ok := waitForRealEvent(api, c.ID, baseline, 8*time.Second)
		if !ok {
			t.Fatalf("k8s exec callback not observed for token %s (kubeconfig %s)\nstdout:\n%s\nstderr:\n%s", c.ID, c.Path, stdout, stderr)
		}
		if !strings.HasPrefix(event.Path, "/c/"+c.ID) {
			t.Fatalf("k8s callback path %q does not match token %s", event.Path, c.ID)
		}
		if !strings.Contains(event.Path, "/exec") {
			t.Fatalf("k8s callback path %q does not prove exec credential plugin fired", event.Path)
		}
	})

	t.Run("git", func(t *testing.T) {
		requireBinary(t, "git")
		c := mustLatestActiveCanaryByType(t, m, "git")
		assertPathUnderHome(t, c.Path, home)

		host := extractGitHostFromContent(c.Content)
		if host == "" {
			t.Fatalf("could not extract git host from planted content:\n%s", c.Content)
		}
		targetURL := "https://" + host + "/snare-proof/repo"

		baseline := realEventCount(api, c.ID)
		env := localOnlyEnv(home)
		env["GIT_CONFIG_GLOBAL"] = c.Path
		env["GIT_CONFIG_NOSYSTEM"] = "1"
		env["GIT_TERMINAL_PROMPT"] = "0"
		// If the url.insteadOf rewrite ever regresses, trap the fake external host
		// through a dead local proxy instead of leaking a DNS/network request.
		env["HTTPS_PROXY"] = "http://127.0.0.1:9"
		stdout, stderr, _ := runCommandAllowFailure(t, 20*time.Second, env, "git", "ls-remote", targetURL)

		event, ok := waitForRealEvent(api, c.ID, baseline, 8*time.Second)
		if !ok {
			t.Fatalf("git callback not observed for token %s (host %s)\nstdout:\n%s\nstderr:\n%s", c.ID, host, stdout, stderr)
		}
		if !strings.HasPrefix(event.Path, "/c/"+c.ID) {
			t.Fatalf("git callback path %q does not match token %s", event.Path, c.ID)
		}
		if !strings.Contains(event.Path, "/git/") {
			t.Fatalf("git callback path %q does not include git rewrite segment", event.Path)
		}
	})

	t.Run("gcp", func(t *testing.T) {
		requirePythonGoogleAuth(t, home)
		c := mustLatestActiveCanaryByType(t, m, "gcp")
		assertPathUnderHome(t, c.Path, home)

		const refreshScript = `
from google.oauth2 import service_account
from google.auth.transport.requests import Request
import sys

creds = service_account.Credentials.from_service_account_file(
    sys.argv[1],
    scopes=["https://www.googleapis.com/auth/cloud-platform"],
)
creds.refresh(Request())
`

		baseline := realEventCount(api, c.ID)
		stdout, stderr, _ := runCommandAllowFailure(t, 20*time.Second, localOnlyEnv(home), "python3", "-c", refreshScript, c.Path)

		event, ok := waitForRealEvent(api, c.ID, baseline, 8*time.Second)
		if !ok {
			t.Fatalf("gcp callback not observed for token %s (credentials %s)\nstdout:\n%s\nstderr:\n%s", c.ID, c.Path, stdout, stderr)
		}
		if !strings.HasPrefix(event.Path, "/c/"+c.ID) {
			t.Fatalf("gcp callback path %q does not match token %s", event.Path, c.ID)
		}
		if event.Method != "POST" {
			t.Fatalf("gcp callback should use POST token refresh, got method %q", event.Method)
		}
	})

	t.Run("npm", func(t *testing.T) {
		requireBinary(t, "npm")
		c := mustLatestActiveCanaryByType(t, m, "npm")
		assertPathUnderHome(t, c.Path, home)

		scope := extractNPMScopeFromContent(c.Content)
		if scope == "" {
			t.Fatalf("could not extract npm scope from planted content:\n%s", c.Content)
		}
		pkg := fmt.Sprintf("@%s/canary-lab-proof-does-not-exist", scope)

		baseline := realEventCount(api, c.ID)
		env := localOnlyEnv(home)
		// If scoped-registry handling regresses, npm falls back to this dead local
		// default instead of registry.npmjs.org.
		env["NPM_CONFIG_REGISTRY"] = "http://127.0.0.1:9/"
		stdout, stderr, _ := runCommandAllowFailure(t, 20*time.Second, env, "npm", "view", pkg, "version",
			"--userconfig", c.Path,
			"--loglevel=silent",
			"--fetch-retries=0",
			"--fetch-retry-mintimeout=1",
			"--fetch-retry-maxtimeout=1",
		)

		event, ok := waitForRealEvent(api, c.ID, baseline, 8*time.Second)
		if !ok {
			t.Fatalf("npm callback not observed for token %s (scope %s, userconfig %s)\nstdout:\n%s\nstderr:\n%s", c.ID, scope, c.Path, stdout, stderr)
		}
		if !strings.HasPrefix(event.Path, "/c/"+c.ID) {
			t.Fatalf("npm callback path %q does not match token %s", event.Path, c.ID)
		}
	})
}

func forceKubeServerHTTPSDeadEndpoint(t *testing.T, kubeconfigPath, plantedCallbackURL string) {
	t.Helper()
	data, err := os.ReadFile(kubeconfigPath)
	if err != nil {
		t.Fatalf("ReadFile kubeconfig: %v", err)
	}
	content := string(data)
	needle := "server: " + plantedCallbackURL
	if !strings.Contains(content, needle) {
		t.Fatalf("kubeconfig does not contain expected planted server URL %q", plantedCallbackURL)
	}
	content = strings.Replace(content, needle, "server: https://127.0.0.1:9", 1)
	if err := os.WriteFile(kubeconfigPath, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile kubeconfig: %v", err)
	}
}

func localOnlyEnv(home string) map[string]string {
	return map[string]string{
		"HOME":        home,
		"NO_PROXY":    "127.0.0.1,localhost",
		"no_proxy":    "127.0.0.1,localhost",
		"HTTP_PROXY":  "",
		"http_proxy":  "",
		"HTTPS_PROXY": "",
		"https_proxy": "",
		"ALL_PROXY":   "",
		"all_proxy":   "",
	}
}

func loadManifestForHome(t *testing.T, home string) manifest.Manifest {
	t.Helper()
	path := filepath.Join(home, ".snare", "manifest.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile manifest: %v", err)
	}
	var m manifest.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("Unmarshal manifest: %v", err)
	}
	return m
}

func mustLatestActiveCanaryByType(t *testing.T, m manifest.Manifest, canaryType string) manifest.Canary {
	t.Helper()
	var chosen manifest.Canary
	found := false
	for _, c := range m.Canaries {
		if !c.Active || c.Type != canaryType {
			continue
		}
		if !found || c.PlantedAt.After(chosen.PlantedAt) {
			chosen = c
			found = true
		}
	}
	if !found {
		t.Fatalf("no active canary of type %s found in manifest", canaryType)
	}
	return chosen
}

func assertPathUnderHome(t *testing.T, path, home string) {
	t.Helper()
	rel, err := filepath.Rel(home, path)
	if err != nil {
		t.Fatalf("filepath.Rel(%q, %q): %v", home, path, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		t.Fatalf("path %q is outside temp HOME %q", path, home)
	}
}

func requireBinary(t *testing.T, binary string) {
	t.Helper()
	if _, err := exec.LookPath(binary); err != nil {
		t.Skipf("canary lab proof skipped: required binary %q not found: %v", binary, err)
	}
}

func requirePythonGoogleAuth(t *testing.T, home string) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skipf("canary lab gcp proof skipped: python3 not found: %v", err)
	}
	cmd := exec.Command("python3", "-c", "import google.oauth2.service_account, google.auth.transport.requests")
	cmd.Env = mergeEnv(os.Environ(), localOnlyEnv(home))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("canary lab gcp proof skipped: python google-auth unavailable: %v (%s)", err, strings.TrimSpace(string(out)))
	}
}

func runCommandAllowFailure(t *testing.T, timeout time.Duration, env map[string]string, name string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = mergeEnv(os.Environ(), env)

	var outBuf, errBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			t.Fatalf("%s timed out after %s", name, timeout)
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("%s run failed: %v", name, err)
		}
	}

	return outBuf.String(), errBuf.String(), exitCode
}

func mergeEnv(base []string, overrides map[string]string) []string {
	out := make([]string, 0, len(base)+len(overrides))
	seen := map[string]bool{}
	for _, entry := range base {
		key, _, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		if _, replacing := overrides[key]; replacing || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, entry)
	}
	for k, v := range overrides {
		out = append(out, k+"="+v)
	}
	return out
}

func realEventCount(api *fakeSnareAPI, tokenID string) int {
	api.mu.Lock()
	defer api.mu.Unlock()
	n := 0
	for _, e := range api.events[tokenID] {
		if !e.IsTest {
			n++
		}
	}
	return n
}

func waitForRealEvent(api *fakeSnareAPI, tokenID string, baseline int, timeout time.Duration) (fakeEvent, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		api.mu.Lock()
		events := append([]fakeEvent(nil), api.events[tokenID]...)
		api.mu.Unlock()

		realCount := 0
		for _, e := range events {
			if e.IsTest {
				continue
			}
			realCount++
			if realCount > baseline {
				return e, true
			}
		}
		time.Sleep(150 * time.Millisecond)
	}
	return fakeEvent{}, false
}

func extractAWSProcProfileFromContent(content string) string {
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

var gitHostPattern = regexp.MustCompile(`(?m)^\s*insteadOf = https://([^/]+)/\s*$`)

func extractGitHostFromContent(content string) string {
	m := gitHostPattern.FindStringSubmatch(content)
	if len(m) != 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

var npmScopePattern = regexp.MustCompile(`(?m)^@([^:\s]+):registry=`)

func extractNPMScopeFromContent(content string) string {
	m := npmScopePattern.FindStringSubmatch(content)
	if len(m) != 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}
