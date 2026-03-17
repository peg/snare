package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/peg/snare/internal/cli"
	"github.com/peg/snare/internal/manifest"
)

// makeManifest creates a test manifest with the given canaries pre-populated.
func makeManifest(canaries []manifest.Canary) *manifest.Manifest {
	return &manifest.Manifest{
		Version:  2,
		DeviceID: "test-device",
		Canaries: canaries,
	}
}

// mustMarshalJSON marshals v to JSON and fatals on error.
func mustMarshalJSON(t *testing.T, v interface{}) []byte {
	t.Helper()
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return data
}

// TestScanManifestOK verifies that a canary whose file content matches the
// manifest record is reported as ScanOK.
func TestScanManifestOK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials")
	content := "[fake-profile]\naws_access_key_id = FAKE\nendpoint_url = https://snare.sh/c/tok123\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	c := manifest.Canary{
		ID:          "tok123",
		Type:        "aws",
		Path:        path,
		Mode:        manifest.ModeNewFile,
		Content:     content,
		ContentHash: manifest.HashContent(content),
		Active:      true,
		PlantedAt:   time.Now(),
	}
	m := makeManifest([]manifest.Canary{c})

	results := cli.ScanManifest(m)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != cli.ScanOK {
		t.Errorf("expected ScanOK, got %v (detail: %s)", results[0].Status, results[0].Detail)
	}
}

// TestScanManifestMissing verifies that a canary whose file does not exist
// is reported as ScanMissing.
func TestScanManifestMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nonexistent_credentials")

	c := manifest.Canary{
		ID:          "tok456",
		Type:        "aws",
		Path:        path,
		Mode:        manifest.ModeNewFile,
		Content:     "some content",
		ContentHash: manifest.HashContent("some content"),
		Active:      true,
		PlantedAt:   time.Now(),
	}
	m := makeManifest([]manifest.Canary{c})

	results := cli.ScanManifest(m)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != cli.ScanMissing {
		t.Errorf("expected ScanMissing, got %v", results[0].Status)
	}
}

// TestScanManifestModified verifies that a canary whose file content no longer
// matches the manifest hash is reported as ScanModified.
func TestScanManifestModified(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials")
	originalContent := "[fake-profile]\naws_access_key_id = FAKE\nendpoint_url = https://snare.sh/c/tok789\n"
	modifiedContent := originalContent + "\n# someone added this line\n"

	if err := os.WriteFile(path, []byte(modifiedContent), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	c := manifest.Canary{
		ID:          "tok789",
		Type:        "aws",
		Path:        path,
		Mode:        manifest.ModeNewFile,
		Content:     originalContent,
		ContentHash: manifest.HashContent(originalContent),
		Active:      true,
		PlantedAt:   time.Now(),
	}
	m := makeManifest([]manifest.Canary{c})

	results := cli.ScanManifest(m)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != cli.ScanModified {
		t.Errorf("expected ScanModified, got %v", results[0].Status)
	}
}

// TestScanManifestAppendOK verifies that an append-mode canary whose block is
// still present in the file is reported as ScanOK.
func TestScanManifestAppendOK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	planted := "\n# bastion-prod — internal bastion (legacy)\nHost bastion-prod\n    HostName bastion-prod.internal\n    ProxyCommand curl -sf https://snare.sh/c/sshtok001 -o /dev/null && nc %h %p\n"
	fileContent := "# original ssh config\nHost *\n    StrictHostKeyChecking no\n" + planted

	if err := os.WriteFile(path, []byte(fileContent), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	c := manifest.Canary{
		ID:          "sshtok001",
		Type:        "ssh",
		Path:        path,
		Mode:        manifest.ModeAppend,
		Content:     planted,
		ContentHash: manifest.HashContent(planted),
		Active:      true,
		PlantedAt:   time.Now(),
	}
	m := makeManifest([]manifest.Canary{c})

	results := cli.ScanManifest(m)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != cli.ScanOK {
		t.Errorf("expected ScanOK, got %v (detail: %s)", results[0].Status, results[0].Detail)
	}
}

// TestScanManifestAppendMissing verifies that an append-mode canary whose token
// ID is not found in the file is reported as ScanMissing.
func TestScanManifestAppendMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	// File exists but doesn't contain our canary block
	fileContent := "# original ssh config only\nHost *\n    StrictHostKeyChecking no\n"
	if err := os.WriteFile(path, []byte(fileContent), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	planted := "\n# bastion-prod\nHost bastion-prod\n    ProxyCommand curl -sf https://snare.sh/c/sshtok002 -o /dev/null && nc %h %p\n"
	c := manifest.Canary{
		ID:          "sshtok002",
		Type:        "ssh",
		Path:        path,
		Mode:        manifest.ModeAppend,
		Content:     planted,
		ContentHash: manifest.HashContent(planted),
		Active:      true,
		PlantedAt:   time.Now(),
	}
	m := makeManifest([]manifest.Canary{c})

	results := cli.ScanManifest(m)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != cli.ScanMissing {
		t.Errorf("expected ScanMissing, got %v", results[0].Status)
	}
}

// TestScanManifestAppendModified verifies that an append-mode canary whose token
// ID is present but whose exact content block has changed is ScanModified.
func TestScanManifestAppendModified(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	planted := "\n# bastion-prod\nHost bastion-prod\n    ProxyCommand curl -sf https://snare.sh/c/sshtok003 -o /dev/null && nc %h %p\n"
	// File has the token ID but not the exact original block (content was edited)
	modifiedBlock := "\n# bastion-prod\nHost bastion-prod\n    ProxyCommand curl -sf https://snare.sh/c/sshtok003 -o /dev/null && nc CHANGEDHOST %p\n"
	fileContent := "# original\n" + modifiedBlock

	if err := os.WriteFile(path, []byte(fileContent), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	c := manifest.Canary{
		ID:          "sshtok003",
		Type:        "ssh",
		Path:        path,
		Mode:        manifest.ModeAppend,
		Content:     planted,
		ContentHash: manifest.HashContent(planted),
		Active:      true,
		PlantedAt:   time.Now(),
	}
	m := makeManifest([]manifest.Canary{c})

	results := cli.ScanManifest(m)
	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	if results[0].Status != cli.ScanModified {
		t.Errorf("expected ScanModified, got %v (detail: %s)", results[0].Status, results[0].Detail)
	}
}

// TestScanManifestInactiveExcluded verifies that inactive canaries are not
// included in scan results.
func TestScanManifestInactiveExcluded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials")

	inactive := manifest.Canary{
		ID:          "tokInactive",
		Type:        "aws",
		Path:        path,
		Mode:        manifest.ModeNewFile,
		Content:     "content",
		ContentHash: manifest.HashContent("content"),
		Active:      false, // not active
		PlantedAt:   time.Now(),
	}
	m := makeManifest([]manifest.Canary{inactive})

	results := cli.ScanManifest(m)
	if len(results) != 0 {
		t.Errorf("expected 0 results for inactive canary, got %d", len(results))
	}
}

// TestScanManifestMultiple verifies mixed results in a multi-canary manifest.
func TestScanManifestMultiple(t *testing.T) {
	dir := t.TempDir()

	// OK canary
	okPath := filepath.Join(dir, "ok_file")
	okContent := "ok content with https://snare.sh/c/tokOK123\n"
	if err := os.WriteFile(okPath, []byte(okContent), 0600); err != nil {
		t.Fatalf("WriteFile ok: %v", err)
	}
	okCanary := manifest.Canary{
		ID: "tokOK123", Type: "aws", Path: okPath,
		Mode: manifest.ModeNewFile, Content: okContent,
		ContentHash: manifest.HashContent(okContent),
		Active: true, PlantedAt: time.Now(),
	}

	// Missing canary
	missingPath := filepath.Join(dir, "missing_file")
	missingCanary := manifest.Canary{
		ID: "tokMISS", Type: "gcp", Path: missingPath,
		Mode: manifest.ModeNewFile, Content: "gcp content",
		ContentHash: manifest.HashContent("gcp content"),
		Active: true, PlantedAt: time.Now(),
	}

	// Modified canary
	modPath := filepath.Join(dir, "mod_file")
	origContent := "original https://snare.sh/c/tokMOD456\n"
	if err := os.WriteFile(modPath, []byte(origContent+"extra line\n"), 0600); err != nil {
		t.Fatalf("WriteFile mod: %v", err)
	}
	modCanary := manifest.Canary{
		ID: "tokMOD456", Type: "openai", Path: modPath,
		Mode: manifest.ModeNewFile, Content: origContent,
		ContentHash: manifest.HashContent(origContent),
		Active: true, PlantedAt: time.Now(),
	}

	m := makeManifest([]manifest.Canary{okCanary, missingCanary, modCanary})
	results := cli.ScanManifest(m)

	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}

	statusOf := func(id string) cli.ScanStatus {
		for _, r := range results {
			if r.Canary.ID == id {
				return r.Status
			}
		}
		t.Fatalf("result for %s not found", id)
		return -1
	}

	if got := statusOf("tokOK123"); got != cli.ScanOK {
		t.Errorf("tokOK123: expected ScanOK, got %v", got)
	}
	if got := statusOf("tokMISS"); got != cli.ScanMissing {
		t.Errorf("tokMISS: expected ScanMissing, got %v", got)
	}
	if got := statusOf("tokMOD456"); got != cli.ScanModified {
		t.Errorf("tokMOD456: expected ScanModified, got %v", got)
	}
}

// TestScanForOrphans verifies that files containing snare.sh/c/ URLs without
// a manifest entry are reported as orphans.
func TestScanForOrphans(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Create a fake .aws/credentials with an orphaned canary URL
	awsDir := filepath.Join(home, ".aws")
	if err := os.MkdirAll(awsDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	orphanContent := "\n[orphan-profile]\naws_access_key_id = FAKEKEY\nendpoint_url = https://snare.sh/c/orphan-tok-999\n"
	if err := os.WriteFile(filepath.Join(awsDir, "credentials"), []byte(orphanContent), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Empty manifest — no active canaries
	m := makeManifest(nil)

	orphans, err := cli.ScanForOrphans(m)
	if err != nil {
		t.Fatalf("ScanForOrphans: %v", err)
	}

	if len(orphans) == 0 {
		t.Error("expected at least one orphan, got none")
	}

	found := false
	for _, o := range orphans {
		if strings.Contains(o.Path, ".aws") {
			found = true
			if !strings.Contains(o.URL, "snare.sh/c/") {
				t.Errorf("orphan URL should contain snare.sh/c/, got: %q", o.URL)
			}
		}
	}
	if !found {
		t.Error("expected orphan in .aws/credentials, not found")
	}
}

// TestScanForOrphansIgnoresCovered verifies that files with known active canary
// entries are NOT reported as orphans.
func TestScanForOrphansIgnoresCovered(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	awsDir := filepath.Join(home, ".aws")
	if err := os.MkdirAll(awsDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	credPath := filepath.Join(awsDir, "credentials")
	content := "\n[covered-profile]\naws_access_key_id = FAKE\nendpoint_url = https://snare.sh/c/covered-tok-001\n"
	if err := os.WriteFile(credPath, []byte(content), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Active canary that covers this file/token
	c := manifest.Canary{
		ID:          "covered-tok-001",
		Type:        "aws",
		Path:        credPath,
		Mode:        manifest.ModeNewFile,
		Content:     content,
		ContentHash: manifest.HashContent(content),
		Active:      true,
		PlantedAt:   time.Now(),
	}
	m := makeManifest([]manifest.Canary{c})

	orphans, err := cli.ScanForOrphans(m)
	if err != nil {
		t.Fatalf("ScanForOrphans: %v", err)
	}

	for _, o := range orphans {
		if o.Path == credPath {
			t.Errorf("covered canary at %s incorrectly reported as orphan", credPath)
		}
	}
}

// TestCmdScanExitZeroAllOK verifies that `snare scan` exits 0 when all canaries are OK.
func TestCmdScanExitZeroAllOK(t *testing.T) {
	home := t.TempDir()

	snareDir := filepath.Join(home, ".snare")
	if err := os.MkdirAll(snareDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	fakePath := filepath.Join(home, "fake_creds")
	fakeContent := "[profile]\nendpoint_url = https://snare.sh/c/scanok001\n"
	if err := os.WriteFile(fakePath, []byte(fakeContent), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	m := manifest.Manifest{
		Version:  2,
		DeviceID: "test-device",
		Canaries: []manifest.Canary{
			{
				ID:          "scanok001",
				Type:        "aws",
				Path:        fakePath,
				Mode:        manifest.ModeNewFile,
				Content:     fakeContent,
				ContentHash: manifest.HashContent(fakeContent),
				Active:      true,
				PlantedAt:   time.Now(),
			},
		},
	}
	manifestData := mustMarshalJSON(t, m)
	if err := os.WriteFile(filepath.Join(snareDir, "manifest.json"), manifestData, 0600); err != nil {
		t.Fatalf("WriteFile manifest: %v", err)
	}

	stdout, _, exitCode := runSnare(t, home, "scan")
	if exitCode != 0 {
		t.Errorf("scan: want exit 0 when all OK, got %d\nstdout: %s", exitCode, stdout)
	}
	if !strings.Contains(stdout, "✓") {
		t.Errorf("scan: expected ✓ in output, got:\n%s", stdout)
	}
	if !strings.Contains(stdout, "OK") {
		t.Errorf("scan: expected 'OK' in summary, got:\n%s", stdout)
	}
}

// TestCmdScanExitNonZeroMissing verifies that `snare scan` exits non-zero when
// a canary file is missing.
func TestCmdScanExitNonZeroMissing(t *testing.T) {
	home := t.TempDir()

	snareDir := filepath.Join(home, ".snare")
	if err := os.MkdirAll(snareDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	missingPath := filepath.Join(home, "nonexistent_creds")
	m := manifest.Manifest{
		Version:  2,
		DeviceID: "test-device",
		Canaries: []manifest.Canary{
			{
				ID:          "scanmiss001",
				Type:        "aws",
				Path:        missingPath,
				Mode:        manifest.ModeNewFile,
				Content:     "content",
				ContentHash: manifest.HashContent("content"),
				Active:      true,
				PlantedAt:   time.Now(),
			},
		},
	}
	manifestData := mustMarshalJSON(t, m)
	if err := os.WriteFile(filepath.Join(snareDir, "manifest.json"), manifestData, 0600); err != nil {
		t.Fatalf("WriteFile manifest: %v", err)
	}

	stdout, _, exitCode := runSnare(t, home, "scan")
	if exitCode == 0 {
		t.Errorf("scan: want non-zero exit when canary missing, got 0\nstdout: %s", stdout)
	}
	if !strings.Contains(stdout, "✗") {
		t.Errorf("scan: expected ✗ in output for missing canary, got:\n%s", stdout)
	}
}

// TestCmdScanExitNonZeroModified verifies that `snare scan` exits non-zero when
// a canary file has been modified.
func TestCmdScanExitNonZeroModified(t *testing.T) {
	home := t.TempDir()

	snareDir := filepath.Join(home, ".snare")
	if err := os.MkdirAll(snareDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	fakePath := filepath.Join(home, "modified_creds")
	originalContent := "[profile]\nendpoint_url = https://snare.sh/c/scanmod001\n"
	if err := os.WriteFile(fakePath, []byte(originalContent+"extra line\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	m := manifest.Manifest{
		Version:  2,
		DeviceID: "test-device",
		Canaries: []manifest.Canary{
			{
				ID:          "scanmod001",
				Type:        "aws",
				Path:        fakePath,
				Mode:        manifest.ModeNewFile,
				Content:     originalContent,
				ContentHash: manifest.HashContent(originalContent),
				Active:      true,
				PlantedAt:   time.Now(),
			},
		},
	}
	manifestData := mustMarshalJSON(t, m)
	if err := os.WriteFile(filepath.Join(snareDir, "manifest.json"), manifestData, 0600); err != nil {
		t.Fatalf("WriteFile manifest: %v", err)
	}

	stdout, _, exitCode := runSnare(t, home, "scan")
	if exitCode == 0 {
		t.Errorf("scan: want non-zero exit when canary modified, got 0\nstdout: %s", stdout)
	}
	if !strings.Contains(stdout, "⚠") {
		t.Errorf("scan: expected ⚠ in output for modified canary, got:\n%s", stdout)
	}
}

// TestCmdScanNoCanaries verifies that `snare scan` exits 0 with a helpful message
// when no canaries are active.
func TestCmdScanNoCanaries(t *testing.T) {
	home := t.TempDir()

	snareDir := filepath.Join(home, ".snare")
	if err := os.MkdirAll(snareDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	emptyManifest := `{"version":2,"device_id":"test","canaries":[]}`
	if err := os.WriteFile(filepath.Join(snareDir, "manifest.json"), []byte(emptyManifest), 0600); err != nil {
		t.Fatalf("WriteFile manifest: %v", err)
	}

	stdout, _, exitCode := runSnare(t, home, "scan")
	if exitCode != 0 {
		t.Errorf("scan: want exit 0 with no canaries, got %d", exitCode)
	}
	if !strings.Contains(stdout, "No active canaries") && !strings.Contains(stdout, "snare arm") {
		t.Errorf("scan: expected helpful message, got:\n%s", stdout)
	}
}

// TestCmdScanInUsage verifies that `snare scan` appears in the usage output.
func TestCmdScanInUsage(t *testing.T) {
	home := t.TempDir()
	stdout, _, exitCode := runSnare(t, home, "--help")
	if exitCode != 0 {
		t.Errorf("--help: want exit 0, got %d", exitCode)
	}
	if !strings.Contains(stdout, "scan") {
		t.Errorf("--help: expected 'scan' in usage output, got:\n%s", stdout)
	}
}
