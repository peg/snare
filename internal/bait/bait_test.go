package bait_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/peg/snare/internal/bait"
	"github.com/peg/snare/internal/manifest"
	"github.com/peg/snare/internal/token"
)

// testParams returns realistic params for a given bait type.
func testParams(t *testing.T, bt bait.Type) bait.Params {
	t.Helper()

	tokenID, err := token.NewID("test")
	if err != nil {
		t.Fatalf("token.NewID: %v", err)
	}

	p := bait.Params{
		TokenID:     tokenID,
		CallbackURL: "https://snare.sh/c/" + tokenID,
		Label:       "test",
		ProfileName: "test-us-east-1-legacy-2024",
	}

	var e error
	switch bt {
	case bait.TypeAWS:
		p.FakeKeyID, e = token.NewAWSKeyID()
		p.FakeSecret, _ = token.NewAWSSecretKey()
	case bait.TypeGCP:
		p.FakeProjID = token.NewGCPProjectID()
		p.FakeKeyID, e = token.NewGCPPrivateKeyID()
		p.FakeSecret = token.NewGCPClientID()
		p.FakePrivateKey, _ = token.NewFakeRSAPrivateKey()
	case bait.TypeGeneric:
		p.FakeToken, e = token.NewGitHubToken()
	case bait.TypeAWSProc:
		p.FakeKeyID, e = token.NewAWSKeyID()
		p.FakeSecret, _ = token.NewAWSSecretKey()
		p.FakeToken, _ = token.NewAWSSecretKey()
	case bait.TypeSSH:
		// SSH template only needs ProfileName and CallbackURL
	case bait.TypeK8s:
		p.FakeToken, e = token.NewGitHubToken()
	case bait.TypeGit:
		// Git template only needs ProfileName and CallbackURL
	case bait.TypePyPIUpload:
		p.FakeToken, e = token.NewNPMToken()
	}
	if e != nil {
		t.Fatalf("generating params for %s: %v", bt, e)
	}
	return p
}

// TestPlantNewFile verifies plant creates a new file with correct content.
func TestPlantNewFile(t *testing.T) {
	dir := t.TempDir()

	for _, bt := range []bait.Type{bait.TypeGCP, bait.TypeGeneric} {
		t.Run(string(bt), func(t *testing.T) {
			path := filepath.Join(dir, string(bt)+"-creds.json")
			params := testParams(t, bt)

			placed, err := bait.Plant(bt, params, path, false)
			if err != nil {
				t.Fatalf("Plant: %v", err)
			}

			if placed.Mode != manifest.ModeNewFile {
				t.Errorf("expected ModeNewFile, got %s", placed.Mode)
			}
			if placed.Content == "" {
				t.Error("placed.Content is empty")
			}

			// File must exist
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading planted file: %v", err)
			}

			// Content on disk must match placed.Content exactly
			if string(data) != placed.Content {
				t.Errorf("disk content does not match placed.Content\ndisk: %q\nplaced: %q",
					string(data), placed.Content)
			}

			// TokenID must be in the file
			if !strings.Contains(string(data), params.TokenID) {
				t.Error("TokenID not found in planted file")
			}

			// CallbackURL must be in the file
			if !strings.Contains(string(data), params.CallbackURL) {
				t.Error("CallbackURL not found in planted file")
			}
		})
	}
}

// TestPlantAppend verifies plant appends to existing files without corrupting them.
func TestPlantAppend(t *testing.T) {
	dir := t.TempDir()

	for _, bt := range []bait.Type{bait.TypeAWS} {
		t.Run(string(bt), func(t *testing.T) {
			path := filepath.Join(dir, string(bt)+"-existing")
			existing := "[real-profile]\naws_access_key_id = AKIAREALKEY\naws_secret_access_key = realSecret\n"

			// Write pre-existing content
			if err := os.WriteFile(path, []byte(existing), 0600); err != nil {
				t.Fatalf("setup: %v", err)
			}

			params := testParams(t, bt)
			placed, err := bait.Plant(bt, params, path, false)
			if err != nil {
				t.Fatalf("Plant: %v", err)
			}

			if placed.Mode != manifest.ModeAppend {
				t.Errorf("expected ModeAppend, got %s", placed.Mode)
			}

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("reading file: %v", err)
			}
			content := string(data)

			// Original content must still be present
			if !strings.Contains(content, "AKIAREALKEY") {
				t.Error("original content was destroyed")
			}

			// Canary must be appended
			if !strings.Contains(content, params.TokenID) {
				t.Error("canary TokenID not found after append")
			}
		})
	}
}

// TestPlantDryRun verifies dry-run does not write to disk.
func TestPlantDryRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "should-not-exist")

	params := testParams(t, bait.TypeAWS)
	placed, err := bait.Plant(bait.TypeAWS, params, path, true)
	if err != nil {
		t.Fatalf("Plant dry-run: %v", err)
	}

	if placed.Content == "" {
		t.Error("dry-run should still return Content")
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("dry-run wrote to disk — should not have")
	}
}

// TestPlantIdempotent verifies planting the same token twice is an error.
func TestPlantIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "creds")
	params := testParams(t, bait.TypeGCP)

	if _, err := bait.Plant(bait.TypeGCP, params, path, false); err != nil {
		t.Fatalf("first plant: %v", err)
	}

	_, err := bait.Plant(bait.TypeGCP, params, path, false)
	if err == nil {
		t.Error("expected error when planting same token twice, got nil")
	}
}

// TestRemoveNewFile verifies teardown deletes a new-file canary cleanly.
func TestRemoveNewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sa.json")
	params := testParams(t, bait.TypeGCP)

	placed, err := bait.Plant(bait.TypeGCP, params, path, false)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}

	c := manifest.Canary{
		ID:          params.TokenID,
		Path:        placed.Path,
		Mode:        placed.Mode,
		Content:     placed.Content,
		ContentHash: manifest.HashContent(placed.Content),
	}

	if err := bait.Remove(c, false, false); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Error("file still exists after Remove")
	}
}

func TestRemoveNewFilePrunesEmptyParents(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".config", "gcloud", "sa.json")
	params := testParams(t, bait.TypeGCP)

	placed, err := bait.Plant(bait.TypeGCP, params, path, false)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}

	c := manifest.Canary{
		ID:          params.TokenID,
		Path:        placed.Path,
		Mode:        placed.Mode,
		Content:     placed.Content,
		ContentHash: manifest.HashContent(placed.Content),
	}

	if err := bait.Remove(c, false, false); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file still exists after Remove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "gcloud")); !os.IsNotExist(err) {
		t.Fatalf("empty gcloud parent still exists after Remove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".config")); !os.IsNotExist(err) {
		t.Fatalf("empty .config parent still exists after Remove: %v", err)
	}
	if _, err := os.Stat(home); err != nil {
		t.Fatalf("home directory should not be pruned: %v", err)
	}
}

func TestRemoveNewFileKeepsNonEmptyParents(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	dir := filepath.Join(home, ".config", "gcloud")
	path := filepath.Join(dir, "sa.json")
	sibling := filepath.Join(dir, "real-account.json")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(sibling, []byte("real config"), 0600); err != nil {
		t.Fatalf("WriteFile sibling: %v", err)
	}
	params := testParams(t, bait.TypeGCP)

	placed, err := bait.Plant(bait.TypeGCP, params, path, false)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}

	c := manifest.Canary{
		ID:          params.TokenID,
		Path:        placed.Path,
		Mode:        placed.Mode,
		Content:     placed.Content,
		ContentHash: manifest.HashContent(placed.Content),
	}

	if err := bait.Remove(c, false, false); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file still exists after Remove: %v", err)
	}
	if _, err := os.Stat(sibling); err != nil {
		t.Fatalf("sibling file should be preserved: %v", err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("non-empty parent should be preserved: %v", err)
	}
}

func TestRemoveNewFileDryRunDoesNotPruneParents(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path := filepath.Join(home, ".config", "gcloud", "sa.json")
	params := testParams(t, bait.TypeGCP)

	placed, err := bait.Plant(bait.TypeGCP, params, path, false)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}

	c := manifest.Canary{
		ID:          params.TokenID,
		Path:        placed.Path,
		Mode:        placed.Mode,
		Content:     placed.Content,
		ContentHash: manifest.HashContent(placed.Content),
	}

	if err := bait.Remove(c, false, true); err != nil {
		t.Fatalf("Remove dry-run: %v", err)
	}

	if _, err := os.Stat(path); err != nil {
		t.Fatalf("file should survive dry-run Remove: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(path)); err != nil {
		t.Fatalf("parent should survive dry-run Remove: %v", err)
	}
}

// TestRemoveAppended verifies teardown surgically removes only the canary block.
func TestRemoveAppended(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials")

	existing := "[real-profile]\naws_access_key_id = AKIAREALKEY\naws_secret_access_key = realSecret123\n"
	if err := os.WriteFile(path, []byte(existing), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	params := testParams(t, bait.TypeAWS)
	placed, err := bait.Plant(bait.TypeAWS, params, path, false)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}

	c := manifest.Canary{
		ID:          params.TokenID,
		Path:        placed.Path,
		Mode:        placed.Mode,
		Content:     placed.Content,
		ContentHash: manifest.HashContent(placed.Content),
	}

	if err := bait.Remove(c, false, false); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading file after teardown: %v", err)
	}
	content := string(data)

	// Real credentials must survive
	if !strings.Contains(content, "AKIAREALKEY") {
		t.Error("real credentials were destroyed during teardown")
	}
	if !strings.Contains(content, "realSecret123") {
		t.Error("real secret was destroyed during teardown")
	}

	// Canary must be gone
	if strings.Contains(content, params.TokenID) {
		t.Error("canary TokenID still present after teardown")
	}
	if strings.Contains(content, params.CallbackURL) {
		t.Error("callback URL still present after teardown")
	}
}

// TestRemovePreservesPermissions verifies teardown doesn't change file permissions.
func TestRemovePreservesPermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials")

	existing := "[existing]\nkey = value\n"
	if err := os.WriteFile(path, []byte(existing), 0644); err != nil {
		t.Fatalf("setup: %v", err)
	}

	params := testParams(t, bait.TypeAWS)
	placed, err := bait.Plant(bait.TypeAWS, params, path, false)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}

	c := manifest.Canary{
		ID:          params.TokenID,
		Path:        placed.Path,
		Mode:        placed.Mode,
		Content:     placed.Content,
		ContentHash: manifest.HashContent(placed.Content),
	}

	if err := bait.Remove(c, false, false); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat after teardown: %v", err)
	}

	if info.Mode() != 0644 {
		t.Errorf("permissions changed: want 0644, got %o", info.Mode())
	}
}

// TestRemoveDryRun verifies dry-run teardown does not modify the file.
func TestRemoveDryRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sa.json")
	params := testParams(t, bait.TypeGCP)

	placed, err := bait.Plant(bait.TypeGCP, params, path, false)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}

	beforeData, _ := os.ReadFile(path)

	c := manifest.Canary{
		ID:          params.TokenID,
		Path:        placed.Path,
		Mode:        placed.Mode,
		Content:     placed.Content,
		ContentHash: manifest.HashContent(placed.Content),
	}

	if err := bait.Remove(c, false, true); err != nil {
		t.Fatalf("Remove dry-run: %v", err)
	}

	afterData, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("file gone after dry-run teardown: %v", err)
	}

	if string(beforeData) != string(afterData) {
		t.Error("dry-run teardown modified the file")
	}
}

// TestRemoveModifiedContent verifies teardown fails when content has changed.
func TestRemoveModifiedContent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sa.json")
	params := testParams(t, bait.TypeGCP)

	placed, err := bait.Plant(bait.TypeGCP, params, path, false)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}

	// Simulate user editing the bait file
	data, _ := os.ReadFile(path)
	modified := strings.Replace(string(data), "deploy-svc", "modified-svc", 1)
	os.WriteFile(path, []byte(modified), 0600)

	c := manifest.Canary{
		ID:          params.TokenID,
		Path:        placed.Path,
		Mode:        placed.Mode,
		Content:     placed.Content,
		ContentHash: manifest.HashContent(placed.Content),
	}

	// Should error without --force (hash mismatch for newfile)
	err = bait.Remove(c, false, false)
	if err == nil {
		t.Error("expected error on modified content without --force, got nil")
	}

	// Should succeed with --force
	if err := bait.Remove(c, true, false); err != nil {
		t.Errorf("Remove with --force failed: %v", err)
	}
}

// TestBackupCreatedOnAppend verifies that a .snare.bak file is created when appending.
func TestBackupCreatedOnAppend(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials")
	existing := "[real-profile]\naws_access_key_id = AKIAREALKEY\n"

	if err := os.WriteFile(path, []byte(existing), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	params := testParams(t, bait.TypeAWS)
	_, err := bait.Plant(bait.TypeAWS, params, path, false)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}

	// .snare.bak must exist with original content
	bakPath := bait.BackupPath(path)
	bakData, err := os.ReadFile(bakPath)
	if err != nil {
		t.Fatalf("backup file not created: %v", err)
	}
	if string(bakData) != existing {
		t.Errorf("backup content mismatch\nwant: %q\ngot:  %q", existing, string(bakData))
	}
}

// TestBackupNotCreatedForNewFile verifies no .snare.bak for new files.
func TestBackupNotCreatedForNewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sa.json")

	params := testParams(t, bait.TypeGCP)
	_, err := bait.Plant(bait.TypeGCP, params, path, false)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}

	bakPath := bait.BackupPath(path)
	if _, err := os.Stat(bakPath); !os.IsNotExist(err) {
		t.Error("backup file should not exist for new files")
	}
}

// TestBackupRemovedOnDisarm verifies .snare.bak is cleaned up after successful removal.
func TestBackupRemovedOnDisarm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials")
	existing := "[real-profile]\naws_access_key_id = AKIAREALKEY\n"

	if err := os.WriteFile(path, []byte(existing), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	params := testParams(t, bait.TypeAWS)
	placed, err := bait.Plant(bait.TypeAWS, params, path, false)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}

	// Backup must exist after plant
	bakPath := bait.BackupPath(path)
	if _, err := os.Stat(bakPath); err != nil {
		t.Fatalf("backup not found after plant: %v", err)
	}

	c := manifest.Canary{
		ID:          params.TokenID,
		Path:        placed.Path,
		Mode:        placed.Mode,
		Content:     placed.Content,
		ContentHash: manifest.HashContent(placed.Content),
	}

	if err := bait.Remove(c, false, false); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	// Backup must be gone after disarm
	if _, err := os.Stat(bakPath); !os.IsNotExist(err) {
		t.Error("backup file should be removed after successful disarm")
	}
}

// TestBackupNotCreatedOnDryRun verifies dry-run does not create .snare.bak.
func TestBackupNotCreatedOnDryRun(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials")
	existing := "[real-profile]\naws_access_key_id = AKIAREALKEY\n"

	if err := os.WriteFile(path, []byte(existing), 0600); err != nil {
		t.Fatalf("setup: %v", err)
	}

	params := testParams(t, bait.TypeAWS)
	_, err := bait.Plant(bait.TypeAWS, params, path, true)
	if err != nil {
		t.Fatalf("Plant dry-run: %v", err)
	}

	bakPath := bait.BackupPath(path)
	if _, err := os.Stat(bakPath); !os.IsNotExist(err) {
		t.Error("backup file should not be created during dry-run")
	}
}

// TestNoGiveawayStrings verifies generated credentials don't contain project identifiers.
func TestNoGiveawayStrings(t *testing.T) {
	giveaways := []string{"SNARE", "snare", "FAKE", "fake", "TEST", "canary", "CANARY"}

	for _, bt := range []bait.Type{bait.TypeAWS, bait.TypeGCP} {
		t.Run(string(bt), func(t *testing.T) {
			params := testParams(t, bt)

			// Check key material fields (not TokenID or CallbackURL which legitimately contain project names)
			fields := map[string]string{
				"FakeKeyID":  params.FakeKeyID,
				"FakeSecret": params.FakeSecret,
				"FakeToken":  params.FakeToken,
			}

			for field, value := range fields {
				if value == "" {
					continue
				}
				for _, g := range giveaways {
					if strings.Contains(value, g) {
						t.Errorf("%s contains giveaway string %q: %q", field, g, value)
					}
				}
			}
		})
	}
}

// TestAWSKeyFormat verifies generated AWS key IDs have the correct format.
func TestAWSKeyFormat(t *testing.T) {
	for i := 0; i < 20; i++ {
		keyID, err := token.NewAWSKeyID()
		if err != nil {
			t.Fatalf("NewAWSKeyID: %v", err)
		}
		if len(keyID) != 20 {
			t.Errorf("AWS key ID length: want 20, got %d (%s)", len(keyID), keyID)
		}
		if !strings.HasPrefix(keyID, "AKIA") {
			t.Errorf("AWS key ID missing AKIA prefix: %s", keyID)
		}
	}
}

// TestGitHubTokenFormat verifies generated GitHub PATs have the correct format.
func TestGitHubTokenFormat(t *testing.T) {
	for i := 0; i < 10; i++ {
		tok, err := token.NewGitHubToken()
		if err != nil {
			t.Fatalf("NewGitHubToken: %v", err)
		}
		if !strings.HasPrefix(tok, "ghp_") {
			t.Errorf("GitHub token missing ghp_ prefix: %s", tok)
		}
		if len(tok) != 40 {
			t.Errorf("GitHub token length: want 40, got %d", len(tok))
		}
	}
}

// TestStripeKeyFormat verifies generated Stripe keys have the correct format.
func TestStripeKeyFormat(t *testing.T) {
	for i := 0; i < 10; i++ {
		tok, err := token.NewStripeKey()
		if err != nil {
			t.Fatalf("NewStripeKey: %v", err)
		}
		if !strings.HasPrefix(tok, "sk_live_") {
			t.Errorf("Stripe key missing sk_live_ prefix: %s", tok)
		}
	}
}

// TestAWSProcTemplate verifies the awsproc canary template generates correct content.
func TestAWSProcTemplate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	params := testParams(t, bait.TypeAWSProc)

	placed, err := bait.Plant(bait.TypeAWSProc, params, path, false)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading planted file: %v", err)
	}
	content := string(data)

	// Must contain credential_process
	if !strings.Contains(content, "credential_process") {
		t.Error("missing credential_process in awsproc template")
	}

	// Must contain role_arn with IAM ARN prefix
	if !strings.Contains(content, "role_arn = arn:aws:iam::") {
		t.Error("missing role_arn = arn:aws:iam:: in awsproc template")
	}

	// Must contain source_profile
	if !strings.Contains(content, "source_profile") {
		t.Error("missing source_profile in awsproc template")
	}

	// Must NOT contain giveaway words (strip test-injected values first)
	stripped := content
	for _, s := range []string{params.CallbackURL, params.TokenID, params.ProfileName} {
		stripped = strings.ReplaceAll(stripped, s, "")
	}
	for _, g := range []string{"SNARE", "FAKE", "TEST", "CANARY"} {
		if strings.Contains(strings.ToUpper(stripped), g) {
			t.Errorf("template contains giveaway word %q", g)
		}
	}

	// The content must contain a curl command with the callback URL in the credential_process block
	if !strings.Contains(content, "curl") {
		t.Error("credential_process block does not contain curl")
	}
	if !strings.Contains(content, params.CallbackURL) {
		t.Error("credential_process block does not contain callback URL")
	}

	_ = placed
}

// TestSSHTemplate verifies the SSH canary template generates correct content.
func TestSSHTemplate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config")
	params := testParams(t, bait.TypeSSH)

	_, err := bait.Plant(bait.TypeSSH, params, path, false)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading planted file: %v", err)
	}
	content := string(data)

	// Must contain ProxyCommand
	if !strings.Contains(content, "ProxyCommand") {
		t.Error("missing ProxyCommand in SSH template")
	}

	// Must contain "Host "
	if !strings.Contains(content, "Host ") {
		t.Error("missing 'Host ' in SSH template")
	}

	// ProxyCommand must contain curl to the callback URL
	for _, line := range strings.Split(content, "\n") {
		if strings.Contains(line, "ProxyCommand") {
			if !strings.Contains(line, "curl") {
				t.Error("ProxyCommand does not contain curl")
			}
			if !strings.Contains(line, params.CallbackURL) {
				t.Error("ProxyCommand does not contain callback URL")
			}
		}
	}
}

// TestK8sTemplate verifies the k8s canary template generates correct content.
func TestK8sTemplate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "staging.yaml")
	params := testParams(t, bait.TypeK8s)

	_, err := bait.Plant(bait.TypeK8s, params, path, false)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading planted file: %v", err)
	}
	content := string(data)

	// Must contain server URL with https://
	if !strings.Contains(content, "server: https://") {
		// The callback URL is https://snare.sh/c/..., so server: {{.CallbackURL}} should match
		if !strings.Contains(content, "server:") {
			t.Error("missing server: in k8s template")
		}
	}

	// Must contain current-context
	if !strings.Contains(content, "current-context:") {
		t.Error("missing current-context: in k8s template")
	}

	// Validate basic YAML structure via key fields
	requiredFields := []string{"apiVersion:", "kind: Config", "clusters:", "contexts:", "users:", "token:"}
	for _, field := range requiredFields {
		if !strings.Contains(content, field) {
			t.Errorf("missing required YAML field %q", field)
		}
	}
	if strings.Contains(content, "exec:") || strings.Contains(content, "command: sh") {
		t.Error("k8s canary must not execute a credential plugin")
	}
	if !strings.Contains(content, "server: "+params.CallbackURL) {
		t.Error("k8s API server does not contain callback URL")
	}
}

func TestPyPIUploadTemplateIsNamedAndNonDefault(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".pypirc")
	params := testParams(t, bait.TypePyPIUpload)

	placed, err := bait.Plant(bait.TypePyPIUpload, params, path, false)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}
	if placed.Mode != manifest.ModeNewFile {
		t.Fatalf("mode = %s, want newfile", placed.Mode)
	}
	content := placed.Content
	if !strings.Contains(content, "[pypi]\nrepository = https://upload.pypi.org/legacy/") {
		t.Error("default publishing repository must remain the real PyPI service")
	}
	if !strings.Contains(content, "["+params.ProfileName+"]") || !strings.Contains(content, params.CallbackURL+"/pypi/upload/") {
		t.Error("named publishing repository does not contain its callback")
	}
	if !strings.Contains(content, "password = "+params.FakeToken) {
		t.Error("publishing canary is missing its fake token")
	}
}

// TestGitTemplate verifies the git canary template generates correct content.
func TestGitTemplate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".gitconfig")
	params := testParams(t, bait.TypeGit)

	_, err := bait.Plant(bait.TypeGit, params, path, false)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading planted file: %v", err)
	}
	content := string(data)

	// Must contain URL rewrite section so clone/ls-remote against the fake host hits Snare.
	if !strings.Contains(content, "[url \"") {
		t.Error("missing [url rewrite section in git template")
	}
	if !strings.Contains(content, "insteadOf = https://git.") {
		t.Error("missing https insteadOf rewrite in git template")
	}
	if !strings.Contains(content, params.CallbackURL+"/git/") {
		t.Error("git URL rewrite does not contain callback URL")
	}

	// Must contain [credential section as a fallback for direct credential lookups.
	if !strings.Contains(content, "[credential") {
		t.Error("missing [credential in git template")
	}

	// Must contain helper =
	if !strings.Contains(content, "helper =") {
		t.Error("missing helper = in git template")
	}
}

// TestTokenURLFormat verifies that for each canary type, the callback URL
// embedded in the planted file matches the token ID in the params.
func TestTokenURLFormat(t *testing.T) {
	types := []bait.Type{
		bait.TypeAWSProc,
		bait.TypeSSH,
		bait.TypeK8s,
		bait.TypeGit,
		bait.TypeNPM,
		bait.TypeAWS,
		bait.TypeGCP,
		bait.TypePyPIUpload,
		bait.TypePyPI,
		bait.TypeOpenAI,
		bait.TypeAnthropic,
		bait.TypeMCP,
		bait.TypeHuggingFace,
		bait.TypeTerraform,
		bait.TypeGeneric,
	}

	for _, bt := range types {
		t.Run(string(bt), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "canary-file")
			params := testParams(t, bt)

			placed, err := bait.Plant(bt, params, path, false)
			if err != nil {
				t.Fatalf("Plant: %v", err)
			}

			// The planted content must contain the callback URL with the token ID
			expectedURL := "https://snare.sh/c/" + params.TokenID
			if !strings.Contains(placed.Content, expectedURL) {
				t.Errorf("planted content does not contain expected callback URL %q", expectedURL)
			}

			// The callback URL in params must match the expected format
			if params.CallbackURL != expectedURL {
				t.Errorf("CallbackURL = %q, want %q", params.CallbackURL, expectedURL)
			}
		})
	}
}

func TestRetiredTypesHaveNoPlantTemplate(t *testing.T) {
	for _, bt := range []bait.Type{bait.TypeAzure, bait.TypeDocker, bait.TypeGitHub, bait.TypeStripe} {
		_, err := bait.Plant(bt, testParams(t, bt), filepath.Join(t.TempDir(), "retired"), true, true)
		if err == nil || !strings.Contains(err.Error(), "unknown bait type") {
			t.Errorf("Plant(%s) error = %v, want unknown bait type", bt, err)
		}
	}
}

// TestPlantRemoveRoundTrip is a full integration test for each canary type.
func TestPlantRemoveRoundTrip(t *testing.T) {
	types := []bait.Type{bait.TypeAWS, bait.TypeGCP, bait.TypeGeneric}

	for _, bt := range types {
		t.Run(string(bt), func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "target-file")

			params := testParams(t, bt)
			placed, err := bait.Plant(bt, params, path, false)
			if err != nil {
				t.Fatalf("Plant: %v", err)
			}

			// Verify planted
			data, _ := os.ReadFile(path)
			if !strings.Contains(string(data), params.TokenID) {
				t.Fatal("TokenID not found after plant")
			}

			c := manifest.Canary{
				ID:          params.TokenID,
				Path:        placed.Path,
				Mode:        placed.Mode,
				Content:     placed.Content,
				ContentHash: manifest.HashContent(placed.Content),
			}

			if err := bait.Remove(c, false, false); err != nil {
				t.Fatalf("Remove: %v", err)
			}

			// For newfile: file should be gone
			if placed.Mode == manifest.ModeNewFile {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Error("newfile canary still exists after teardown")
				}
			} else {
				// For append: TokenID must be gone, file must still exist
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("file gone after append teardown: %v", err)
				}
				if strings.Contains(string(data), params.TokenID) {
					t.Error("TokenID still present after append teardown")
				}
			}
		})
	}
}
