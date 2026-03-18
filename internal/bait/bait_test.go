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
	case bait.TypeGitHub:
		p.FakeToken, e = token.NewGitHubToken()
		p.ProfileName = "test-internal"
	case bait.TypeStripe:
		p.FakeToken, e = token.NewStripeKey()
		p.FakeKeyID = "abc123def456789012345678"
	case bait.TypeGeneric:
		p.FakeToken, e = token.NewGitHubToken()
	}
	if e != nil {
		t.Fatalf("generating params for %s: %v", bt, e)
	}
	return p
}

// TestPlantNewFile verifies plant creates a new file with correct content.
func TestPlantNewFile(t *testing.T) {
	dir := t.TempDir()

	for _, bt := range []bait.Type{bait.TypeGCP, bait.TypeStripe, bait.TypeGeneric} {
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

	for _, bt := range []bait.Type{bait.TypeAWS, bait.TypeGitHub} {
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
		ID:      params.TokenID,
		Path:    placed.Path,
		Mode:    placed.Mode,
		Content: placed.Content,
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

	for _, bt := range []bait.Type{bait.TypeAWS, bait.TypeGCP, bait.TypeGitHub, bait.TypeStripe} {
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

// TestPlantRemoveRoundTrip is a full integration test for each canary type.
func TestPlantRemoveRoundTrip(t *testing.T) {
	types := []bait.Type{bait.TypeAWS, bait.TypeGCP, bait.TypeGitHub, bait.TypeStripe, bait.TypeGeneric}

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
