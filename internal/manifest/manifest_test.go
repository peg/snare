package manifest_test

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/peg/snare/internal/manifest"
)

func tempManifest(t *testing.T) (*manifest.Manifest, string) {
	t.Helper()
	dir := t.TempDir()
	// Override home dir for this test
	t.Setenv("HOME", dir)
	m, err := manifest.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return m, dir
}

func sampleCanary(id string) manifest.Canary {
	return manifest.Canary{
		ID:          id,
		Type:        "aws",
		Path:        "/home/user/.aws/credentials",
		Mode:        manifest.ModeAppend,
		Content:     "[fake-profile]\nkey = value\n",
		ContentHash: manifest.HashContent("[fake-profile]\nkey = value\n"),
		CallbackURL: "https://snare.sh/c/" + id,
		PlantedAt:   time.Now(),
		Active:      true,
	}
}

func TestLoadEmpty(t *testing.T) {
	m, _ := tempManifest(t)
	if len(m.Active()) != 0 {
		t.Error("fresh manifest should have no active canaries")
	}
}

func TestAddAndActive(t *testing.T) {
	m, _ := tempManifest(t)

	c := sampleCanary("token-001")
	if err := m.Add(c); err != nil {
		t.Fatalf("Add: %v", err)
	}

	active := m.Active()
	if len(active) != 1 {
		t.Fatalf("expected 1 active canary, got %d", len(active))
	}
	if active[0].ID != "token-001" {
		t.Errorf("wrong ID: %s", active[0].ID)
	}
}

func TestFindByID(t *testing.T) {
	m, _ := tempManifest(t)
	m.Add(sampleCanary("aaa"))
	m.Add(sampleCanary("bbb"))

	if c := m.FindByID("aaa"); c == nil {
		t.Error("FindByID returned nil for existing ID")
	}
	if c := m.FindByID("zzz"); c != nil {
		t.Error("FindByID returned non-nil for missing ID")
	}
}

func TestDeactivate(t *testing.T) {
	m, _ := tempManifest(t)
	m.Add(sampleCanary("tok1"))

	if err := m.Deactivate("tok1", "teardown"); err != nil {
		t.Fatalf("Deactivate: %v", err)
	}

	if len(m.Active()) != 0 {
		t.Error("deactivated canary still showing as active")
	}

	c := m.FindByID("tok1")
	if c.InactiveReason != "teardown" {
		t.Errorf("wrong InactiveReason: %s", c.InactiveReason)
	}
	if c.InactiveAt == nil {
		t.Error("InactiveAt should be set after deactivation")
	}
}

func TestRemove(t *testing.T) {
	m, _ := tempManifest(t)
	m.Add(sampleCanary("remove-me"))
	m.Add(sampleCanary("keep-me"))

	if err := m.Remove("remove-me"); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	if m.FindByID("remove-me") != nil {
		t.Error("removed canary still in manifest")
	}
	if m.FindByID("keep-me") == nil {
		t.Error("keep-me canary was incorrectly removed")
	}
}

func TestRemoveNotFound(t *testing.T) {
	m, _ := tempManifest(t)
	if err := m.Remove("nonexistent"); err == nil {
		t.Error("expected error removing nonexistent canary")
	}
}

func TestTransactionalPending(t *testing.T) {
	m, _ := tempManifest(t)

	c := sampleCanary("pending-tok")
	if err := m.AddPending(c); err != nil {
		t.Fatalf("AddPending: %v", err)
	}

	// Should not appear in Active()
	if len(m.Active()) != 0 {
		t.Error("pending canary should not be in Active()")
	}

	// Should appear in Pending()
	pending := m.Pending()
	if len(pending) != 1 || pending[0].ID != "pending-tok" {
		t.Errorf("expected 1 pending canary, got %v", pending)
	}

	// Activate it
	if err := m.Activate("pending-tok"); err != nil {
		t.Fatalf("Activate: %v", err)
	}

	if len(m.Active()) != 1 {
		t.Error("activated canary should be in Active()")
	}
	if len(m.Pending()) != 0 {
		t.Error("pending list should be empty after Activate()")
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	m, dir := tempManifest(t)

	c := sampleCanary("persist-me")
	m.Add(c)

	// Reload from disk
	m2, err := manifest.Load()
	if err != nil {
		t.Fatalf("Load after Save: %v", err)
	}

	loaded := m2.FindByID("persist-me")
	if loaded == nil {
		t.Fatal("canary not found after reload")
	}
	if loaded.ContentHash != c.ContentHash {
		t.Errorf("ContentHash mismatch after reload")
	}
	if loaded.Content != c.Content {
		t.Errorf("Content mismatch after reload")
	}

	// Verify manifest file exists with correct permissions
	manifestPath := filepath.Join(dir, ".snare", "manifest.json")
	info, err := os.Stat(manifestPath)
	if err != nil {
		t.Fatalf("manifest file not found: %v", err)
	}
	if info.Mode() != 0600 {
		t.Errorf("manifest permissions: want 0600, got %o", info.Mode())
	}
}

func TestAtomicWrite(t *testing.T) {
	m, dir := tempManifest(t)
	m.Add(sampleCanary("atomic-test"))

	// No .tmp file should remain after Save
	tmpPath := filepath.Join(dir, ".snare", "manifest.json.tmp")
	if _, err := os.Stat(tmpPath); !os.IsNotExist(err) {
		t.Error("manifest.json.tmp still exists after atomic save")
	}
}

func TestHashContent(t *testing.T) {
	h1 := manifest.HashContent("hello world")
	h2 := manifest.HashContent("hello world")
	h3 := manifest.HashContent("different")

	if h1 != h2 {
		t.Error("same content should produce same hash")
	}
	if h1 == h3 {
		t.Error("different content should produce different hash")
	}
	if len(h1) != 64 {
		t.Errorf("SHA-256 hex should be 64 chars, got %d", len(h1))
	}
}

func TestMultipleActiveCanaries(t *testing.T) {
	m, _ := tempManifest(t)

	for i := 0; i < 5; i++ {
		m.Add(sampleCanary(fmt.Sprintf("tok-%d", i)))
	}

	if len(m.Active()) != 5 {
		t.Errorf("expected 5 active canaries, got %d", len(m.Active()))
	}

	m.Deactivate("tok-2", "teardown")

	if len(m.Active()) != 4 {
		t.Errorf("expected 4 active after deactivation, got %d", len(m.Active()))
	}
}
