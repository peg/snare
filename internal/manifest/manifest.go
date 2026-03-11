// Package manifest tracks what canaries have been planted and where.
// Stored at ~/.snare/manifest.json — this is metadata, NOT bait.
package manifest

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const manifestDir = ".snare"
const manifestFile = "manifest.json"
const currentVersion = 2

// Mode describes how bait was written to disk.
type Mode string

const (
	ModeAppend  Mode = "append"  // appended to an existing file (e.g. ~/.aws/credentials)
	ModeNewFile Mode = "newfile" // created as a new file (e.g. GCP JSON, .env)
)

// Canary represents a single planted canary artifact.
type Canary struct {
	ID             string     `json:"id"`                        // unique token ID (matches snare.sh token)
	Type           string     `json:"type"`                      // aws, github, stripe, gcp, generic
	Label          string     `json:"label,omitempty"`           // user-supplied label (e.g. "openclaw")
	Path           string     `json:"path"`                      // absolute path where bait was planted
	Mode           Mode       `json:"mode"`                      // "append" or "newfile"
	Content        string     `json:"content"`                   // exact bytes written to disk
	ContentHash    string     `json:"content_hash"`              // SHA-256 of Content — used for teardown verification
	CallbackURL    string     `json:"callback_url"`
	PlantedAt      time.Time  `json:"planted_at"`
	LastSeen       *time.Time `json:"last_seen,omitempty"`       // populated via snare.sh API on snare status
	Active         bool       `json:"active"`
	InactiveReason string     `json:"inactive_reason,omitempty"` // "teardown" | "uninstall" | "manual"
	InactiveAt     *time.Time `json:"inactive_at,omitempty"`
}

// HashContent returns the SHA-256 hex digest of s.
func HashContent(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum)
}

// Manifest is the full set of planted canaries for this machine.
type Manifest struct {
	Version  int      `json:"version"`
	DeviceID string   `json:"device_id"`
	Canaries []Canary `json:"canaries"`
}

// Load reads the manifest from ~/.snare/manifest.json.
// Returns an empty manifest (not an error) if none exists yet.
func Load() (*Manifest, error) {
	path, err := manifestPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Manifest{Version: currentVersion}, nil
	}
	if err != nil {
		return nil, err
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("manifest corrupt or unreadable: %w", err)
	}

	if m.Version > currentVersion {
		return nil, fmt.Errorf("manifest version %d is newer than this binary supports (%d) — upgrade snare", m.Version, currentVersion)
	}

	return &m, nil
}

// Save writes the manifest atomically to ~/.snare/manifest.json.
// Writes to a temp file first, then renames — prevents corruption on crash.
func (m *Manifest) Save() error {
	path, err := manifestPath()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}

	// Write to temp file in same directory, then rename (atomic on same fs)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// AddPending writes a canary in pending state before bait is written to disk.
// Call Activate(id) after successfully writing bait.
// This ensures orphaned bait (bait on disk with no manifest record) can't happen.
func (m *Manifest) AddPending(c Canary) error {
	c.Active = false
	c.InactiveReason = "pending"
	m.Canaries = append(m.Canaries, c)
	return m.Save()
}

// Activate marks a pending canary as active after bait is successfully written.
func (m *Manifest) Activate(id string) error {
	c := m.FindByID(id)
	if c == nil {
		return fmt.Errorf("canary %s not found in manifest", id)
	}
	c.Active = true
	c.InactiveReason = ""
	return m.Save()
}

// Add adds a canary to the manifest and saves.
// Prefer AddPending + Activate for transactional safety.
func (m *Manifest) Add(c Canary) error {
	m.Canaries = append(m.Canaries, c)
	return m.Save()
}

// Pending returns canaries stuck in pending state (bait write may have failed).
func (m *Manifest) Pending() []Canary {
	var pending []Canary
	for _, c := range m.Canaries {
		if !c.Active && c.InactiveReason == "pending" {
			pending = append(pending, c)
		}
	}
	return pending
}

// FindByID returns a pointer to the canary with the given ID, or nil.
func (m *Manifest) FindByID(id string) *Canary {
	for i := range m.Canaries {
		if m.Canaries[i].ID == id {
			return &m.Canaries[i]
		}
	}
	return nil
}

// Deactivate marks a canary inactive with a reason and saves.
// Returns an error if the ID is not found.
func (m *Manifest) Deactivate(id string, reason string) error {
	c := m.FindByID(id)
	if c == nil {
		return fmt.Errorf("canary %s not found in manifest", id)
	}
	now := time.Now()
	c.Active = false
	c.InactiveReason = reason
	c.InactiveAt = &now
	return m.Save()
}

// Remove deletes a canary from the manifest entirely and saves.
// Prefer Deactivate for audit trails; use Remove only for uninstall.
func (m *Manifest) Remove(id string) error {
	filtered := make([]Canary, 0, len(m.Canaries))
	found := false
	for _, c := range m.Canaries {
		if c.ID == id {
			found = true
			continue
		}
		filtered = append(filtered, c)
	}
	if !found {
		return fmt.Errorf("canary %s not found in manifest", id)
	}
	m.Canaries = filtered
	return m.Save()
}

// Active returns only currently active canaries.
func (m *Manifest) Active() []Canary {
	var active []Canary
	for _, c := range m.Canaries {
		if c.Active {
			active = append(active, c)
		}
	}
	return active
}

// Dir returns the ~/.snare directory path.
func Dir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, manifestDir), nil
}

func manifestPath() (string, error) {
	dir, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, manifestFile), nil
}
