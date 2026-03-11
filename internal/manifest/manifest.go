// Package manifest tracks what canaries have been planted and where.
// Stored at ~/.snare/manifest.json — this is metadata, NOT bait.
package manifest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

const manifestDir = ".snare"
const manifestFile = "manifest.json"

// Canary represents a single planted canary artifact.
type Canary struct {
	ID        string    `json:"id"`         // unique token ID (matches snare.sh token)
	Type      string    `json:"type"`        // aws, github, stripe, gcp, generic
	Path      string    `json:"path"`        // absolute path where bait was planted
	PlantedAt time.Time `json:"planted_at"`
	LastSeen  *time.Time `json:"last_seen,omitempty"` // populated by snare.sh callbacks
	CallbackURL string  `json:"callback_url"`
	Active    bool      `json:"active"`
}

// Manifest is the full set of planted canaries for this machine.
type Manifest struct {
	Version  int       `json:"version"`
	DeviceID string    `json:"device_id"`
	Canaries []Canary  `json:"canaries"`
}

// Load reads the manifest from ~/.snare/manifest.json.
func Load() (*Manifest, error) {
	path, err := manifestPath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Manifest{Version: 1}, nil
	}
	if err != nil {
		return nil, err
	}

	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// Save writes the manifest to ~/.snare/manifest.json.
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

	return os.WriteFile(path, data, 0600)
}

// Add adds a canary to the manifest and saves.
func (m *Manifest) Add(c Canary) error {
	m.Canaries = append(m.Canaries, c)
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

func manifestPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, manifestDir, manifestFile), nil
}
