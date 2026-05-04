package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/peg/snare/internal/manifest"
)

// ScanStatus represents the result for a single canary check.
type ScanStatus int

const (
	ScanOK       ScanStatus = iota // canary present, hash matches
	ScanModified                   // canary present, hash mismatch
	ScanMissing                    // canary not on disk
)

// ScanResult holds the outcome of scanning one manifest entry.
type ScanResult struct {
	Canary manifest.Canary
	Status ScanStatus
	Detail string
}

// OrphanResult holds a discovered canary URL with no manifest record.
type OrphanResult struct {
	Path string
	URL  string
}

// snareURLPattern is the substring we look for to detect canary content on disk.
const snareURLPattern = "snare.sh/c/"

// ScanManifest checks each active canary against disk and returns categorised results.
// It does NOT scan for orphans (that requires filesystem walking — see ScanForOrphans).
func ScanManifest(m *manifest.Manifest) []ScanResult {
	active := m.Active()
	results := make([]ScanResult, 0, len(active))
	for _, c := range active {
		r := ScanResult{Canary: c}
		data, err := os.ReadFile(c.Path)
		if err != nil {
			r.Status = ScanMissing
			r.Detail = "file not found"
			results = append(results, r)
			continue
		}

		if c.Mode == manifest.ModeAppend {
			// Append mode: check the planted block is still present by looking for the ID
			if !strings.Contains(string(data), c.ID) {
				r.Status = ScanMissing
				r.Detail = "canary block not found in file"
			} else {
				// Block present — check if content matches exactly
				if !strings.Contains(string(data), c.Content) {
					r.Status = ScanModified
					r.Detail = "canary block present but content has changed"
				} else {
					r.Status = ScanOK
				}
			}
		} else {
			// New-file mode: compare full content hash
			h := sha256.Sum256(data)
			fileHash := hex.EncodeToString(h[:])
			if fileHash != c.ContentHash {
				r.Status = ScanModified
				r.Detail = "content hash mismatch"
			} else {
				r.Status = ScanOK
			}
		}
		results = append(results, r)
	}
	return results
}

// pathID is a (path, id) pair used for orphan scanning.
type pathID struct{ path, id string }

// ScanForOrphans walks the known canary paths and looks for snare.sh/c/ URLs
// in files that have no matching manifest entry. Returns any found orphans.
func ScanForOrphans(m *manifest.Manifest) ([]OrphanResult, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}

	// Build a set of active canary (path, id) pairs for fast lookup
	active := m.Active()
	covered := make(map[pathID]bool, len(active))
	for _, c := range active {
		covered[pathID{c.Path, c.ID}] = true
	}

	// Directories to scan for orphaned canary content
	scanDirs := []string{
		filepath.Join(home, ".aws"),
		filepath.Join(home, ".config"),
		filepath.Join(home, ".kube"),
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".npmrc"),
		filepath.Join(home, ".pip"),
		filepath.Join(home, ".env"),
		filepath.Join(home, ".env.local"),
		filepath.Join(home, ".env.production"),
	}

	var orphans []OrphanResult

	for _, scanPath := range scanDirs {
		info, err := os.Stat(scanPath)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			continue
		}

		if info.IsDir() {
			// Walk directory
			err := filepath.WalkDir(scanPath, func(path string, d os.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return nil
				}
				// Skip large files
				fi, err := d.Info()
				if err != nil || fi.Size() > 1<<20 { // 1 MB cap
					return nil
				}
				orphans = append(orphans, checkFileForOrphans(path, covered, active)...)
				return nil
			})
			if err != nil {
				continue
			}
		} else {
			// Single file
			orphans = append(orphans, checkFileForOrphans(scanPath, covered, active)...)
		}
	}

	return orphans, nil
}

// checkFileForOrphans reads a file and returns any snare canary URLs found
// that don't correspond to a known active canary entry.
func checkFileForOrphans(path string, covered map[pathID]bool, active []manifest.Canary) []OrphanResult {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	content := string(data)
	if !strings.Contains(content, snareURLPattern) {
		return nil
	}

	// Check if any known active canary covers this file by ID
	for _, c := range active {
		if c.Path == path && strings.Contains(content, c.ID) {
			return nil // covered by manifest
		}
	}

	// Found snare URL in this file but no manifest entry — it's an orphan
	// Extract the URL for display
	url := extractSnareURL(content)
	return []OrphanResult{{Path: path, URL: url}}
}

// extractSnareURL pulls out the first snare.sh/c/... URL from content.
func extractSnareURL(content string) string {
	idx := strings.Index(content, snareURLPattern)
	if idx == -1 {
		return "(unknown)"
	}
	// Walk backwards to find https://
	start := idx
	for start > 0 && content[start-1] != '\n' && content[start-1] != '"' &&
		content[start-1] != ' ' && content[start-1] != '\t' {
		start--
	}
	// Walk forward to end of URL
	end := idx
	for end < len(content) && content[end] != '\n' && content[end] != '"' &&
		content[end] != ' ' && content[end] != '\t' {
		end++
	}
	return strings.TrimSpace(content[start:end])
}

// cmdScan checks each active canary against disk and reports status.
func cmdScan(args []string) {
	m, err := manifest.Load()
	if err != nil {
		fatal(err)
	}

	active := m.Active()
	if len(active) == 0 {
		fmt.Println("No active canaries. Run `snare arm` to deploy.")
		return
	}

	results := ScanManifest(m)

	// Count per status
	var nOK, nModified, nMissing int
	for _, r := range results {
		switch r.Status {
		case ScanOK:
			nOK++
		case ScanModified:
			nModified++
		case ScanMissing:
			nMissing++
		}
	}

	// Scan for orphans
	orphans, orphanErr := ScanForOrphans(m)
	if orphanErr != nil {
		fmt.Fprintf(os.Stderr, "  ⚠  orphan scan failed: %v\n", orphanErr)
	}

	fmt.Printf("Canary scan (%d active):\n\n", len(active))

	for _, r := range results {
		var icon, detail string
		switch r.Status {
		case ScanOK:
			icon = "✓"
		case ScanModified:
			icon = "⚠"
			detail = r.Detail
		case ScanMissing:
			icon = "✗"
			detail = r.Detail
		}
		short := r.Canary.ID
		if len(short) > 32 {
			short = short[:32] + "..."
		}
		if detail != "" {
			fmt.Printf("  %s  %-12s  %s\n", icon, r.Canary.Type, r.Canary.Path)
			fmt.Printf("     %-12s  %s  — %s\n", "", short, detail)
		} else {
			fmt.Printf("  %s  %-12s  %s\n", icon, r.Canary.Type, r.Canary.Path)
			fmt.Printf("     %-12s  %s\n", "", short)
		}
		fmt.Println()
	}

	if len(orphans) > 0 {
		fmt.Printf("Orphaned canaries (%d found):\n\n", len(orphans))
		for _, o := range orphans {
			fmt.Printf("  ?  %s\n", o.Path)
			if o.URL != "" && o.URL != "(unknown)" {
				fmt.Printf("     %s\n", o.URL)
			}
			fmt.Println()
		}
	}

	// Summary line
	parts := []string{}
	if nOK > 0 {
		parts = append(parts, fmt.Sprintf("%d OK", nOK))
	}
	if nModified > 0 {
		parts = append(parts, fmt.Sprintf("%d modified", nModified))
	}
	if nMissing > 0 {
		parts = append(parts, fmt.Sprintf("%d missing", nMissing))
	}
	if len(orphans) > 0 {
		parts = append(parts, fmt.Sprintf("%d orphaned", len(orphans)))
	}
	fmt.Println("  " + strings.Join(parts, ", "))
	fmt.Println()

	if nModified == 0 && nMissing == 0 && len(orphans) == 0 {
		fmt.Println("  ✓ All active canary files are present and unchanged.")
		fmt.Println("  This is a local health check only; it does not fire alerts.")
		fmt.Println("  Run `snare status` for event state or `snare test` to verify delivery.")
	}
	if nModified > 0 {
		fmt.Println("  ⚠  MODIFIED canaries may have been tampered with.")
		fmt.Println("     Run `snare teardown --force && snare arm` to replant.")
	}
	if nMissing > 0 {
		fmt.Println("  ✗  MISSING canaries are no longer protecting this machine.")
		fmt.Println("     Run `snare arm` to replant.")
	}
	if len(orphans) > 0 {
		fmt.Println("  ?  ORPHANED canaries have no manifest record.")
		fmt.Println("     These may be from a previous install. Run `snare disarm --purge && snare arm` to clean up.")
	}

	// Exit non-zero if anything is wrong
	if nModified > 0 || nMissing > 0 || len(orphans) > 0 {
		os.Exit(1)
	}
}
