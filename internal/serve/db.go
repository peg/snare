// Package serve implements a self-hosted HTTP server that replaces the
// Cloudflare Worker backend for snare.sh.
package serve

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no CGo
)

const schema = `
CREATE TABLE IF NOT EXISTS devices (
	device_id   TEXT PRIMARY KEY,
	secret_hash TEXT NOT NULL,
	created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS tokens (
	token_id      TEXT PRIMARY KEY,
	device_id     TEXT NOT NULL,
	webhook_url   TEXT,
	canary_type   TEXT,
	label         TEXT,
	registered_at TEXT NOT NULL,
	FOREIGN KEY (device_id) REFERENCES devices(device_id)
);

CREATE TABLE IF NOT EXISTS events (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	token_id   TEXT NOT NULL,
	is_test    INTEGER NOT NULL DEFAULT 0,
	timestamp  TEXT NOT NULL,
	ip         TEXT,
	user_agent TEXT,
	method     TEXT,
	path       TEXT,
	country    TEXT,
	city       TEXT,
	asn        TEXT,
	asn_org    TEXT,
	created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_events_token_id  ON events(token_id);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_tokens_device_id ON tokens(device_id);
`

// DB wraps a SQLite database with snare-specific operations.
type DB struct {
	db *sql.DB
}

// openDB opens (or creates) the SQLite database at the given path.
func openDB(path string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, fmt.Errorf("creating db dir: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite: %w", err)
	}

	// WAL mode for concurrent reads
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;`); err != nil {
		return nil, fmt.Errorf("pragma: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}

	return &DB{db: db}, nil
}

func (d *DB) close() error {
	return d.db.Close()
}

// hashSecret returns the SHA-256 hex digest of a plaintext secret.
func hashSecret(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

// ─── Device operations ────────────────────────────────────────────────────────

// createDevice inserts a new device record and returns the device_id.
func (d *DB) createDevice(deviceID, deviceSecret string) error {
	_, err := d.db.Exec(
		`INSERT INTO devices (device_id, secret_hash, created_at) VALUES (?, ?, ?)`,
		deviceID, hashSecret(deviceSecret), time.Now().UTC().Format(time.RFC3339),
	)
	return err
}

// deviceSecretHash looks up the stored secret hash for a device.
// Returns ("", nil) when the device does not exist.
func (d *DB) deviceSecretHash(deviceID string) (string, error) {
	var h string
	err := d.db.QueryRow(`SELECT secret_hash FROM devices WHERE device_id = ?`, deviceID).Scan(&h)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return h, err
}

// ─── Token (webhook registration) operations ─────────────────────────────────

type tokenReg struct {
	TokenID      string
	DeviceID     string
	WebhookURL   string
	CanaryType   string
	Label        string
	RegisteredAt string
}

// upsertToken inserts or replaces a token registration.
func (d *DB) upsertToken(t tokenReg) error {
	_, err := d.db.Exec(`
		INSERT INTO tokens (token_id, device_id, webhook_url, canary_type, label, registered_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(token_id) DO UPDATE SET
			device_id     = excluded.device_id,
			webhook_url   = excluded.webhook_url,
			canary_type   = excluded.canary_type,
			label         = excluded.label,
			registered_at = excluded.registered_at
	`, t.TokenID, t.DeviceID, t.WebhookURL, t.CanaryType, t.Label, t.RegisteredAt)
	return err
}

// getToken returns the registration for a token, or nil if not found.
func (d *DB) getToken(tokenID string) (*tokenReg, error) {
	var t tokenReg
	err := d.db.QueryRow(`
		SELECT token_id, device_id, COALESCE(webhook_url,''), COALESCE(canary_type,''), COALESCE(label,''), registered_at
		FROM tokens WHERE token_id = ?
	`, tokenID).Scan(&t.TokenID, &t.DeviceID, &t.WebhookURL, &t.CanaryType, &t.Label, &t.RegisteredAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

// deleteToken removes a token registration.
func (d *DB) deleteToken(tokenID string) error {
	_, err := d.db.Exec(`DELETE FROM tokens WHERE token_id = ?`, tokenID)
	return err
}

// ─── Event operations ─────────────────────────────────────────────────────────

type event struct {
	ID        int64
	TokenID   string
	IsTest    bool
	Timestamp string
	IP        string
	UserAgent string
	Method    string
	Path      string
	Country   string
	City      string
	ASN       string
	ASNOrg    string
	CreatedAt string
	// Resolved from token registration (not stored in events)
	CanaryType string
	Label      string
}

// insertEvent stores a new canary event.
func (d *DB) insertEvent(e event) error {
	isTest := 0
	if e.IsTest {
		isTest = 1
	}
	_, err := d.db.Exec(`
		INSERT INTO events (token_id, is_test, timestamp, ip, user_agent, method, path, country, city, asn, asn_org, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, e.TokenID, isTest, e.Timestamp, e.IP, e.UserAgent, e.Method, e.Path, e.Country, e.City, e.ASN, e.ASNOrg, e.CreatedAt)
	return err
}

// getEvents returns recent events for a token (newest first, limit 20).
func (d *DB) getEvents(tokenID string) ([]event, error) {
	rows, err := d.db.Query(`
		SELECT id, token_id, is_test, timestamp, COALESCE(ip,''), COALESCE(user_agent,''),
		       COALESCE(method,''), COALESCE(path,''), COALESCE(country,''), COALESCE(city,''),
		       COALESCE(asn,''), COALESCE(asn_org,''), created_at
		FROM events
		WHERE token_id = ?
		ORDER BY timestamp DESC
		LIMIT 20
	`, tokenID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// recentEvents returns the most recent events across all tokens (for dashboard).
func (d *DB) recentEvents(limit int) ([]event, error) {
	rows, err := d.db.Query(`
		SELECT e.id, e.token_id, e.is_test, e.timestamp, COALESCE(e.ip,''), COALESCE(e.user_agent,''),
		       COALESCE(e.method,''), COALESCE(e.path,''), COALESCE(e.country,''), COALESCE(e.city,''),
		       COALESCE(e.asn,''), COALESCE(e.asn_org,''), e.created_at
		FROM events e
		ORDER BY e.timestamp DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

func scanEvents(rows *sql.Rows) ([]event, error) {
	var out []event
	for rows.Next() {
		var e event
		var isTest int
		if err := rows.Scan(
			&e.ID, &e.TokenID, &isTest, &e.Timestamp,
			&e.IP, &e.UserAgent, &e.Method, &e.Path,
			&e.Country, &e.City, &e.ASN, &e.ASNOrg, &e.CreatedAt,
		); err != nil {
			return nil, err
		}
		e.IsTest = isTest != 0
		out = append(out, e)
	}
	return out, rows.Err()
}

// listDevices returns all registered devices (for dashboard).
type deviceRow struct {
	DeviceID  string
	CreatedAt string
	TokenCount int
}

func (d *DB) listDevices() ([]deviceRow, error) {
	rows, err := d.db.Query(`
		SELECT d.device_id, d.created_at, COUNT(t.token_id) AS token_count
		FROM devices d
		LEFT JOIN tokens t ON t.device_id = d.device_id
		GROUP BY d.device_id
		ORDER BY d.created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []deviceRow
	for rows.Next() {
		var r deviceRow
		if err := rows.Scan(&r.DeviceID, &r.CreatedAt, &r.TokenCount); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}
