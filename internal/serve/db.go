// Package serve implements a self-hosted HTTP server that replaces the
// Cloudflare Worker backend for snare.sh.
package serve

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

CREATE TABLE IF NOT EXISTS token_owners (
	token_id  TEXT PRIMARY KEY,
	device_id TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
	id         INTEGER PRIMARY KEY AUTOINCREMENT,
	token_id   TEXT NOT NULL,
	device_id  TEXT,
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
	// Keep connection-local pragmas effective and serialize transactions in this
	// process. SQLite still arbitrates claims across independent server processes.
	db.SetMaxOpenConns(1)

	// WAL mode for concurrent reads
	if _, err := db.Exec(`PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;`); err != nil {
		db.Close()
		return nil, fmt.Errorf("pragma: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	if _, err := db.Exec(`ALTER TABLE events ADD COLUMN device_id TEXT`); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		db.Close()
		return nil, fmt.Errorf("add events.device_id column: %w", err)
	}
	if _, err := db.Exec(`ALTER TABLE events ADD COLUMN proof_id TEXT NOT NULL DEFAULT ''`); err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		db.Close()
		return nil, fmt.Errorf("add events.proof_id column: %w", err)
	}
	// Preserve legacy ownership before any new claim. Ambiguous or ownerless
	// histories are reserved with an empty owner, which cannot authenticate or
	// claim the token. Never guess an owner from the most recent event.
	if _, err := db.Exec(`
		INSERT INTO token_owners (token_id, device_id)
		SELECT token_id, CASE WHEN COUNT(DISTINCT NULLIF(device_id, '')) = 1
			THEN MAX(device_id) ELSE '' END
		FROM (
			SELECT token_id, device_id FROM tokens
			UNION ALL
			SELECT token_id, COALESCE(device_id, '') FROM events
		)
		GROUP BY token_id
		ON CONFLICT(token_id) DO NOTHING;
		CREATE INDEX IF NOT EXISTS idx_events_token_order ON events(token_id, id DESC);
		CREATE INDEX IF NOT EXISTS idx_events_token_proof ON events(token_id, proof_id, id DESC);
	`); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate token ownership and event indexes: %w", err)
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

// updateDeviceSecret replaces the stored secret hash for an existing device.
// Returns (false, nil) when the device does not exist.
func (d *DB) updateDeviceSecret(deviceID, deviceSecret string) (bool, error) {
	res, err := d.db.Exec(`UPDATE devices SET secret_hash = ? WHERE device_id = ?`, hashSecret(deviceSecret), deviceID)
	if err != nil {
		return false, err
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return rows > 0, nil
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

var errTokenOwned = errors.New("token already owned or reserved")

// upsertToken atomically claims ownership and updates an owner's registration.
// Revocation never removes the ownership record.
func (d *DB) upsertToken(t tokenReg) error {
	tx, err := d.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Acquire the write lock before reading, preventing a read/check/write race.
	if _, err := tx.Exec(`INSERT INTO token_owners (token_id, device_id) VALUES (?, ?)
		ON CONFLICT(token_id) DO NOTHING`, t.TokenID, t.DeviceID); err != nil {
		return err
	}
	var owner string
	if err := tx.QueryRow(`SELECT device_id FROM token_owners WHERE token_id = ?`, t.TokenID).Scan(&owner); err != nil {
		return err
	}
	if owner == "" || owner != t.DeviceID {
		return errTokenOwned
	}
	res, err := tx.Exec(`
		INSERT INTO tokens (token_id, device_id, webhook_url, canary_type, label, registered_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(token_id) DO UPDATE SET
			webhook_url   = excluded.webhook_url,
			canary_type   = excluded.canary_type,
			label         = excluded.label,
			registered_at = excluded.registered_at
		WHERE tokens.device_id = excluded.device_id
	`, t.TokenID, t.DeviceID, t.WebhookURL, t.CanaryType, t.Label, t.RegisteredAt)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errTokenOwned
	}
	return tx.Commit()
}

func (d *DB) tokenOwner(tokenID string) (string, error) {
	var owner string
	err := d.db.QueryRow(`SELECT device_id FROM token_owners WHERE token_id = ?`, tokenID).Scan(&owner)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return owner, err
}

// getToken returns the registration for a token, or nil if not found.
func (d *DB) getToken(tokenID string) (*tokenReg, error) {
	var t tokenReg
	err := d.db.QueryRow(`
		SELECT token_id, device_id, COALESCE(webhook_url,''), COALESCE(canary_type,''), COALESCE(label,''), registered_at
		FROM tokens WHERE token_id = ? AND device_id =
			(SELECT device_id FROM token_owners WHERE token_id = tokens.token_id)
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

func (d *DB) revokeToken(tokenID, deviceID string) error {
	owner, err := d.tokenOwner(tokenID)
	if err != nil {
		return err
	}
	if owner != "" && owner != deviceID {
		return errTokenOwned
	}
	// A claim made after the read above must not be deleted by another device.
	_, err = d.db.Exec(`DELETE FROM tokens WHERE token_id = ? AND device_id = ?`, tokenID, deviceID)
	return err
}

// ─── Event operations ─────────────────────────────────────────────────────────

type event struct {
	ID        int64
	TokenID   string
	DeviceID  string
	ProofID   string
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
		INSERT INTO events (token_id, device_id, is_test, timestamp, ip, user_agent, method, path, country, city, asn, asn_org, created_at, proof_id)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, e.TokenID, e.DeviceID, isTest, e.Timestamp, e.IP, e.UserAgent, e.Method, e.Path, e.Country, e.City, e.ASN, e.ASNOrg, e.CreatedAt, e.ProofID)
	return err
}

// getEvents returns recent events for a token (newest first, limit 20).
func (d *DB) getEvents(tokenID string) ([]event, error) {
	return d.getProofEvents(tokenID, "")
}

func (d *DB) getProofEvents(tokenID, proofID string) ([]event, error) {
	filter := ""
	args := []interface{}{tokenID}
	if proofID != "" {
		filter = " AND proof_id = ?"
		args = append(args, proofID)
	}
	rows, err := d.db.Query(`
		SELECT id, token_id, COALESCE(device_id,''), is_test, timestamp, COALESCE(ip,''), COALESCE(user_agent,''),
		       COALESCE(method,''), COALESCE(path,''), COALESCE(country,''), COALESCE(city,''),
		       COALESCE(asn,''), COALESCE(asn_org,''), created_at, proof_id
		FROM events
		WHERE token_id = ?`+filter+`
		ORDER BY id DESC
		LIMIT 20
	`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

// recentEvents returns the most recent events across all tokens (for dashboard).
func (d *DB) recentEvents(limit int) ([]event, error) {
	rows, err := d.db.Query(`
		SELECT e.id, e.token_id, COALESCE(e.device_id,''), e.is_test, e.timestamp, COALESCE(e.ip,''), COALESCE(e.user_agent,''),
		       COALESCE(e.method,''), COALESCE(e.path,''), COALESCE(e.country,''), COALESCE(e.city,''),
		       COALESCE(e.asn,''), COALESCE(e.asn_org,''), e.created_at, e.proof_id
		FROM events e
		ORDER BY e.id DESC
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
			&e.ID, &e.TokenID, &e.DeviceID, &isTest, &e.Timestamp,
			&e.IP, &e.UserAgent, &e.Method, &e.Path,
			&e.Country, &e.City, &e.ASN, &e.ASNOrg, &e.CreatedAt, &e.ProofID,
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
	DeviceID   string
	CreatedAt  string
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
