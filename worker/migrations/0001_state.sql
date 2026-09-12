-- Apply explicitly with Wrangler D1 migrations before activating SNARE_DB.
PRAGMA foreign_keys = ON;

CREATE TABLE devices (
  device_id TEXT PRIMARY KEY,
  secret_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE tokens (
  token TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(device_id),
  webhook_url TEXT NOT NULL,
  canary_type TEXT NOT NULL,
  label TEXT NOT NULL,
  registered_at INTEGER NOT NULL,
  revoked INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0, 1)),
  revision INTEGER NOT NULL DEFAULT 1 CHECK (revision > 0)
);
CREATE INDEX tokens_owner_active ON tokens(device_id, revoked);
CREATE INDEX tokens_active ON tokens(revoked);
-- Revoke and re-arm retain ownership. Even accidental application UPDATEs
-- cannot reassign existing history to a different device.
CREATE TRIGGER tokens_immutable_owner BEFORE UPDATE OF device_id ON tokens
WHEN NEW.device_id <> OLD.device_id
BEGIN
  SELECT RAISE(ABORT, 'immutable token owner');
END;

CREATE TABLE events (
  event_id TEXT PRIMARY KEY,
  token TEXT NOT NULL REFERENCES tokens(token),
  device_id TEXT NOT NULL REFERENCES devices(device_id),
  timestamp INTEGER NOT NULL,
  admitted_at INTEGER NOT NULL,
  admission_day INTEGER NOT NULL,
  admission_id TEXT NOT NULL UNIQUE,
  proof_id TEXT,
  suppressed INTEGER NOT NULL DEFAULT 0 CHECK (suppressed IN (0, 1)),
  token_revision INTEGER NOT NULL,
  event_json TEXT NOT NULL CHECK (length(event_json) <= 16384)
);
CREATE INDEX events_token_recent ON events(token, timestamp DESC, event_id DESC);
CREATE INDEX events_token_proof_recent ON events(token, proof_id, timestamp DESC, event_id DESC);
CREATE INDEX events_daily ON events(admission_day);
CREATE INDEX events_owner_daily ON events(device_id, admission_day);
CREATE INDEX events_suppressed_daily ON events(admission_day) WHERE suppressed = 1;
CREATE INDEX events_owner_suppressed_daily ON events(device_id, admission_day) WHERE suppressed = 1;
CREATE INDEX events_retention ON events(admitted_at);

CREATE TABLE deliveries (
  delivery_id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL,
  token TEXT NOT NULL REFERENCES tokens(token),
  device_id TEXT NOT NULL REFERENCES devices(device_id),
  token_revision INTEGER NOT NULL,
  destination_id TEXT NOT NULL,
  message_json TEXT NOT NULL CHECK (length(message_json) <= 16384),
  state TEXT NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'enqueued', 'delivered', 'failed', 'cancelled')),
  attempts INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  next_attempt_at INTEGER NOT NULL,
  enqueued_at INTEGER,
  lease_token TEXT,
  lease_kind TEXT CHECK (lease_kind IN ('publisher', 'consumer')),
  lease_until INTEGER,
  error_code TEXT
);
CREATE INDEX deliveries_due ON deliveries(state, next_attempt_at);
CREATE INDEX deliveries_event ON deliveries(event_id);
CREATE INDEX deliveries_token ON deliveries(token, token_revision, state);
CREATE INDEX deliveries_retention ON deliveries(created_at);

CREATE TABLE delivery_attempts (
  attempt_id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(device_id),
  delivery_id TEXT,
  lease_token TEXT,
  admission_day INTEGER NOT NULL,
  admitted_at INTEGER NOT NULL,
  UNIQUE(delivery_id, lease_token)
);
CREATE INDEX attempts_daily ON delivery_attempts(admission_day);
CREATE INDEX attempts_owner_daily ON delivery_attempts(device_id, admission_day);
CREATE INDEX attempts_retention ON delivery_attempts(admitted_at);
