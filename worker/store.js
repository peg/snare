import { validateDeliveryMessage } from "./delivery.js";

const DAY = 86_400_000;
const DELIVERY_MAX_AGE = DAY;
const TERMINAL = new Set(["delivered", "failed", "cancelled"]);

export const DEFAULT_STORE_LIMITS = Object.freeze({
  maxDevices: 200,
  maxTokens: 500,
  maxTokensPerDevice: 100,
  maxTokenRecords: 10000,
  maxTokenRecordsPerDevice: 2000,
  dailyEvents: 200,
  dailyEventsPerDevice: 50,
  dailySuppressedEvents: 50,
  dailySuppressedEventsPerDevice: 10,
  retainedEvents: 5000,
  retainedEventsPerDevice: 1000,
  dailyAttempts: 1000,
  dailyAttemptsPerDevice: 200,
  maxDeliveryRows: 10000,
  maxDestinationsPerEvent: 8,
  retentionDays: 7,
});

function integer(value, min, max, name) {
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new TypeError(`Invalid ${name}`);
  return value;
}

function text(value, max, name, empty = false) {
  if (typeof value !== "string" || (!empty && !value.length) || value.length > max) throw new TypeError(`Invalid ${name}`);
  return value;
}

function milliseconds(value, name = "timestamp") {
  const number = typeof value === "string" ? Date.parse(value) : value;
  return integer(number, 0, Number.MAX_SAFE_INTEGER, name);
}

function json(value) {
  const encoded = JSON.stringify(value);
  if (new TextEncoder().encode(encoded).length > 16384) throw new TypeError("Metadata exceeds storage bound");
  return encoded;
}

function delivery(row) {
  return row ? { ...row, message: JSON.parse(row.message_json) } : null;
}

export class D1Store {
  constructor(db, limits = {}) {
    this.db = db;
    this.limits = Object.fromEntries(Object.entries(DEFAULT_STORE_LIMITS).map(([key, fallback]) => [
      key, integer(limits[key] ?? fallback, 1, key === "retentionDays" ? 30 : Math.min(100000, fallback * 10), key),
    ]));
  }

  statement(sql, ...values) { return this.db.prepare(sql).bind(...values); }

  async getDevice(id) {
    return this.statement("SELECT * FROM devices WHERE device_id = ?", id).first();
  }

  async createDevice(id, secretHash, createdAt = Date.now()) {
    const result = await this.statement(`INSERT INTO devices(device_id, secret_hash, created_at)
      SELECT ?, ?, ? WHERE (SELECT COUNT(*) FROM devices) < ?
      ON CONFLICT(device_id) DO NOTHING`, text(id, 128, "device id"), text(secretHash, 128, "secret hash"),
    milliseconds(createdAt), this.limits.maxDevices).run();
    return result.meta.changes === 1;
  }

  async rotateDevice(id, hash) {
    const result = await this.statement("UPDATE devices SET secret_hash = ? WHERE device_id = ?", text(hash, 128, "secret hash"), id).run();
    return result.meta.changes === 1;
  }

  async getToken(token) {
    const row = await this.statement("SELECT * FROM tokens WHERE token = ?", token).first();
    return row ? { ...row, revoked: Boolean(row.revoked) } : null;
  }

  async registerToken(token, record) {
    const owner = text(record.device_id, 128, "device id");
    const l = this.limits;
    const result = await this.db.batch([
      this.statement(`INSERT INTO tokens(token, device_id, webhook_url, canary_type, label, registered_at)
        SELECT ?, ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM devices WHERE device_id = ?)
        AND (EXISTS (SELECT 1 FROM tokens WHERE token = ? AND device_id = ? AND revoked = 0)
          OR ((SELECT COUNT(*) FROM tokens WHERE revoked = 0) < ?
            AND (SELECT COUNT(*) FROM tokens WHERE device_id = ? AND revoked = 0) < ?))
        AND (EXISTS (SELECT 1 FROM tokens WHERE token = ?)
          OR ((SELECT COUNT(*) FROM tokens) < ? AND (SELECT COUNT(*) FROM tokens WHERE device_id = ?) < ?))
        ON CONFLICT(token) DO UPDATE SET webhook_url = excluded.webhook_url,
          canary_type = excluded.canary_type, label = excluded.label,
          registered_at = CASE WHEN tokens.revoked = 0 AND tokens.webhook_url = excluded.webhook_url
            AND tokens.canary_type = excluded.canary_type AND tokens.label = excluded.label
            THEN tokens.registered_at ELSE excluded.registered_at END,
          revision = CASE WHEN tokens.revoked = 0 AND tokens.webhook_url = excluded.webhook_url
            AND tokens.canary_type = excluded.canary_type AND tokens.label = excluded.label
            THEN tokens.revision ELSE tokens.revision + 1 END,
          revoked = 0 WHERE tokens.device_id = excluded.device_id`,
      text(token, 128, "token"), owner, text(record.webhook_url ?? "", 2048, "webhook URL", true),
      text(record.canary_type ?? "generic", 64, "canary type"), text(record.label ?? "", 256, "label", true),
      milliseconds(record.registered_at ?? Date.now()), owner, token, owner, l.maxTokens,
      owner, l.maxTokensPerDevice, token, l.maxTokenRecords, owner, l.maxTokenRecordsPerDevice),
      this.statement(`UPDATE deliveries SET state = 'cancelled', error_code = 'token_changed', lease_token = NULL, lease_until = NULL
        WHERE token = ? AND state IN ('pending', 'enqueued') AND token_revision <> (SELECT revision FROM tokens WHERE token = ?)`, token, token),
    ]);
    if (result[0].meta.changes === 1) return "registered";
    const existing = await this.getToken(token);
    return existing && existing.device_id !== owner ? "owner_mismatch" : "quota";
  }

  async revokeToken(token, deviceId) {
    const result = await this.db.batch([
      this.statement(`UPDATE tokens SET revoked = 1, revision = revision + 1
        WHERE token = ? AND device_id = ? AND revoked = 0`, token, deviceId),
      this.statement(`UPDATE deliveries SET state = 'cancelled', error_code = 'token_revoked', lease_token = NULL, lease_until = NULL
        WHERE token = ? AND device_id = ? AND state IN ('pending', 'enqueued')
        AND EXISTS (SELECT 1 FROM tokens WHERE token = ? AND device_id = ? AND revoked = 1)`, token, deviceId, token, deviceId),
    ]);
    if (result[0].meta.changes === 1) return true;
    const existing = await this.getToken(token);
    return Boolean(existing && existing.device_id === deviceId && existing.revoked);
  }

  async getEvents(token, { proofId = null, limit = 10 } = {}) {
    integer(limit, 1, 100, "event limit");
    const result = proofId === null
      ? await this.statement("SELECT event_id, event_json FROM events WHERE token = ? ORDER BY timestamp DESC, event_id DESC LIMIT ?", token, limit).all()
      : await this.statement("SELECT event_id, event_json FROM events WHERE token = ? AND proof_id = ? ORDER BY timestamp DESC, event_id DESC LIMIT ?", token, proofId, limit).all();
    if (!result.results.length) return [];
    const ids = result.results.map(row => row.event_id);
    const states = await this.statement(`SELECT event_id, delivery_id AS id, state, attempts, error_code FROM deliveries
      WHERE event_id IN (${ids.map(() => "?").join(",")}) ORDER BY delivery_id`, ...ids).all();
    return result.results.map(row => ({ ...JSON.parse(row.event_json), id: row.event_id,
      deliveries: states.results.filter(state => state.event_id === row.event_id).map(({ event_id: _eventId, ...state }) => state) }));
  }

  async saveEvent(event, deliveryMessages = []) {
    const id = text(event.id, 128, "event id");
    const token = text(event.token, 128, "token");
    const owner = text(event.device_id, 128, "device id");
    const revision = integer(event.token_revision, 1, Number.MAX_SAFE_INTEGER, "token revision");
    const now = Date.now();
    const day = Math.floor(now / DAY);
    const nonce = crypto.randomUUID();
    const suppressed = event.notification_suppressed ? 1 : 0;
    const l = this.limits;
    if (!Array.isArray(deliveryMessages) || deliveryMessages.length > l.maxDestinationsPerEvent) throw new TypeError("Too many delivery destinations");
    const seen = new Set();
    for (const message of deliveryMessages) {
      validateDeliveryMessage(message);
      if (message.event.id !== id || message.event.token !== token || message.event.device_id !== owner ||
          message.token_revision !== revision || seen.has(message.delivery_id)) {
        throw new TypeError("Delivery event identity mismatch");
      }
      seen.add(message.delivery_id);
    }
    const statements = [this.statement(`INSERT INTO events(event_id, token, device_id, timestamp, admitted_at,
      admission_day, admission_id, proof_id, suppressed, token_revision, event_json)
      SELECT ?, token, device_id, ?, ?, ?, ?, ?, ?, revision, ? FROM tokens
      WHERE token = ? AND device_id = ? AND revoked = 0 AND revision = ?
      AND (SELECT COUNT(*) FROM events WHERE admission_day = ?) < ?
      AND (SELECT COUNT(*) FROM events WHERE device_id = ? AND admission_day = ?) < ?
      AND (? = 0 OR ((SELECT COUNT(*) FROM events WHERE suppressed = 1 AND admission_day = ?) < ?
        AND (SELECT COUNT(*) FROM events WHERE device_id = ? AND suppressed = 1 AND admission_day = ?) < ?))
      AND (SELECT COUNT(*) FROM events) < ? AND (SELECT COUNT(*) FROM events WHERE device_id = ?) < ?
      AND (SELECT COUNT(*) FROM deliveries) + ? <= ?
      ON CONFLICT(event_id) DO NOTHING`, id, milliseconds(event.timestamp), now, day, nonce,
    event.proof_id == null ? null : text(event.proof_id, 128, "proof id"), suppressed, json(event), token, owner, revision,
    day, l.dailyEvents, owner, day, l.dailyEventsPerDevice, suppressed, day, l.dailySuppressedEvents,
    owner, day, l.dailySuppressedEventsPerDevice, l.retainedEvents, owner, l.retainedEventsPerDevice,
    deliveryMessages.length, l.maxDeliveryRows)];
    for (const message of deliveryMessages) {
      statements.push(this.statement(`INSERT INTO deliveries(delivery_id, event_id, token, device_id, token_revision,
        destination_id, message_json, created_at, next_attempt_at)
        SELECT ?, event_id, token, device_id, token_revision, ?, ?, ?, ? FROM events WHERE event_id = ? AND admission_id = ?`,
      message.delivery_id, message.destination_id, json(message), now, now, id, nonce));
    }
    const result = await this.db.batch(statements);
    return result[0].meta.changes === 1;
  }

  async expireDeliveries(now) {
    return this.db.batch([
      this.statement(`UPDATE deliveries SET state = 'failed', error_code = 'delivery_expired', lease_token = NULL, lease_until = NULL
        WHERE delivery_id IN (SELECT delivery_id FROM deliveries WHERE state IN ('pending', 'enqueued') AND created_at <= ? LIMIT 100)`, now - DELIVERY_MAX_AGE),
      this.statement(`UPDATE deliveries SET state = 'cancelled', error_code = 'token_changed', lease_token = NULL, lease_until = NULL
        WHERE delivery_id IN (SELECT d.delivery_id FROM deliveries d JOIN tokens t ON t.token = d.token
          WHERE d.state IN ('pending', 'enqueued') AND (t.revoked = 1 OR t.revision <> d.token_revision) LIMIT 100)`),
    ]);
  }

  async dueDeliveries(now, limit = 20) {
    milliseconds(now);
    integer(limit, 1, 100, "delivery limit");
    await this.expireDeliveries(now);
    const result = await this.statement(`SELECT d.* FROM deliveries d JOIN tokens t ON t.token = d.token
      WHERE d.state IN ('pending', 'enqueued') AND d.next_attempt_at <= ? AND (d.lease_until IS NULL OR d.lease_until <= ?)
      AND d.created_at > ? AND t.revoked = 0 AND t.revision = d.token_revision
      ORDER BY d.next_attempt_at, d.delivery_id LIMIT ?`, now, now, now - DELIVERY_MAX_AGE, limit).all();
    return result.results.map(delivery);
  }

  async getDelivery(id) {
    return delivery(await this.statement("SELECT * FROM deliveries WHERE delivery_id = ?", id).first());
  }

  async expireDelivery(id, now) {
    milliseconds(now);
    const result = await this.statement(`UPDATE deliveries SET state = 'failed', error_code = 'delivery_expired',
      lease_token = NULL, lease_kind = NULL, lease_until = NULL
      WHERE delivery_id = ? AND state IN ('pending', 'enqueued') AND created_at <= ?`, id, now - DELIVERY_MAX_AGE).run();
    return result.meta.changes === 1;
  }

  async claimEnqueue(id, now, leaseMs = 30000) {
    milliseconds(now);
    integer(leaseMs, 1000, 300000, "lease duration");
    const result = await this.statement(`UPDATE deliveries SET lease_token = ?, lease_kind = 'publisher', lease_until = ?
      WHERE delivery_id = ?
      AND state IN ('pending', 'enqueued') AND next_attempt_at <= ? AND (lease_until IS NULL OR lease_until <= ?)
      AND created_at > ? AND EXISTS (SELECT 1 FROM tokens t WHERE t.token = deliveries.token AND t.revoked = 0 AND t.revision = deliveries.token_revision)
      RETURNING *`, crypto.randomUUID(), now + leaseMs, id, now, now, now - DELIVERY_MAX_AGE).all();
    return delivery(result.results[0]);
  }

  async markEnqueued(id, now, leaseToken) {
    milliseconds(now);
    if (!leaseToken) return false;
    const result = await this.statement(`UPDATE deliveries SET state = 'enqueued', enqueued_at = ?, next_attempt_at = ?,
      lease_token = NULL, lease_kind = NULL, lease_until = NULL WHERE delivery_id = ?
      AND state IN ('pending', 'enqueued') AND lease_token = ? AND lease_kind = 'publisher' AND lease_until > ?`,
    now, now + 3600000, id, leaseToken, now).run();
    return result.meta.changes === 1;
  }

  async releaseEnqueue(id, now, leaseToken) {
    milliseconds(now);
    if (!leaseToken) return false;
    const result = await this.statement(`UPDATE deliveries SET state = 'pending', enqueued_at = NULL, next_attempt_at = ?,
      lease_token = NULL, lease_kind = NULL, lease_until = NULL WHERE delivery_id = ?
      AND state IN ('pending', 'enqueued') AND lease_token = ? AND lease_kind = 'publisher' AND lease_until > ?`,
    now + 60000, id, leaseToken, now).run();
    return result.meta.changes === 1;
  }

  async claimDelivery(id, now, leaseMs = 30000) {
    milliseconds(now);
    integer(leaseMs, 1000, 300000, "lease duration");
    const result = await this.statement(`UPDATE deliveries SET lease_token = ?, lease_kind = 'consumer', lease_until = ?
      WHERE delivery_id = ? AND (state = 'enqueued' OR (state = 'pending' AND next_attempt_at <= ?))
      AND (lease_until IS NULL OR lease_until <= ?) AND created_at > ?
      AND EXISTS (SELECT 1 FROM tokens t WHERE t.token = deliveries.token AND t.revoked = 0 AND t.revision = deliveries.token_revision)
      RETURNING *`, crypto.randomUUID(), now + leaseMs, id, now, now, now - DELIVERY_MAX_AGE).all();
    return delivery(result.results[0]);
  }

  async finishDelivery(id, state, attempts, nextAttemptAt, errorCode = null, leaseToken = null) {
    if (!["pending", "enqueued", ...TERMINAL].includes(state)) throw new TypeError("Invalid delivery state");
    integer(attempts, 0, 100, "delivery attempts");
    if (!leaseToken) return false;
    const now = Date.now();
    // Attempts are reserved durably before the network operation. Finalization
    // cannot reset/invent them, including cancellation before any send.
    const result = await this.statement(`UPDATE deliveries SET state = ?, next_attempt_at = ?,
      error_code = ?, lease_token = NULL, lease_kind = NULL, lease_until = NULL, enqueued_at = NULL
      WHERE delivery_id = ? AND lease_token = ? AND lease_kind = 'consumer' AND lease_until > ? AND state IN ('pending', 'enqueued') AND attempts <= ?`,
    state, milliseconds(nextAttemptAt ?? now), errorCode == null ? null : text(errorCode, 64, "error code"), id, leaseToken, now, attempts).run();
    return result.meta.changes === 1;
  }

  async reserveDeliveryAttempt(deliveryId, leaseToken, now, maxAttempts = 5) {
    milliseconds(now);
    integer(maxAttempts, 1, 100, "maximum delivery attempts");
    if (!leaseToken) return false;
    const day = Math.floor(now / DAY);
    const attemptId = crypto.randomUUID();
    const result = await this.db.batch([
      this.statement(`INSERT INTO delivery_attempts(attempt_id, device_id, delivery_id, lease_token, admission_day, admitted_at)
        SELECT ?, d.device_id, d.delivery_id, d.lease_token, ?, ? FROM deliveries d JOIN tokens t ON t.token = d.token
        WHERE d.delivery_id = ? AND d.lease_token = ? AND d.lease_kind = 'consumer' AND d.lease_until > ?
        AND d.state IN ('pending', 'enqueued') AND d.attempts < ? AND d.created_at > ?
        AND t.revoked = 0 AND t.revision = d.token_revision
        AND (SELECT COUNT(*) FROM delivery_attempts WHERE admission_day = ?) < ?
        AND (SELECT COUNT(*) FROM delivery_attempts WHERE device_id = d.device_id AND admission_day = ?) < ?
        ON CONFLICT(delivery_id, lease_token) DO NOTHING`, attemptId, day, now, deliveryId, leaseToken, now, maxAttempts,
      now - DELIVERY_MAX_AGE, day, this.limits.dailyAttempts, day, this.limits.dailyAttemptsPerDevice),
      this.statement(`UPDATE deliveries SET attempts = attempts + 1 WHERE delivery_id = ?
        AND EXISTS (SELECT 1 FROM delivery_attempts WHERE attempt_id = ?)`, deliveryId, attemptId),
    ]);
    return result[0].meta.changes === 1;
  }

  async admitDeliveryAttempt(deviceId, now) {
    milliseconds(now);
    const day = Math.floor(now / DAY);
    const result = await this.statement(`INSERT INTO delivery_attempts(attempt_id, device_id, admission_day, admitted_at)
      SELECT ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM devices WHERE device_id = ?)
      AND (SELECT COUNT(*) FROM delivery_attempts WHERE admission_day = ?) < ?
      AND (SELECT COUNT(*) FROM delivery_attempts WHERE device_id = ? AND admission_day = ?) < ?`,
    crypto.randomUUID(), deviceId, day, now, deviceId, day, this.limits.dailyAttempts,
    deviceId, day, this.limits.dailyAttemptsPerDevice).run();
    return result.meta.changes === 1;
  }

  async cleanup(now) {
    milliseconds(now);
    await this.expireDeliveries(now);
    // Never remove today's quota evidence. Retention is based on admission,
    // not an event's supplied timestamp; expired deliveries stay visible first.
    const cutoff = now - this.limits.retentionDays * DAY;
    return this.db.batch([
      this.statement("DELETE FROM events WHERE event_id IN (SELECT event_id FROM events WHERE admitted_at < ? ORDER BY admitted_at LIMIT 100)", cutoff),
      this.statement(`DELETE FROM deliveries WHERE delivery_id IN (SELECT delivery_id FROM deliveries
        WHERE created_at < ? AND state IN ('delivered', 'failed', 'cancelled') ORDER BY created_at LIMIT 100)`, cutoff),
      this.statement("DELETE FROM delivery_attempts WHERE attempt_id IN (SELECT attempt_id FROM delivery_attempts WHERE admitted_at < ? ORDER BY admitted_at LIMIT 100)", cutoff),
    ]);
  }
}
