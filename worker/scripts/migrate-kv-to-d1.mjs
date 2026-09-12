#!/usr/bin/env node
// Offline only. Reads an explicit local backup and writes a new private SQL
// file; never authenticates, contacts Cloudflare, or replays notifications.
import { createHash } from "node:crypto";
import { constants } from "node:fs";
import { open, unlink } from "node:fs/promises";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_STORE_LIMITS } from "../store.js";
import { sanitizeCallbackMetadata, validateDeviceId, validateTokenId } from "../policy.js";

const MAX_BYTES = 64 * 1024 * 1024;
const MAX_RECORDS = 30000;
const DAY = 86400000;
const ID = /^[a-zA-Z0-9_-]{8,80}$/;

export class MigrationError extends Error {
  constructor(code) { super(code); this.code = code; }
}

function fail(code) { throw new MigrationError(code); }
function object(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function bounded(value, maximum, { empty = false } = {}) {
  if (typeof value !== "string" || (!empty && !value.length) || /[\x00-\x1f\x7f]/.test(value) || Buffer.byteLength(value) > maximum) fail("INVALID_FIELD");
  return value;
}
function time(value, fallback = 0) {
  const parsed = value == null ? fallback : typeof value === "string" ? Date.parse(value) : value;
  if (!Number.isSafeInteger(parsed) || parsed < 0) fail("INVALID_TIME");
  return parsed;
}
function revision(value) {
  if (value == null) return 1;
  if (!Number.isSafeInteger(value) || value < 1 || value >= Number.MAX_SAFE_INTEGER) fail("INVALID_REVISION");
  return value;
}
function device(value) {
  try { return validateDeviceId(value); } catch { fail("INVALID_DEVICE"); }
}
function token(value) {
  try { return validateTokenId(value); } catch { fail("INVALID_TOKEN"); }
}
function parseValue(value) {
  let record = value;
  if (typeof record === "string") {
    if (Buffer.byteLength(record) > 64 * 1024) fail("RECORD_TOO_LARGE");
    try { record = JSON.parse(record); } catch { fail("INVALID_RECORD_JSON"); }
  }
  if (!object(record) || Buffer.byteLength(JSON.stringify(record)) > 64 * 1024) fail("INVALID_RECORD");
  return record;
}
function sql(value) {
  if (value === null) return "NULL";
  if (typeof value === "number" && Number.isSafeInteger(value)) return String(value);
  if (typeof value !== "string" || value.includes("\0")) fail("INVALID_SQL_VALUE");
  return `'${value.replaceAll("'", "''")}'`;
}
function insert(table, fields, values) {
  return `INSERT INTO ${table} (${fields.join(", ")}) VALUES (${values.map(sql).join(", ")});`;
}
function digest(value) { return createHash("sha256").update(value).digest("hex"); }

export function compileMigration(backup, { now = Date.now() } = {}) {
  time(now);
  if (!Array.isArray(backup) || backup.length > MAX_RECORDS || Buffer.byteLength(JSON.stringify(backup)) > MAX_BYTES) fail("INVALID_BACKUP");
  const devices = new Map();
  const registrations = new Map();
  const owners = new Map();
  const events = [];
  const keys = new Set();
  const eventIds = new Set();
  const counts = { devices: 0, activeTokens: 0, revokedTokens: 0, events: 0, inferredTombstones: 0,
    ignoredTransientRecords: 0, sanitizedEvents: 0, eventsOutsideRetention: 0, pendingDeliveries: 0 };

  function own(tokenId, owner) {
    const ownerId = device(owner);
    if (owners.has(tokenId) && owners.get(tokenId) !== ownerId) fail("OWNERSHIP_CONFLICT");
    owners.set(tokenId, ownerId);
    return ownerId;
  }

  for (const entry of backup) {
    if (!object(entry) || Object.keys(entry).some(key => !["name", "value"].includes(key)) || !Object.hasOwn(entry, "value")) fail("INVALID_ENTRY");
    const name = bounded(entry.name, 512);
    if (keys.has(name)) fail("DUPLICATE_KEY");
    keys.add(name);
    if (name.startsWith("rl:") || name.startsWith("dedup:")) { counts.ignoredTransientRecords++; continue; }
    const match = name.match(/^(device|webhook|owner):([^:]+)$/);
    if (match) {
      const record = parseValue(entry.value);
      if (match[1] === "device") {
        const id = device(match[2]);
        if (record.device_id != null && record.device_id !== id) fail("IDENTITY_CONFLICT");
        if (typeof record.secret_hash !== "string" || !/^[0-9a-fA-F]{64}$/.test(record.secret_hash)) fail("INVALID_SECRET_HASH");
        devices.set(id, { secret_hash: record.secret_hash.toLowerCase(), created_at: time(record.created_at) });
      } else {
        const id = token(match[2]);
        const owner = own(id, record.device_id);
        if (record.token_id != null && record.token_id !== id) fail("IDENTITY_CONFLICT");
        if (match[1] === "owner") continue;
        if (record.revoked !== undefined && typeof record.revoked !== "boolean") fail("INVALID_REVOKED_STATE");
        const revoked = record.revoked === true;
        let webhook = record.webhook_url ?? (revoked ? "" : null);
        bounded(webhook, 2048, { empty: revoked });
        if (webhook && webhook !== "use-global") {
          let parsed;
          try { parsed = new URL(webhook); } catch { fail("INVALID_WEBHOOK"); }
          if (parsed.protocol !== "https:" || parsed.username || parsed.password) fail("INVALID_WEBHOOK");
          parsed.hash = "";
          webhook = bounded(parsed.href, 2048);
        }
        const type = record.canary_type ?? "generic";
        if (typeof type !== "string" || !/^[a-z][a-z0-9-]{0,31}$/.test(type)) fail("INVALID_CANARY_TYPE");
        registrations.set(id, { device_id: owner, webhook_url: webhook, canary_type: type,
          label: bounded(record.label ?? "", 128, { empty: true }), registered_at: time(record.registered_at),
          revoked: revoked ? 1 : 0, revision: revision(record.revision) });
      }
      continue;
    }
    const eventKey = name.match(/^event:([a-zA-Z0-9_-]{8,80}):([0-9]{1,16}):([a-zA-Z0-9_-]{1,80})$/);
    if (!eventKey) fail("UNKNOWN_KEY_TYPE");
    const record = parseValue(entry.value);
    const tokenId = token(eventKey[1]);
    if (record.token !== undefined && record.token !== tokenId) fail("IDENTITY_CONFLICT");
    // Missing historical ownership is ambiguous, even if a current registration
    // exists: that registration could have been reassigned by the legacy bug.
    if (!record.device_id) fail("MISSING_EVENT_OWNER");
    const owner = own(tokenId, record.device_id);
    const id = record.id ?? `legacy_${digest(name)}`;
    if (typeof id !== "string" || !ID.test(id)) fail("INVALID_EVENT_ID");
    if (eventIds.has(id)) fail("DUPLICATE_EVENT_ID");
    eventIds.add(id);
    const admitted = time(Number(eventKey[2]));
    if (admitted > now + 300000) fail("FUTURE_ADMISSION");
    if (record.timestamp == null) fail("MISSING_EVENT_TIME");
    const timestamp = time(record.timestamp);
    const proof = record.proof_id ?? null;
    if (proof !== null && (typeof proof !== "string" || !/^[0-9a-f]{32}$/.test(proof))) fail("INVALID_PROOF_ID");
    const tokenRevision = revision(record.token_revision);
    const clean = { ...sanitizeCallbackMetadata(record), id, token: tokenId, device_id: owner,
      timestamp: new Date(timestamp).toISOString(), token_revision: tokenRevision, proof_id: proof,
      is_test: record.is_test === true, classification: bounded(record.classification ?? "legacy", 64),
      notification_suppressed: record.notification_suppressed == null ? null : bounded(record.notification_suppressed, 64),
      delivery_mode: "historical_import" };
    const encoded = JSON.stringify(clean);
    if (Buffer.byteLength(encoded) > 16384) fail("EVENT_TOO_LARGE");
    if (JSON.stringify(sanitizeCallbackMetadata(record)) !== JSON.stringify(record)) counts.sanitizedEvents++;
    if (admitted < now - DEFAULT_STORE_LIMITS.retentionDays * DAY) counts.eventsOutsideRetention++;
    events.push({ id, token: tokenId, owner, timestamp, admitted, admission_id: `import_${digest(name)}`,
      proof, suppressed: clean.notification_suppressed ? 1 : 0, revision: tokenRevision, json: encoded });
  }

  for (const [tokenId, owner] of owners) {
    if (!devices.has(owner)) fail("MISSING_DEVICE_RECORD");
    if (!registrations.has(tokenId)) {
      const history = events.filter(event => event.token === tokenId);
      registrations.set(tokenId, { device_id: owner, webhook_url: "", canary_type: "generic", label: "",
        registered_at: history.length ? Math.min(...history.map(event => event.admitted)) : 0, revoked: 1,
        revision: history.length ? Math.max(...history.map(event => event.revision)) + 1 : 1 });
      counts.inferredTombstones++;
    }
  }
  for (const event of events) {
    if (event.revision > registrations.get(event.token).revision) fail("REVISION_CONFLICT");
  }
  const activeByDevice = new Map();
  const recordsByDevice = new Map();
  const eventsByDevice = new Map();
  for (const record of registrations.values()) {
    recordsByDevice.set(record.device_id, (recordsByDevice.get(record.device_id) ?? 0) + 1);
    if (record.revoked) counts.revokedTokens++;
    else { counts.activeTokens++; activeByDevice.set(record.device_id, (activeByDevice.get(record.device_id) ?? 0) + 1); }
  }
  for (const event of events) eventsByDevice.set(event.owner, (eventsByDevice.get(event.owner) ?? 0) + 1);
  counts.devices = devices.size;
  counts.events = events.length;
  const l = DEFAULT_STORE_LIMITS;
  if (devices.size > l.maxDevices || registrations.size > l.maxTokenRecords || counts.activeTokens > l.maxTokens || events.length > l.retainedEvents ||
      [...recordsByDevice.values()].some(count => count > l.maxTokenRecordsPerDevice) ||
      [...activeByDevice.values()].some(count => count > l.maxTokensPerDevice) ||
      [...eventsByDevice.values()].some(count => count > l.retainedEventsPerDevice)) fail("CAPACITY_EXCEEDED");

  const statements = [
    "-- Snare offline KV import. Apply schema migration first; target must be EMPTY.",
    "-- Contains private credential hashes, webhook URLs, and event metadata. Do not publish.",
    "-- No historical webhook deliveries are created. Existing retention policy applies.",
    "PRAGMA foreign_keys = ON;",
    // Deliberate NOT NULL failure on a populated target. No INSERT OR REPLACE,
    // owner reassignment, table deletion, or merging into a live database.
    "INSERT INTO devices(device_id, secret_hash, created_at) SELECT NULL, NULL, NULL WHERE EXISTS(SELECT 1 FROM devices) OR EXISTS(SELECT 1 FROM tokens) OR EXISTS(SELECT 1 FROM events) OR EXISTS(SELECT 1 FROM deliveries) OR EXISTS(SELECT 1 FROM delivery_attempts);",
  ];
  for (const [id, record] of [...devices].sort(([a], [b]) => a.localeCompare(b))) statements.push(insert("devices",
    ["device_id", "secret_hash", "created_at"], [id, record.secret_hash, record.created_at]));
  for (const [id, record] of [...registrations].sort(([a], [b]) => a.localeCompare(b))) statements.push(insert("tokens",
    ["token", "device_id", "webhook_url", "canary_type", "label", "registered_at", "revoked", "revision"],
    [id, record.device_id, record.webhook_url, record.canary_type, record.label, record.registered_at, record.revoked, record.revision]));
  for (const event of events.sort((a, b) => a.id.localeCompare(b.id))) statements.push(insert("events",
    ["event_id", "token", "device_id", "timestamp", "admitted_at", "admission_day", "admission_id", "proof_id", "suppressed", "token_revision", "event_json"],
    [event.id, event.token, event.owner, event.timestamp, event.admitted, Math.floor(event.admitted / DAY), event.admission_id, event.proof, event.suppressed, event.revision, event.json]));
  return { sql: `${statements.join("\n")}\n`, counts };
}

export async function migrateFile(inputPath, outputPath) {
  if (!inputPath || !outputPath || resolve(inputPath) === resolve(outputPath)) fail("INVALID_PATHS");
  const input = await open(inputPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  let backup;
  try {
    const info = await input.stat();
    if (!info.isFile() || info.size > MAX_BYTES) fail("INVALID_BACKUP_FILE");
    const bytes = await input.readFile();
    if (bytes.length > MAX_BYTES) fail("INVALID_BACKUP_FILE");
    try { backup = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
    catch { fail("INVALID_BACKUP_JSON"); }
  } finally { await input.close(); }
  const result = compileMigration(backup);
  let output;
  try {
    // Exclusive create refuses existing files and symlinks. Permissions are
    // private from creation; never write sensitive bytes before chmod.
    output = await open(outputPath, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL, 0o600);
    await output.chmod(0o600);
    await output.writeFile(result.sql, "utf8");
    await output.sync();
    await output.close();
  } catch (error) {
    if (output) { await output.close().catch(() => {}); await unlink(outputPath).catch(() => {}); }
    throw error;
  }
  return result.counts;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 4) fail("USAGE_INPUT_JSON_OUTPUT_SQL");
    const counts = await migrateFile(process.argv[2], process.argv[3]);
    process.stdout.write(`${JSON.stringify(counts)}\n`);
  } catch (error) {
    const code = error instanceof MigrationError ? error.code : "IO_ERROR";
    process.stderr.write(`Migration failed: ${code}. No output was created or existing output changed.\n`);
    process.exitCode = 1;
  }
}
