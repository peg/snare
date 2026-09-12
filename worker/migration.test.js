import { describe, expect, it } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { mkdtemp, readFile, writeFile, stat, rm, symlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { compileMigration, migrateFile } from "./scripts/migrate-kv-to-d1.mjs";

const NOW = Date.parse("2026-09-11T12:00:00Z");
const TOKEN = "token_active_001";
const OLD_TOKEN = "token_revoked_001";
const DEVICE = "device_owner";
const SECRET_HASH = "a".repeat(64);
const WEBHOOK = "https://hooks.slack.com/services/private-secret-path";
const PROOF = "d".repeat(32);
const SCRIPT = fileURLToPath(new URL("./scripts/migrate-kv-to-d1.mjs", import.meta.url));

function entry(name, value) { return { name, value: JSON.stringify(value) }; }
function backup() {
  return [
    entry(`device:${DEVICE}`, { secret_hash: SECRET_HASH, created_at: new Date(NOW - 86400000).toISOString() }),
    entry(`webhook:${TOKEN}`, { device_id: DEVICE, webhook_url: WEBHOOK, canary_type: "aws", label: "Owner's token", registered_at: NOW - 1000 }),
    entry(`event:${TOKEN}:${NOW}:11111111-1111-1111-1111-111111111111`, { id: "event_original_001", token: TOKEN, device_id: DEVICE,
      timestamp: new Date(NOW).toISOString(), userAgent: "aws-cli/test", method: "POST", proof_id: PROOF,
      body: "sensitive-body-to-drop", authorization: "Bearer secret-to-drop" }),
    entry(`event:${OLD_TOKEN}:${NOW - 1000}:22222222-2222-2222-2222-222222222222`, { token: OLD_TOKEN, device_id: DEVICE,
      timestamp: new Date(NOW - 1000).toISOString(), method: "GET", notification_suppressed: "preview" }),
    { name: "rl:api:192.0.2.1:1234", value: "4" },
    { name: "dedup:token:192.0.2.1:1234", value: "1" },
  ];
}

function database() {
  const db = new DatabaseSync(":memory:");
  db.exec(readFileSync(new URL("./migrations/0001_state.sql", import.meta.url), "utf8"));
  return db;
}

describe("offline KV migration", () => {
  it("restores hashes, active ownership, revoked history, proof IDs and stable event IDs without replay", () => {
    const source = backup();
    const result = compileMigration(source, { now: NOW });
    expect(result.counts).toMatchObject({ devices: 1, activeTokens: 1, revokedTokens: 1, events: 2, inferredTombstones: 1, ignoredTransientRecords: 2, pendingDeliveries: 0 });
    expect(result.sql).not.toContain("sensitive-body-to-drop");
    expect(result.sql).not.toContain("Bearer secret-to-drop");
    const db = database();
    try {
      db.exec(result.sql);
      expect(db.prepare("SELECT secret_hash FROM devices WHERE device_id = ?").get(DEVICE).secret_hash).toBe(SECRET_HASH);
      expect(db.prepare("SELECT * FROM tokens WHERE token = ?").get(TOKEN)).toMatchObject({ device_id: DEVICE, webhook_url: WEBHOOK, label: "Owner's token", revoked: 0 });
      expect(db.prepare("SELECT * FROM tokens WHERE token = ?").get(OLD_TOKEN)).toMatchObject({ device_id: DEVICE, webhook_url: "", revoked: 1 });
      expect(db.prepare("SELECT proof_id FROM events WHERE event_id = 'event_original_001'").get().proof_id).toBe(PROOF);
      const expectedId = `legacy_${createHash("sha256").update(source[3].name).digest("hex")}`;
      expect(db.prepare("SELECT event_id FROM events WHERE token = ?").get(OLD_TOKEN).event_id).toBe(expectedId);
      expect(db.prepare("SELECT suppressed FROM events WHERE token = ?").get(OLD_TOKEN).suppressed).toBe(1);
      expect(db.prepare("SELECT COUNT(*) AS n FROM deliveries").get().n).toBe(0);
      expect(db.prepare("SELECT COUNT(*) AS n FROM delivery_attempts").get().n).toBe(0);
      expect(compileMigration([...source].reverse(), { now: NOW }).sql).toBe(result.sql);
    } finally { db.close(); }
  });

  it("fails closed on conflicting owners, missing historical owner, or incomplete device backup", () => {
    const conflict = backup();
    conflict.push(entry(`owner:${TOKEN}`, { device_id: "other_owner" }));
    expect(() => compileMigration(conflict, { now: NOW })).toThrow("OWNERSHIP_CONFLICT");
    const missingOwner = backup();
    const legacy = JSON.parse(missingOwner[3].value);
    delete legacy.device_id;
    missingOwner[3].value = JSON.stringify(legacy);
    expect(() => compileMigration(missingOwner, { now: NOW })).toThrow("MISSING_EVENT_OWNER");
    expect(() => compileMigration(backup().slice(1), { now: NOW })).toThrow("MISSING_DEVICE_RECORD");
  });

  it("rejects corrupt hashes, identities, proof IDs, revisions and unsupported backup formats", () => {
    const mutations = [
      [0, { secret_hash: "not-a-hash" }, "INVALID_SECRET_HASH"],
      [2, { device_id: DEVICE, token: "token_other_001", timestamp: NOW }, "IDENTITY_CONFLICT"],
      [2, { device_id: DEVICE, token: TOKEN, timestamp: NOW, proof_id: "not-a-proof" }, "INVALID_PROOF_ID"],
      [2, { device_id: DEVICE, token: TOKEN, timestamp: NOW, token_revision: 5 }, "REVISION_CONFLICT"],
    ];
    for (const [index, replacement, code] of mutations) {
      const source = backup();
      source[index].value = JSON.stringify(replacement);
      expect(() => compileMigration(source, { now: NOW })).toThrow(code);
    }
    expect(() => compileMigration({ keys: backup() }, { now: NOW })).toThrow("INVALID_BACKUP");
    expect(() => compileMigration([{ name: "unknown:private", value: "sensitive-value" }], { now: NOW })).toThrow("UNKNOWN_KEY_TYPE");
    expect(() => compileMigration([{ ...backup()[0], base64: true }], { now: NOW })).toThrow("INVALID_ENTRY");
    expect(() => compileMigration([...backup(), backup()[0]], { now: NOW })).toThrow("DUPLICATE_KEY");
  });

  it("preserves explicit tombstones and reports history outside current retention", () => {
    const source = [backup()[0], entry(`owner:${OLD_TOKEN}`, { device_id: DEVICE }),
      entry(`webhook:${TOKEN}`, { device_id: DEVICE, webhook_url: "", revoked: true, revision: 4 }),
      entry(`event:${TOKEN}:${NOW - 10 * 86400000}:old-event-key`, { token: TOKEN, device_id: DEVICE,
        timestamp: new Date(NOW - 10 * 86400000).toISOString(), token_revision: 3 })];
    const result = compileMigration(source, { now: NOW });
    expect(result.counts).toMatchObject({ activeTokens: 0, revokedTokens: 2, eventsOutsideRetention: 1 });
    const db = database();
    try {
      db.exec(result.sql);
      expect(db.prepare("SELECT revision FROM tokens WHERE token = ?").get(TOKEN).revision).toBe(4);
    } finally { db.close(); }
  });

  it("refuses to import into a populated target instead of replacing ownership", () => {
    const db = database();
    try {
      db.prepare("INSERT INTO devices VALUES ('existing_owner', ?, 1)").run("b".repeat(64));
      expect(() => db.exec(compileMigration(backup(), { now: NOW }).sql)).toThrow("NOT NULL");
      expect(db.prepare("SELECT COUNT(*) AS n FROM devices").get().n).toBe(1);
      expect(db.prepare("SELECT COUNT(*) AS n FROM tokens").get().n).toBe(0);
    } finally { db.close(); }
  });

  it("rejects oversized physical imports and escapes hostile metadata as SQL data", () => {
    const tooMany = Array.from({ length: 201 }, (_, i) => entry(`device:device_${i}`, { secret_hash: SECRET_HASH }));
    expect(() => compileMigration(tooMany, { now: NOW })).toThrow("CAPACITY_EXCEEDED");
    const source = backup();
    const registration = JSON.parse(source[1].value);
    registration.label = "x'); DROP TABLE devices; --";
    source[1].value = JSON.stringify(registration);
    const db = database();
    try {
      db.exec(compileMigration(source, { now: NOW }).sql);
      expect(db.prepare("SELECT label FROM tokens WHERE token = ?").get(TOKEN).label).toBe(registration.label);
      expect(db.prepare("SELECT COUNT(*) AS n FROM devices").get().n).toBe(1);
    } finally { db.close(); }
  });

  it("creates a private output and never overwrites existing files or follows output symlinks", async () => {
    const dir = await mkdtemp(join(tmpdir(), "snare-migration-"));
    try {
      const input = join(dir, "backup.json");
      const output = join(dir, "import.sql");
      await writeFile(input, JSON.stringify(backup()), { mode: 0o600 });
      expect(await migrateFile(input, output)).toMatchObject({ devices: 1, events: 2 });
      expect((await stat(output)).mode & 0o777).toBe(0o600);
      const original = await readFile(output, "utf8");
      await expect(migrateFile(input, output)).rejects.toMatchObject({ code: "EEXIST" });
      expect(await readFile(output, "utf8")).toBe(original);
      const linked = join(dir, "linked.sql");
      await symlink(output, linked);
      await expect(migrateFile(input, linked)).rejects.toMatchObject({ code: "EEXIST" });
      expect(await readFile(output, "utf8")).toBe(original);
    } finally { await rm(dir, { recursive: true, force: true }); }
  });

  it("prints counts only and never echoes secrets on successful or failed CLI runs", async () => {
    const dir = await mkdtemp(join(tmpdir(), "snare-migration-cli-"));
    try {
      const input = join(dir, "backup.json");
      const output = join(dir, "import.sql");
      await writeFile(input, JSON.stringify(backup()), { mode: 0o600 });
      const success = spawnSync(process.execPath, [SCRIPT, input, output], { encoding: "utf8" });
      expect(success.status).toBe(0);
      expect(JSON.parse(success.stdout)).toMatchObject({ devices: 1, events: 2 });
      expect(success.stderr).toBe("");
      const conflicted = backup();
      conflicted.push(entry(`owner:${TOKEN}`, { device_id: "other_owner" }));
      await writeFile(input, JSON.stringify(conflicted));
      const failure = spawnSync(process.execPath, [SCRIPT, input, join(dir, "rejected.sql")], { encoding: "utf8" });
      expect(failure.status).toBe(1);
      expect(failure.stdout).toBe("");
      expect(failure.stderr).toContain("OWNERSHIP_CONFLICT");
      await expect(stat(join(dir, "rejected.sql"))).rejects.toMatchObject({ code: "ENOENT" });
      for (const outputText of [success.stdout, success.stderr, failure.stdout, failure.stderr]) {
        expect(outputText).not.toContain(SECRET_HASH);
        expect(outputText).not.toContain(WEBHOOK);
        expect(outputText).not.toContain("secret-to-drop");
        expect(outputText).not.toContain(TOKEN);
      }
    } finally { await rm(dir, { recursive: true, force: true }); }
  });
});
