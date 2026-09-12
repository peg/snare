import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DatabaseSync } from "node:sqlite";
import { readFileSync } from "node:fs";
import { D1Store } from "./store.js";
import { createDeliveryMessage } from "./delivery.js";

// Execute the production SQL against real SQLite, preserving D1 batch rollback
// and serialized writes. This adapter does not implement any admission logic.
class SQLiteD1 {
  constructor() {
    this.sqlite = new DatabaseSync(":memory:");
    this.sqlite.exec(readFileSync(new URL("./migrations/0001_state.sql", import.meta.url), "utf8"));
  }
  prepare(sql) {
    const db = this.sqlite;
    const values = [];
    const query = {
      bind(...bound) { values.push(...bound); return query; },
      execute() {
        const statement = db.prepare(sql);
        const before = Number(db.prepare("SELECT total_changes() AS n").get().n);
        let results = [];
        if (statement.columns().length) results = statement.all(...values).map(row => ({ ...row }));
        else statement.run(...values);
        const changes = Number(db.prepare("SELECT total_changes() AS n").get().n) - before;
        return { success: true, meta: { changes }, results };
      },
      async run() { return query.execute(); },
      async all() { return query.execute(); },
      async first() { return query.execute().results[0] ?? null; },
    };
    return query;
  }
  async batch(statements) {
    this.sqlite.exec("BEGIN IMMEDIATE");
    try {
      const result = statements.map(statement => statement.execute());
      this.sqlite.exec("COMMIT");
      return result;
    } catch (error) {
      this.sqlite.exec("ROLLBACK");
      throw error;
    }
  }
  count(table) { return Number(this.sqlite.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get().n); }
  close() { this.sqlite.close(); }
}

const DAY = 86400000;
const NOW = Date.parse("2026-09-11T12:00:00Z");
const TOKEN = "token_00000001";
const OTHER_TOKEN = "token_00000002";
const databases = [];
let sequence;

beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(NOW); sequence = 0; });
afterEach(() => { databases.splice(0).forEach(db => db.close()); vi.useRealTimers(); });

function setup(limits) {
  const db = new SQLiteD1();
  databases.push(db);
  return { db, store: new D1Store(db, limits) };
}

async function seed(store, id = "device_a", token = TOKEN) {
  if (!await store.getDevice(id)) await store.createDevice(id, "hash_a", NOW);
  expect(await store.registerToken(token, { device_id: id, webhook_url: "https://example.com/secret-hook", registered_at: new Date(NOW).toISOString() })).toBe("registered");
}

function event(overrides = {}) {
  return { id: `event_${String(++sequence).padStart(8, "0")}`, token: TOKEN, device_id: "device_a",
    timestamp: new Date(Date.now()).toISOString(), token_revision: 1, classification: "callback", ...overrides };
}

async function message(e, overrides = {}) {
  return { ...await createDeliveryMessage("https://example.com/secret-hook", e,
    { deviceId: e.device_id, canaryType: "generic", label: "test" }, { tokenRevision: e.token_revision }), ...overrides };
}

describe("transactional device and token ownership", () => {
  it("admits only the exact device cap under concurrent requests", async () => {
    const { db, store } = setup({ maxDevices: 3 });
    const results = await Promise.all(Array.from({ length: 20 }, (_, i) => store.createDevice(`device_${i}`, "hash", NOW)));
    expect(results.filter(Boolean)).toHaveLength(3);
    expect(db.count("devices")).toBe(3);
    expect(await store.createDevice("device_0", "other", NOW)).toBe(false);
    expect((await store.getDevice("device_0")).secret_hash).toBe("hash");
    expect(await store.rotateDevice("device_0", "new_hash")).toBe(true);
    expect((await store.getDevice("device_0")).secret_hash).toBe("new_hash");
  });

  it("retains ownership and history across revoke and re-arm, with active and physical caps", async () => {
    const { db, store } = setup({ maxTokens: 1, maxTokensPerDevice: 1, maxTokenRecords: 2, maxTokenRecordsPerDevice: 2 });
    await seed(store);
    await store.createDevice("device_b", "hash_b");
    const e = event();
    const m = await message(e);
    expect(await store.saveEvent(e, [m])).toBe(true);
    expect(await store.revokeToken(TOKEN, "device_b")).toBe(false);
    expect(await store.revokeToken(TOKEN, "device_a")).toBe(true);
    expect((await store.getDelivery(m.delivery_id)).state).toBe("cancelled");
    expect(await store.registerToken(TOKEN, { device_id: "device_b" })).toBe("owner_mismatch");
    expect((await store.getEvents(TOKEN))[0].device_id).toBe("device_a");
    expect(() => db.sqlite.prepare("UPDATE tokens SET device_id = 'device_b' WHERE token = ?").run(TOKEN)).toThrow("immutable token owner");
    expect(await store.registerToken(TOKEN, { device_id: "device_a" })).toBe("registered");
    expect((await store.getToken(TOKEN)).revision).toBe(3);
    expect(await store.registerToken(OTHER_TOKEN, { device_id: "device_a" })).toBe("quota");
    await store.revokeToken(TOKEN, "device_a");
    expect(await store.registerToken(OTHER_TOKEN, { device_id: "device_a" })).toBe("registered");
    await store.revokeToken(OTHER_TOKEN, "device_a");
    expect(await store.registerToken("token_00000003", { device_id: "device_a" })).toBe("quota");
    expect(await store.registerToken(TOKEN, { device_id: "device_a" })).toBe("registered");
    expect(db.count("tokens")).toBe(2);
  });

  it("atomically enforces global and per-device active token limits", async () => {
    const { db, store } = setup({ maxTokens: 3, maxTokensPerDevice: 2 });
    await store.createDevice("device_a", "hash");
    await store.createDevice("device_b", "hash");
    const results = await Promise.all(Array.from({ length: 20 }, (_, i) => store.registerToken(`token_${String(i).padStart(8, "0")}`, { device_id: i % 2 ? "device_b" : "device_a" })));
    expect(results.filter(result => result === "registered")).toHaveLength(3);
    expect(db.count("tokens")).toBe(3);
    expect(db.sqlite.prepare("SELECT MAX(n) AS n FROM (SELECT COUNT(*) AS n FROM tokens GROUP BY device_id)").get().n).toBeLessThanOrEqual(2);
  });

  it("keeps pending deliveries valid during an identical registration repair", async () => {
    const { store } = setup();
    await seed(store);
    const e = event();
    const m = await message(e);
    expect(await store.saveEvent(e, [m])).toBe(true);
    vi.setSystemTime(NOW + 1000);
    const record = { device_id: "device_a", webhook_url: "https://example.com/secret-hook", canary_type: "generic", label: "" };
    expect(await store.registerToken(TOKEN, record)).toBe("registered");
    expect(await store.getToken(TOKEN)).toMatchObject({ revision: 1, registered_at: NOW });
    expect((await store.getDelivery(m.delivery_id)).state).toBe("pending");
    expect(await store.registerToken(TOKEN, { ...record, label: "new placement" })).toBe("registered");
    expect((await store.getToken(TOKEN)).revision).toBe(2);
    expect((await store.getDelivery(m.delivery_id)).state).toBe("cancelled");
    await store.revokeToken(TOKEN, "device_a");
    expect(await store.registerToken(TOKEN, { ...record, label: "new placement" })).toBe("registered");
    expect((await store.getToken(TOKEN)).revision).toBe(4);
  });
});

describe("event admission and evidence", () => {
  it("enforces exact retained and daily admission budgets across concurrent requests", async () => {
    const { db, store } = setup({ retainedEvents: 4, retainedEventsPerDevice: 3, dailyEvents: 5, dailyEventsPerDevice: 3 });
    await seed(store);
    await seed(store, "device_b", OTHER_TOKEN);
    const results = await Promise.all(Array.from({ length: 20 }, (_, i) => store.saveEvent(event(i % 2 ? { token: OTHER_TOKEN, device_id: "device_b" } : {}))));
    expect(results.filter(Boolean)).toHaveLength(4);
    expect(db.count("events")).toBe(4);
    expect(db.sqlite.prepare("SELECT MAX(n) AS n FROM (SELECT COUNT(*) AS n FROM events GROUP BY device_id)").get().n).toBeLessThanOrEqual(3);
  });

  it("uses admission day instead of supplied event time, and resets daily allowance at UTC midnight", async () => {
    const { store } = setup({ dailyEvents: 3, dailyEventsPerDevice: 2 });
    await seed(store);
    await seed(store, "device_b", OTHER_TOKEN);
    expect(await store.saveEvent(event({ timestamp: "2020-01-01T00:00:00Z" }))).toBe(true);
    expect(await store.saveEvent(event({ timestamp: "2030-01-01T00:00:00Z" }))).toBe(true);
    expect(await store.saveEvent(event())).toBe(false);
    expect(await store.saveEvent(event({ token: OTHER_TOKEN, device_id: "device_b" }))).toBe(true);
    expect(await store.saveEvent(event({ token: OTHER_TOKEN, device_id: "device_b" }))).toBe(false);
    vi.setSystemTime(Date.parse("2026-09-12T00:00:00Z"));
    expect(await store.saveEvent(event())).toBe(true);
  });

  it("caps suppressed evidence separately so a preview flood preserves activity capacity", async () => {
    const { db, store } = setup();
    await seed(store);
    await seed(store, "device_a", OTHER_TOKEN);
    const noise = await Promise.all(Array.from({ length: 50 }, (_, i) => store.saveEvent(event({
      classification: i % 2 ? "preview" : "activity", notification_suppressed: i % 2 ? "preview" : "coalesced",
    }))));
    expect(noise.filter(Boolean)).toHaveLength(10);
    const activity = await Promise.all(Array.from({ length: 50 }, () => store.saveEvent(event({ token: OTHER_TOKEN }))));
    expect(activity.filter(Boolean)).toHaveLength(40);
    expect(db.count("events")).toBe(50);
    expect(db.sqlite.prepare("SELECT COUNT(*) AS n FROM events WHERE suppressed = 1").get().n).toBe(10);
  });

  it("returns the newest events and filters a proof before applying the limit", async () => {
    const { store } = setup({ dailyEventsPerDevice: 100 });
    await seed(store);
    const proof = "a".repeat(32);
    const created = [];
    for (let i = 0; i < 30; i++) {
      const e = event({ timestamp: new Date(NOW + i).toISOString(), proof_id: i === 1 ? proof : null });
      created.push(e);
      expect(await store.saveEvent(e)).toBe(true);
    }
    expect((await store.getEvents(TOKEN)).map(e => e.id)).toEqual(created.slice(20).reverse().map(e => e.id));
    expect((await store.getEvents(TOKEN, { proofId: proof, limit: 1 })).map(e => e.id)).toEqual([created[1].id]);
    expect(await store.getEvents(TOKEN, { proofId: "b".repeat(32) })).toEqual([]);
  });

  it("atomically persists the event and outbox, without replaying duplicate admissions", async () => {
    const { db, store } = setup();
    await seed(store);
    const e = event();
    const m = await message(e);
    expect(await store.saveEvent(e, [m])).toBe(true);
    expect(await store.saveEvent(e, [m])).toBe(false);
    expect(db.count("events")).toBe(1);
    expect(db.count("deliveries")).toBe(1);
    expect((await store.getDelivery(m.delivery_id)).message).toEqual(m);
    expect((await store.getDelivery(m.delivery_id)).message_json).not.toContain("https://example.com/secret-hook");
    expect((await store.getEvents(TOKEN))[0].deliveries).toEqual([{ id: m.delivery_id, state: "pending", attempts: 0, error_code: null }]);
    db.sqlite.exec("CREATE TRIGGER fail_outbox BEFORE INSERT ON deliveries BEGIN SELECT RAISE(ABORT, 'injected outbox failure'); END;");
    const rejected = event();
    await expect(store.saveEvent(rejected, [await message(rejected)])).rejects.toThrow("injected outbox failure");
    expect(db.count("events")).toBe(1);
    expect(db.count("deliveries")).toBe(1);
  });

  it("rejects mismatched, stale, revoked and overflowing delivery admissions", async () => {
    const { db, store } = setup({ maxDeliveryRows: 1 });
    await seed(store);
    const stale = event();
    const staleMessage = await message(stale);
    await store.registerToken(TOKEN, { device_id: "device_a" });
    expect(await store.saveEvent(stale, [staleMessage])).toBe(false);
    const e = event({ token_revision: 2 });
    await expect(store.saveEvent(e, [await message(e, { token_revision: 1 })])).rejects.toThrow("identity mismatch");
    expect(await store.saveEvent(e, [await message(e)])).toBe(true);
    const overflow = event({ token_revision: 2 });
    expect(await store.saveEvent(overflow, [await message(overflow)])).toBe(false);
    expect(db.count("events")).toBe(1);
    await store.revokeToken(TOKEN, "device_a");
    expect(await store.saveEvent(event({ token_revision: 3 }))).toBe(false);
  });
});

describe("durable delivery leases and budgets", () => {
  async function queued(limits) {
    const context = setup(limits);
    await seed(context.store);
    const e = event();
    const m = await message(e);
    expect(await context.store.saveEvent(e, [m])).toBe(true);
    return { ...context, id: m.delivery_id };
  }

  it("allows only one publisher and one consumer; stale leases cannot finalize new work", async () => {
    const { store, id } = await queued();
    const publications = await Promise.all(Array.from({ length: 20 }, () => store.claimEnqueue(id, NOW)));
    expect(publications.filter(Boolean)).toHaveLength(1);
    const publisher = publications.find(Boolean);
    expect(await store.claimDelivery(id, NOW)).toBeNull();
    expect(await store.markEnqueued(id, NOW, "wrong_lease")).toBe(false);
    expect(await store.markEnqueued(id, NOW, publisher.lease_token)).toBe(true);
    expect(await store.dueDeliveries(NOW)).toEqual([]);
    const consumers = await Promise.all(Array.from({ length: 20 }, () => store.claimDelivery(id, NOW)));
    expect(consumers.filter(Boolean)).toHaveLength(1);
    const first = consumers.find(Boolean);
    vi.setSystemTime(NOW + 31000);
    const replacement = await store.claimDelivery(id, Date.now());
    expect(replacement).not.toBeNull();
    expect(await store.finishDelivery(id, "delivered", 1, Date.now(), null, first.lease_token)).toBe(false);
    expect(await store.finishDelivery(id, "delivered", 1, Date.now(), null, replacement.lease_token)).toBe(true);
    expect(await store.claimDelivery(id, Date.now())).toBeNull();
    expect((await store.getEvents(TOKEN))[0].deliveries[0].state).toBe("delivered");
  });

  it("backs off failed publication, and reconciles a lost enqueued message after one hour", async () => {
    const { store, id } = await queued();
    const first = await store.claimEnqueue(id, NOW);
    expect(await store.releaseEnqueue(id, NOW, first.lease_token)).toBe(true);
    expect(await store.claimEnqueue(id, NOW + 59000)).toBeNull();
    const second = await store.claimEnqueue(id, NOW + 60000);
    expect(second).not.toBeNull();
    expect(await store.markEnqueued(id, NOW + 60000, second.lease_token)).toBe(true);
    expect(await store.dueDeliveries(NOW + 3599999)).toEqual([]);
    expect((await store.dueDeliveries(NOW + 3660000)).map(row => row.delivery_id)).toEqual([id]);
    expect(await store.claimEnqueue(id, NOW + 3660000)).not.toBeNull();
  });

  it("keeps retry timing and cancellation atomic with active consumer leases", async () => {
    const { store, id } = await queued();
    const first = await store.claimDelivery(id, NOW);
    expect(await store.finishDelivery(id, "pending", 1, NOW + 60000, "http_503", first.lease_token)).toBe(true);
    expect(await store.claimDelivery(id, NOW + 59000)).toBeNull();
    expect(await store.dueDeliveries(NOW + 59000)).toEqual([]);
    vi.setSystemTime(NOW + 60000);
    const second = await store.claimDelivery(id, Date.now());
    expect(second.attempts).toBe(0); // Finalization alone cannot fabricate an outbound attempt.
    await store.revokeToken(TOKEN, "device_a");
    expect(await store.finishDelivery(id, "delivered", 2, Date.now(), null, second.lease_token)).toBe(false);
    expect((await store.getDelivery(id)).state).toBe("cancelled");
  });

  it("reserves per-delivery attempts before a send and preserves the cap after crashes", async () => {
    const { db, store, id } = await queued();
    const first = await store.claimDelivery(id, NOW);
    const reservations = await Promise.all(Array.from({ length: 10 }, () => store.reserveDeliveryAttempt(id, first.lease_token, NOW, 2)));
    expect(reservations.filter(Boolean)).toHaveLength(1);
    expect((await store.getDelivery(id)).attempts).toBe(1);
    // Simulate successful send followed by termination before finishDelivery.
    vi.setSystemTime(NOW + 31000);
    const second = await store.claimDelivery(id, Date.now());
    expect(second.attempts).toBe(1);
    expect(await store.reserveDeliveryAttempt(id, first.lease_token, Date.now(), 2)).toBe(false);
    expect(await store.reserveDeliveryAttempt(id, second.lease_token, Date.now(), 2)).toBe(true);
    vi.setSystemTime(NOW + 62000);
    const third = await store.claimDelivery(id, Date.now());
    expect(third.attempts).toBe(2);
    expect(await store.reserveDeliveryAttempt(id, third.lease_token, Date.now(), 2)).toBe(false);
    expect(db.count("delivery_attempts")).toBe(2);
    expect(await store.finishDelivery(id, "failed", 3, Date.now(), "attempts_exhausted", third.lease_token)).toBe(true);
    expect((await store.getDelivery(id))).toMatchObject({ state: "failed", attempts: 2 });
  });

  it("atomically caps global and per-device outbound attempts", async () => {
    const { db, store } = setup({ dailyAttempts: 5, dailyAttemptsPerDevice: 2 });
    for (const id of ["device_a", "device_b", "device_c"]) await store.createDevice(id, "hash");
    const results = await Promise.all(Array.from({ length: 30 }, (_, i) => store.admitDeliveryAttempt(["device_a", "device_b", "device_c"][i % 3], NOW)));
    expect(results.filter(Boolean)).toHaveLength(5);
    expect(db.count("delivery_attempts")).toBe(5);
    expect(db.sqlite.prepare("SELECT MAX(n) AS n FROM (SELECT COUNT(*) AS n FROM delivery_attempts GROUP BY device_id)").get().n).toBe(2);
    expect(await store.admitDeliveryAttempt("unknown", NOW)).toBe(false);
    expect(await store.admitDeliveryAttempt("device_a", NOW + DAY)).toBe(true);
  });

  it("records age-expired delivery failure before bounded retention cleanup", async () => {
    const { db, store, id } = await queued();
    expect(await store.dueDeliveries(NOW + DAY)).toEqual([]);
    expect((await store.getDelivery(id))).toMatchObject({ state: "failed", error_code: "delivery_expired" });
    expect((await store.getEvents(TOKEN))[0].deliveries[0].state).toBe("failed");
    expect(await store.admitDeliveryAttempt("device_a", NOW)).toBe(true);
    vi.setSystemTime(NOW + 8 * DAY);
    // A backdated event admitted today must survive, preserving today's quota.
    expect(await store.saveEvent(event({ timestamp: new Date(NOW).toISOString() }))).toBe(true);
    await store.cleanup(Date.now());
    expect(db.count("events")).toBe(1);
    expect(db.count("deliveries")).toBe(0);
    expect(db.count("delivery_attempts")).toBe(0);
    expect(db.count("tokens")).toBe(1);
  });

  it("expires the requested queued delivery independently of the bulk cleanup batch", async () => {
    const { store, id } = await queued();
    expect(await store.expireDelivery(id, NOW + DAY - 1)).toBe(false);
    expect(await store.expireDelivery(id, NOW + DAY)).toBe(true);
    expect(await store.expireDelivery(id, NOW + DAY)).toBe(false);
    expect(await store.getDelivery(id)).toMatchObject({ state: "failed", error_code: "delivery_expired", lease_token: null });
  });
});
