import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import worker from "./index.js";
import { D1Store } from "./store.js";
import { SQLiteD1 } from "./test-support/sqlite.js";

const NOW = Date.parse("2026-09-11T12:00:00Z");
const TOKEN = "receiver-token-12345678";
const WEBHOOK = "https://hooks.slack.com/services/LOCAL/TEST/NO-NETWORK";
const SECRET = "synthetic-device-secret-for-receiver-fixtures";
const databases = [];

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(NOW);
  vi.stubGlobal("fetch", vi.fn(async () => { throw new Error("unexpected external request in receiver fixture"); }));
});
afterEach(() => {
  databases.splice(0).forEach(db => db.close());
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

function fixture(overrides = {}) {
  const db = new SQLiteD1();
  databases.push(db);
  const queued = [];
  const env = {
    SNARE_DB: db, STORAGE_BACKEND: "d1", ENROLLMENT_MODE: "open", RATE_LIMITS_REQUIRED: "true",
    WEBHOOK_DELIVERY_QUEUE: { send: vi.fn(async message => { queued.push(message); }) },
    ...Object.fromEntries(["ENROLLMENT_RATE_LIMITER", "API_SOURCE_RATE_LIMITER", "CALLBACK_SOURCE_RATE_LIMITER", "API_DEVICE_RATE_LIMITER"]
      .map(name => [name, { limit: vi.fn(async () => ({ success: true })) }])),
    ...overrides,
  };
  return { db, env, queued, store: new D1Store(db) };
}

async function invoke(env, request) {
  const pending = [];
  const response = await worker.fetch(request, env, { waitUntil(promise) { pending.push(promise); } });
  await Promise.all(pending);
  return response;
}

function api(path, body, secret = SECRET) {
  return new Request(`https://snare.invalid/api/${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: { "content-type": "application/json", "cf-connecting-ip": "192.0.2.1", ...(secret ? { authorization: `Bearer ${secret}` } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

async function enroll(env, secret = SECRET) {
  const response = await invoke(env, api("devices", { device_secret: secret }, null));
  expect(response.status).toBe(200);
  return (await response.json()).device_id;
}

async function register(env, deviceId, options = {}, secret = SECRET) {
  return invoke(env, api("register", {
    token_id: TOKEN, device_id: deviceId, webhook_url: WEBHOOK, canary_type: "generic", label: "fixture", ...options,
  }, secret));
}

function callback(path = "", headers = {}) {
  return new Request(`https://snare.invalid/c/${TOKEN}${path}`, {
    method: "POST", headers: { "user-agent": "curl/local-fixture", "cf-connecting-ip": "192.0.2.1", ...headers },
  });
}

describe("integrated receiver admission and evidence", () => {
  it("denies public use-global registration while keeping authorized public destinations usable", async () => {
    const { env, db, queued } = fixture({ WEBHOOK_URLS: WEBHOOK });
    const deviceId = await enroll(env);
    const denied = await register(env, deviceId, { webhook_url: "use-global" });
    expect(denied.status).toBe(403);
    expect(db.count("tokens")).toBe(0);
    expect((await invoke(env, callback())).status).toBe(200);
    expect(db.count("events")).toBe(0);
    expect(queued).toHaveLength(0);
    expect((await register(env, deviceId)).status).toBe(200);
    expect((await invoke(env, callback())).status).toBe(200);
    expect(db.count("events")).toBe(1);
    expect(queued).toHaveLength(1);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("gates new enrollment without disabling existing device management", async () => {
    const { env, db } = fixture();
    const deviceId = await enroll(env);
    env.ENROLLMENT_MODE = "closed";
    expect((await invoke(env, api("devices", { device_secret: SECRET }, null))).status).toBe(403);
    expect(db.count("devices")).toBe(1);
    expect((await register(env, deviceId)).status).toBe(200);
    expect((await invoke(env, api(`events/${TOKEN}`))).status).toBe(200);
  });

  it("fails closed without persistent side effects when configured burst protection is unavailable", async () => {
    const { env, db } = fixture();
    env.ENROLLMENT_RATE_LIMITER.limit.mockRejectedValueOnce(new Error("fixture limiter unavailable"));
    const failed = await invoke(env, api("devices", { device_secret: SECRET }, null));
    expect(failed.status).toBe(503);
    expect(db.count("devices")).toBe(0);
    const owner = await enroll(env);
    env.API_DEVICE_RATE_LIMITER.limit.mockRejectedValueOnce(new Error("fixture limiter unavailable"));
    expect((await register(env, owner)).status).toBe(503);
    expect(db.count("tokens")).toBe(0);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("keeps original history private after revoke and refuses another enrolled owner's claim", async () => {
    const { env, store } = fixture();
    const owner = await enroll(env);
    const otherSecret = `${SECRET}-other`;
    const other = await enroll(env, otherSecret);
    expect((await register(env, owner)).status).toBe(200);
    await invoke(env, callback());
    expect((await invoke(env, api("revoke", { token_id: TOKEN, device_id: owner }))).status).toBe(200);
    expect((await register(env, other, {}, otherSecret)).status).toBe(403);
    expect((await invoke(env, api(`events/${TOKEN}`, undefined, otherSecret))).status).toBe(401);
    const response = await invoke(env, api(`events/${TOKEN}`));
    expect(response.status).toBe(200);
    const result = await response.json();
    expect(result.events).toHaveLength(1);
    expect(result.events[0].device_id).toBe(owner);
    expect(result.events[0].deliveries[0].state).toBe("cancelled");
    expect((await store.getToken(TOKEN)).device_id).toBe(owner);
  });

  it("returns the newest page and finds an old proof before limiting a 40-event history", async () => {
    const { env } = fixture();
    const owner = await enroll(env);
    await register(env, owner);
    const proof = "a".repeat(32);
    for (let i = 0; i < 40; i++) {
      vi.setSystemTime(NOW + i * 1000);
      const suffix = i === 1 ? `/proof/${proof}/v1/test` : `/sample/${i}`;
      expect((await invoke(env, callback(suffix))).status).toBe(200);
    }
    const recent = await (await invoke(env, api(`events/${TOKEN}`))).json();
    expect(recent.events).toHaveLength(10);
    expect(recent.events.map(event => event.path.split("/").at(-1))).toEqual(Array.from({ length: 10 }, (_, i) => String(39 - i)));
    const found = await (await invoke(env, api(`events/${TOKEN}?proof_id=${proof}`))).json();
    expect(found.events).toHaveLength(1);
    expect(found.events[0].proof_id).toBe(proof);
    expect((await invoke(env, api(`events/${TOKEN}?proof_id=invalid`))).status).toBe(400);
  });

  it("never accesses callback body properties or readers, including durable ingestion", async () => {
    const { env, db, queued } = fixture();
    const owner = await enroll(env);
    await register(env, owner);
    const req = callback("/v1/messages", { authorization: "Bearer real-sensitive-value-not-stored" });
    const touched = vi.fn(() => { throw new Error("body must not be read"); });
    for (const property of ["body", "bodyUsed"]) Object.defineProperty(req, property, { get: touched });
    for (const method of ["text", "json", "arrayBuffer", "formData", "blob", "clone"]) req[method] = touched;
    expect((await invoke(env, req)).status).toBe(200);
    expect(touched).not.toHaveBeenCalled();
    expect(db.count("events")).toBe(1);
    expect(JSON.stringify(queued)).not.toContain("real-sensitive-value-not-stored");
    expect(JSON.stringify(queued)).not.toContain(WEBHOOK);
  });

  it("retains spoofed preview evidence and prevents unsigned AWS probes from poisoning signed callbacks", async () => {
    const { env, db, store, queued } = fixture();
    const owner = await enroll(env);
    await register(env, owner, { canary_type: "aws" });
    expect((await invoke(env, callback("/preview", { "user-agent": "Slackbot" }))).status).toBe(200);
    expect((await invoke(env, callback("/unsigned"))).status).toBe(200);
    expect((await invoke(env, callback("/signed", { authorization: "AWS4-HMAC-SHA256 credential-not-stored" }))).status).toBe(200);
    expect(db.count("events")).toBe(3);
    const events = await store.getEvents(TOKEN);
    expect(events.map(event => event.classification).sort()).toEqual(["activity", "preview", "probe"]);
    expect(events.find(event => event.classification === "activity").notification_suppressed).toBeNull();
    expect(queued).toHaveLength(1);
    expect(queued[0].event.path).toContain("/signed");
  });

  it("limits suppressed preview storage while leaving capacity for signed activity on another token", async () => {
    const { env, db, queued, store } = fixture();
    const owner = await enroll(env);
    await register(env, owner);
    const activityToken = "activity-token-12345678";
    expect((await register(env, owner, { token_id: activityToken, canary_type: "aws" })).status).toBe(200);
    for (let i = 0; i < 10; i++) {
      expect((await invoke(env, callback(`/preview/${i}`, { "user-agent": "Slackbot" }))).status).toBe(200);
    }
    const changes = db.changes();
    for (let i = 0; i < 10; i++) {
      expect((await invoke(env, callback(`/preview/rejected/${i}`, { "user-agent": "Slackbot" }))).status).toBe(429);
    }
    expect(db.changes()).toBe(changes);
    expect(db.count("events")).toBe(10);
    expect(queued).toHaveLength(0);
    const signed = new Request(`https://snare.invalid/c/${activityToken}/signed`, {
      method: "POST", headers: {
        "user-agent": "aws-sdk-go/fixture", "cf-connecting-ip": "192.0.2.1",
        authorization: "AWS4-HMAC-SHA256 synthetic-credentials-not-retained",
      },
    });
    expect((await invoke(env, signed)).status).toBe(200);
    expect(db.count("events")).toBe(11);
    expect(queued).toHaveLength(1);
    expect((await store.getEvents(activityToken))[0]).toMatchObject({ classification: "activity", notification_suppressed: null });
    expect(JSON.stringify(queued)).not.toContain("synthetic-credentials-not-retained");
  });

  it("returns a service error instead of acknowledging unpersisted callback evidence", async () => {
    const { env, db } = fixture();
    const owner = await enroll(env);
    await register(env, owner);
    db.sqlite.exec("CREATE TRIGGER fail_event BEFORE INSERT ON events BEGIN SELECT RAISE(ABORT, 'injected storage failure'); END;");
    const response = await invoke(env, callback());
    expect(response.status).toBe(503);
    expect(db.count("events")).toBe(0);
    expect(db.count("deliveries")).toBe(0);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("bounds a known-token flood and performs no persistent writes for rejected callbacks", async () => {
    const { env, db, queued } = fixture();
    const owner = await enroll(env);
    await register(env, owner);
    for (let i = 0; i < 50; i++) expect((await invoke(env, callback(`/flood/${i}`))).status).toBe(200);
    const before = db.changes();
    for (let i = 0; i < 20; i++) {
      const response = await invoke(env, callback(`/over-limit/${i}`));
      expect(response.status).toBe(429);
      expect((await response.json()).code).toBe("event_admission_limited");
    }
    expect(db.count("events")).toBe(50);
    expect(db.count("deliveries")).toBe(50);
    expect(queued).toHaveLength(50);
    expect(db.changes()).toBe(before);
    expect(fetch).not.toHaveBeenCalled();
  });

  it("keeps repeated legacy event reads free of KV counter writes", async () => {
    const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(SECRET)));
    const secretHash = Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
    const data = new Map([
      ["device:legacy-owner", JSON.stringify({ secret_hash: secretHash })],
      [`webhook:${TOKEN}`, JSON.stringify({ device_id: "legacy-owner", webhook_url: WEBHOOK })],
      [`event:${TOKEN}:1:legacy-event`, JSON.stringify({ id: "legacy-event", device_id: "legacy-owner", timestamp: new Date(NOW).toISOString() })],
    ]);
    const put = vi.fn();
    const env = { SNARE_KV: {
      get: vi.fn(async key => data.get(key) ?? null), put,
      list: vi.fn(async ({ prefix }) => ({ keys: [...data.keys()].filter(name => name.startsWith(prefix)).map(name => ({ name })), list_complete: true })),
    } };
    for (let i = 0; i < 12; i++) expect((await invoke(env, api(`events/${TOKEN}`))).status).toBe(200);
    expect(put).not.toHaveBeenCalled();
    expect(env.SNARE_KV.get.mock.calls.flat().some(key => key.startsWith("rl:"))).toBe(false);
  });

  it("rejects oversized legacy history before fetching values past the Free subrequest budget", async () => {
    const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(SECRET)));
    const secretHash = Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
    const data = new Map([
      ["device:legacy-owner", JSON.stringify({ secret_hash: secretHash })],
      [`webhook:${TOKEN}`, JSON.stringify({ device_id: "legacy-owner", webhook_url: WEBHOOK })],
    ]);
    const env = { SNARE_KV: {
      get: vi.fn(async key => data.get(key) ?? null), put: vi.fn(),
      list: vi.fn(async () => ({
        keys: Array.from({ length: 901 }, (_, i) => ({ name: `event:${TOKEN}:${i}:legacy-event` })),
        list_complete: true,
      })),
    } };
    const response = await invoke(env, api(`events/${TOKEN}`));
    expect(response.status).toBe(503);
    expect((await response.json()).code).toBe("history_migration_required");
    expect(env.SNARE_KV.get.mock.calls.flat().some(key => key.startsWith("event:"))).toBe(false);
    expect(env.SNARE_KV.put).not.toHaveBeenCalled();

    // Listed keys can disappear before get(); count those reads too.
    env.SNARE_KV.get.mockClear();
    env.SNARE_KV.list.mockImplementation(async ({ cursor }) => {
      const page = Number(cursor || 0);
      return { keys: Array.from({ length: 100 }, (_, i) => ({ name: `event:${TOKEN}:${page * 100 + i}:expired` })),
        list_complete: false, cursor: String(page + 1) };
    });
    const expired = await invoke(env, api(`events/${TOKEN}`));
    expect(expired.status).toBe(503);
    expect((await expired.json()).code).toBe("history_migration_required");
    expect(env.SNARE_KV.get.mock.calls.length).toBeLessThan(1000);
  });
});
