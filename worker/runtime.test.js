import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const ORIGIN = "https://snare.invalid";
const TOKEN = "runtime-canary-12345678";
const SECRET = "synthetic-runtime-device-secret-12345678";
const OTHER_SECRET = "synthetic-other-device-secret-123456789";
const WEBHOOK = "https://hooks.slack.com/services/SYNTHETIC/LOCAL/ONLY";
const PROOF = "0123456789abcdef0123456789abcdef";

// These routes exist only in this in-memory test module. Application requests
// still execute the unchanged receiver in workerd. Running SQL inside workerd
// also avoids Miniflare 5 alpha's synchronous Node D1 proxy; this is real D1,
// including its batch transactions, constraints, and query result metadata.
const harness = `
import receiver from "./index.js";
export default {
  async fetch(request, env, ctx) {
    const path = new URL(request.url).pathname;
    if (path === "/__runtime/sql") {
      const statements = await request.json();
      try {
        const result = await env.SNARE_DB.batch(statements.map(({ sql, params = [] }) =>
          env.SNARE_DB.prepare(sql).bind(...params)));
        return Response.json(result);
      } catch (error) {
        return Response.json({ error: error.message }, { status: 500 });
      }
    }
    if (path === "/__runtime/scheduled") {
      const pending = [];
      await receiver.scheduled({}, env, { waitUntil: promise => pending.push(promise) });
      await Promise.all(pending);
      return new Response(null, { status: 204 });
    }
    return receiver.fetch(request, env, ctx);
  },
};`;

// Keep complete CREATE TRIGGER ... BEGIN ... END statements together. D1 exec
// treats newlines as separators, so use prepare/batch for the checked-in SQL.
function migrationStatements() {
  const source = readFileSync(new URL("./migrations/0001_state.sql", import.meta.url), "utf8");
  const statements = [];
  let current = "";
  for (const line of source.split("\n")) {
    if (line.trim().startsWith("--")) continue;
    current += `${line}\n`;
    if (/;\s*$/.test(line) && (!/^\s*CREATE TRIGGER/i.test(current) || /^\s*END;\s*$/.test(line))) {
      statements.push({ sql: current.trim() });
      current = "";
    }
  }
  if (current.trim()) throw new Error("Unterminated migration statement");
  return statements;
}

let runtime;
let outbound;
let sinkStatus;

beforeEach(async () => {
  outbound = [];
  sinkStatus = 503;
  // Wrangler's pinned Miniflare 5 exposes this v4 compatibility adapter. Explicit
  // modules include the production import graph without bundling a test route
  // into index.js or adding another build dependency.
  runtime = new Miniflare(convertV4MiniflareOptions({
    name: "snare-runtime-test", port: 0, cf: false, unsafeRegisterWorker: false,
    compatibilityDate: "2026-07-24",
    modules: [
      { type: "ESModule", path: fileURLToPath(new URL("./__runtime_test_harness.js", import.meta.url)), contents: harness },
      ...["index.js", "policy.js", "store.js", "delivery.js", "outbox.js"].map(name => ({
        type: "ESModule", path: fileURLToPath(new URL(name, import.meta.url)),
      })),
    ],
    d1Databases: ["SNARE_DB"],
    bindings: { STORAGE_BACKEND: "d1", ENROLLMENT_MODE: "open", RATE_LIMITS_REQUIRED: "true" },
    ratelimits: Object.fromEntries([
      "ENROLLMENT_RATE_LIMITER", "API_SOURCE_RATE_LIMITER", "API_DEVICE_RATE_LIMITER", "CALLBACK_SOURCE_RATE_LIMITER",
    ].map((name, index) => [name, { namespace_id: String(index + 1), simple: { limit: 1000, period: 60 } }])),
    outboundService: async request => {
      outbound.push({ url: request.url, body: await request.text(), headers: Object.fromEntries(request.headers) });
      return new Response(null, { status: sinkStatus });
    },
  }));
  const results = await sqlBatch(migrationStatements());
  expect(results.every(result => result.success && result.meta.served_by === "miniflare.db")).toBe(true);
}, 20000);

afterEach(async () => { await runtime?.dispose(); }, 20000);

function request(path, body, secret = SECRET) {
  return runtime.dispatchFetch(`${ORIGIN}${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: { "content-type": "application/json", ...(secret ? { authorization: `Bearer ${secret}` } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

async function sqlBatch(statements) {
  const response = await request("/__runtime/sql", statements, null);
  const result = await response.json();
  if (!response.ok) throw new Error(result.error);
  return result;
}

async function rows(sql, params = []) { return (await sqlBatch([{ sql, params }]))[0].results; }

async function enroll(secret = SECRET) {
  const response = await request("/api/devices", { device_secret: secret }, null);
  expect(response.status).toBe(200);
  return (await response.json()).device_id;
}

function register(deviceId, secret = SECRET, token = TOKEN) {
  return request("/api/register", {
    device_id: deviceId, token_id: token, webhook_url: WEBHOOK, canary_type: "generic", label: "runtime fixture",
  }, secret);
}

async function callback(suffix = "", init = {}) {
  const response = await runtime.dispatchFetch(`${ORIGIN}/c/${TOKEN}${suffix}`, {
    method: "POST", headers: { "user-agent": "curl/runtime-fixture" }, ...init,
  });
  // Drain the response independently of waitUntil delivery work.
  await response.arrayBuffer();
  return response;
}

async function eventually(check) {
  const deadline = Date.now() + 5000;
  let failure;
  do {
    try { return await check(); } catch (error) { failure = error; }
    await new Promise(resolve => setTimeout(resolve, 20));
  } while (Date.now() < deadline);
  throw failure;
}

async function failedFirstDelivery() {
  return eventually(async () => {
    const delivery = (await rows("SELECT * FROM deliveries"))[0];
    expect(delivery).toMatchObject({ state: "pending", attempts: 1, error_code: "http_503" });
    return delivery;
  });
}

describe("Cloudflare runtime with real D1", () => {
  it("applies the real owner trigger and rolls back a batch that violates it", async () => {
    const owner = await enroll();
    const other = await enroll(OTHER_SECRET);
    expect((await register(owner)).status).toBe(200);
    expect(await rows("SELECT name FROM sqlite_master WHERE type = 'trigger'")).toContainEqual({ name: "tokens_immutable_owner" });
    await expect(sqlBatch([
      { sql: "INSERT INTO devices (device_id, secret_hash, created_at) VALUES (?, ?, ?)", params: ["must-rollback", "synthetic", Date.now()] },
      { sql: "UPDATE tokens SET device_id = ? WHERE token = ?", params: [other, TOKEN] },
    ])).rejects.toThrow("immutable token owner");
    expect(await rows("SELECT device_id FROM devices WHERE device_id = 'must-rollback'")).toEqual([]);
    expect(await rows("SELECT device_id FROM tokens WHERE token = ?", [TOKEN])).toEqual([{ device_id: owner }]);
  });

  it("admits exactly one owner under concurrent HTTP first claims", async () => {
    const owners = [await enroll(), await enroll(OTHER_SECRET)];
    const secrets = [SECRET, OTHER_SECRET];
    const responses = await Promise.all(Array.from({ length: 20 }, (_, index) => register(owners[index % 2], secrets[index % 2])));
    const token = (await rows("SELECT device_id, revision FROM tokens WHERE token = ?", [TOKEN]))[0];
    const winner = owners.indexOf(token.device_id);
    expect(winner).toBeGreaterThanOrEqual(0);
    expect(token.revision).toBe(1);
    expect(responses.map(response => response.status)).toEqual(responses.map((_, index) => index % 2 === winner ? 200 : 403));
    expect(await rows("SELECT COUNT(*) AS count FROM tokens")).toEqual([{ count: 1 }]);
  });

  it("persists correlated body-blind evidence and an outbox before acknowledging a callback", async () => {
    const owner = await enroll();
    expect((await register(owner)).status).toBe(200);
    const response = await callback(`/proof/${PROOF}/sdk/path?secret=query-not-evidence`, {
      body: "private-body-marker-never-store",
      headers: { "user-agent": "curl/runtime-fixture", authorization: "Bearer private-auth-marker-never-store" },
    });
    expect(response.status).toBe(200);
    const persisted = (await rows("SELECT event_id, proof_id, event_json FROM events"))[0];
    expect(persisted.proof_id).toBe(PROOF);
    expect(JSON.parse(persisted.event_json)).toMatchObject({ id: persisted.event_id, token: TOKEN, device_id: owner, proof_id: PROOF, is_test: false });
    expect(persisted.event_id).toMatch(/^[0-9a-f-]{36}$/);
    expect(await rows("SELECT COUNT(*) AS count FROM deliveries")).toEqual([{ count: 1 }]);
    const delivery = await failedFirstDelivery();
    const observed = await (await request(`/api/events/${TOKEN}?proof_id=${PROOF}`)).json();
    expect(observed.events).toHaveLength(1);
    expect(observed.events[0].id).toBe(persisted.event_id);
    expect(observed.events[0].deliveries).toEqual([{ id: delivery.delivery_id, state: "pending", attempts: 1, error_code: "http_503" }]);
    expect(outbound).toHaveLength(1);
    expect(outbound[0].url).toBe(WEBHOOK);
    for (const value of [persisted.event_json, delivery.message_json, outbound[0].body]) {
      expect(value).not.toContain("private-body-marker");
      expect(value).not.toContain("private-auth-marker");
      expect(value).not.toContain("query-not-evidence");
    }
    expect(delivery.message_json).not.toContain(WEBHOOK);
  });

  it("retries persisted delivery through the scheduled handler and exposes terminal success", async () => {
    const owner = await enroll();
    await register(owner);
    expect((await callback(`/proof/${PROOF}`)).status).toBe(200);
    const pending = await failedFirstDelivery();
    sinkStatus = 204;
    await rows("UPDATE deliveries SET next_attempt_at = 0 WHERE delivery_id = ?", [pending.delivery_id]);
    expect((await request("/__runtime/scheduled", {}, null)).status).toBe(204);
    expect((await rows("SELECT state, attempts, error_code FROM deliveries"))[0]).toEqual({ state: "delivered", attempts: 2, error_code: null });
    expect(outbound).toHaveLength(2);
    expect(outbound[0].headers["x-snare-delivery-id"]).toBe(pending.delivery_id);
    expect(outbound[1].headers["x-snare-delivery-id"]).toBe(pending.delivery_id);
    const observed = await (await request(`/api/events/${TOKEN}?proof_id=${PROOF}`)).json();
    expect(observed.events[0].deliveries[0]).toMatchObject({ state: "delivered", attempts: 2 });
    expect((await rows("SELECT COUNT(*) AS count FROM delivery_attempts"))[0].count).toBe(2);
  });

  it("filters a proof before limiting a history with forty newer events", async () => {
    const owner = await enroll();
    await register(owner);
    expect((await callback(`/proof/${PROOF}`)).status).toBe(200);
    await failedFirstDelivery();
    const proofEvent = (await rows("SELECT event_id, timestamp FROM events"))[0];
    const now = Date.now();
    await sqlBatch(Array.from({ length: 40 }, (_, index) => {
      const id = `newer-event-${String(index).padStart(2, "0")}`;
      const timestamp = proofEvent.timestamp + index + 1;
      return {
        sql: `INSERT INTO events (event_id, token, device_id, timestamp, admitted_at, admission_day,
          admission_id, proof_id, token_revision, event_json) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        params: [id, TOKEN, owner, timestamp, now, Math.floor(now / 86400000), id, null, 1,
          JSON.stringify({ id, token: TOKEN, device_id: owner, timestamp: new Date(timestamp).toISOString(), proof_id: null, is_test: false })],
      };
    }));
    const page = await (await request(`/api/events/${TOKEN}`)).json();
    expect(page.events).toHaveLength(10);
    expect(page.events[0].id).toBe("newer-event-39");
    expect(page.events.some(event => event.id === proofEvent.event_id)).toBe(false);
    const matching = await (await request(`/api/events/${TOKEN}?proof_id=${PROOF}`)).json();
    expect(matching.events.map(event => event.id)).toEqual([proofEvent.event_id]);
    const missing = await request(`/api/events/${TOKEN}?proof_id=${"f".repeat(32)}`);
    expect(missing.status).toBe(200);
    expect((await missing.json()).events).toEqual([]);
    expect((await request(`/api/events/${TOKEN}?proof_id=invalid`)).status).toBe(400);
  });

  it("keeps revoked history private, cancels pending delivery, and permits only the original owner to re-arm", async () => {
    const owner = await enroll();
    const other = await enroll(OTHER_SECRET);
    await register(owner);
    await callback(`/proof/${PROOF}`);
    await failedFirstDelivery();
    expect((await request("/api/revoke", { token_id: TOKEN, device_id: owner })).status).toBe(200);
    expect((await register(other, OTHER_SECRET)).status).toBe(403);
    expect((await request(`/api/events/${TOKEN}`, undefined, OTHER_SECRET)).status).toBe(401);
    const history = await (await request(`/api/events/${TOKEN}`)).json();
    expect(history.events).toHaveLength(1);
    expect(history.events[0].device_id).toBe(owner);
    expect(history.events[0].deliveries[0].state).toBe("cancelled");
    expect((await callback()).status).toBe(200);
    expect((await rows("SELECT COUNT(*) AS count FROM events"))[0].count).toBe(1);
    expect((await register(owner)).status).toBe(200);
    expect((await rows("SELECT device_id, revision, revoked FROM tokens"))[0]).toEqual({ device_id: owner, revision: 3, revoked: 0 });
    sinkStatus = 204;
    expect((await request("/__runtime/scheduled", {}, null)).status).toBe(204);
    expect(outbound).toHaveLength(1);
  });

  it("does not acknowledge or retain an event whose outbox insert rolls back", async () => {
    const owner = await enroll();
    await register(owner);
    await rows("CREATE TRIGGER injected_delivery_failure BEFORE INSERT ON deliveries BEGIN SELECT RAISE(ABORT, 'runtime outbox failure'); END;");
    expect((await callback(`/proof/${PROOF}`)).status).toBe(503);
    expect(await rows("SELECT COUNT(*) AS count FROM events")).toEqual([{ count: 0 }]);
    expect(await rows("SELECT COUNT(*) AS count FROM deliveries")).toEqual([{ count: 0 }]);
    expect(outbound).toHaveLength(0);
  });
});
