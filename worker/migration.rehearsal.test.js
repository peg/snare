import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { exportNamespace } from "./scripts/export-kv.mjs";
import { compileMigration } from "./scripts/migrate-kv-to-d1.mjs";

const ORIGIN = "https://snare.invalid";
const ACCOUNT = "a".repeat(32);
const NAMESPACE = "b".repeat(32);
const NOW = Date.now();
const DEVICES = 2400;
const OWNERS = [8, 4, 3, 2, 1];
const secretFor = i => `synthetic-rehearsal-secret-${String(i).padStart(6, "0")}-xxxxxx`;
const deviceFor = i => `dev_r_${String(i).padStart(5, "0")}`;
const sha = value => createHash("sha256").update(value).digest("hex");

function syntheticKV() {
  const kv = new Map();
  for (let i = 0; i < DEVICES; i++) {
    const at = new Date(NOW - (DEVICES - i) * 3600_000).toISOString();
    kv.set(`device:${deviceFor(i)}`, JSON.stringify(i < 4 ? { secret_hash: sha(secretFor(i)), registered_at: at }
      : { secret_hash: sha(secretFor(i)), created_at: at }));
  }
  let n = 0;
  OWNERS.forEach((count, owner) => {
    for (let j = 0; j < count; j++, n++) {
      kv.set(`webhook:tok_rehearsal_${String(n).padStart(3, "0")}`, JSON.stringify({
        device_id: deviceFor(owner), webhook_url: n < 8 ? "use-global" : `https://discord.com/api/webhooks/0/synthetic-${n}`,
        canary_type: n < 3 ? null : n === 17 ? "awsproc" : "aws", label: `rehearsal ${n}`, registered_at: new Date(NOW - 86400000).toISOString(),
      }));
    }
  });
  const inverted = String(9999999999999 - (NOW - 60000)).padStart(13, "0");
  kv.set(`evr:tok_rehearsal_017:${inverted}:44444444-4444-4444-4444-444444444444`, JSON.stringify({
    id: "evt_rehearsal_imported", token: "tok_rehearsal_017", device_id: deviceFor(4),
    timestamp: new Date(NOW - 60000).toISOString(), method: "GET", userAgent: "aws-cli/rehearsal",
  }));
  kv.set("rl:api:192.0.2.9:1", "3");
  kv.set("dedup:tok_rehearsal_017:192.0.2.9:1", "1");
  return kv;
}

function kvApi(kv) {
  const names = [...kv.keys()].sort();
  return async (url, init = {}) => {
    const u = new URL(url);
    expect(u.pathname.startsWith(`/client/v4/accounts/${ACCOUNT}/storage/kv/namespaces/${NAMESPACE}/`)).toBe(true);
    if (u.pathname.endsWith("/keys")) {
      const start = Number(u.searchParams.get("cursor") || 0);
      const page = names.slice(start, start + 1000);
      const next = start + 1000 < names.length ? String(start + 1000) : "";
      return Response.json({ success: true, result: page.map(name => ({ name })), result_info: { cursor: next } });
    }
    if (u.pathname.endsWith("/bulk/get") && init.method === "POST") {
      const { keys, type } = JSON.parse(init.body);
      expect(type).toBe("text");
      expect(keys.length).toBeLessThanOrEqual(100);
      return Response.json({ success: true, result: { values: Object.fromEntries(keys.map(k => [k, kv.get(k)])) } });
    }
    return Response.json({ success: false }, { status: 404 });
  };
}

const harness = `
import receiver from "./index.js";
export default {
  async fetch(request, env, ctx) {
    if (new URL(request.url).pathname === "/__rehearsal/sql") {
      const statements = await request.json();
      try {
        const result = await env.SNARE_DB.batch(statements.map(({ sql, params = [] }) => env.SNARE_DB.prepare(sql).bind(...params)));
        return Response.json(result);
      } catch (error) { return Response.json({ error: error.message }, { status: 500 }); }
    }
    return receiver.fetch(request, env, ctx);
  },
};`;

function statements(source, { triggers = false } = {}) {
  const out = [];
  let current = "";
  for (const line of source.split("\n")) {
    if (line.trim().startsWith("--") || (!current && !line.trim())) continue;
    current += `${line}\n`;
    if (/;\s*$/.test(line) && (!triggers || !/^\s*CREATE TRIGGER/i.test(current) || /^\s*END;\s*$/.test(line))) {
      out.push({ sql: current.trim() });
      current = "";
    }
  }
  if (current.trim()) throw new Error("Unterminated statement");
  return out;
}

let runtime;
let outbound = [];
let exported;
let migration;

async function sql(batch) {
  const response = await runtime.dispatchFetch(`${ORIGIN}/__rehearsal/sql`, { method: "POST", body: JSON.stringify(batch) });
  const body = await response.json();
  if (!response.ok) throw new Error(body.error);
  return body;
}
const rows = async (query, params = []) => (await sql([{ sql: query, params }]))[0].results;
function api(path, body, secret, device) {
  return runtime.dispatchFetch(`${ORIGIN}${path}`, {
    method: body === undefined ? "GET" : "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${secret}`, ...(device ? { "x-snare-device-id": device } : {}) },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

beforeAll(async () => {
  exported = await exportNamespace({ accountId: ACCOUNT, namespaceId: NAMESPACE, token: "synthetic", fetchImpl: kvApi(syntheticKV()) });
  migration = compileMigration(exported.entries, { now: NOW });
  runtime = new Miniflare(convertV4MiniflareOptions({
    name: "snare-rehearsal", port: 0, cf: false, unsafeRegisterWorker: false, compatibilityDate: "2026-07-24",
    modules: [
      { type: "ESModule", path: fileURLToPath(new URL("./__rehearsal_harness.js", import.meta.url)), contents: harness },
      ...["index.js", "policy.js", "store.js", "delivery.js", "outbox.js"].map(name => ({ type: "ESModule", path: fileURLToPath(new URL(name, import.meta.url)) })),
    ],
    d1Databases: ["SNARE_DB"],
    bindings: { STORAGE_BACKEND: "d1", ENROLLMENT_MODE: "open", RATE_LIMITS_REQUIRED: "true", WEBHOOK_URLS: "https://hooks.slack.com/services/SYNTHETIC/GLOBAL" },
    ratelimits: Object.fromEntries(["ENROLLMENT_RATE_LIMITER", "API_SOURCE_RATE_LIMITER", "API_DEVICE_RATE_LIMITER", "CALLBACK_SOURCE_RATE_LIMITER", "NOTIFICATION_RATE_LIMITER"]
      .map((name, i) => [name, { namespace_id: String(i + 1), simple: { limit: 10000, period: 60 } }])),
    outboundService: async request => { outbound.push(request.url); return new Response(null, { status: 204 }); },
  }));
  await sql(statements(readFileSync(new URL("./migrations/0001_state.sql", import.meta.url), "utf8"), { triggers: true }));
  await sql(statements(migration.sql));
}, 60000);

afterAll(async () => { await runtime?.dispose(); }, 20000);

describe("KV -> D1 migration rehearsal", () => {
  it("exports every key and converts with the default (growth) limits", () => {
    expect(exported.counts).toEqual({ total: DEVICES + 21, byPrefix: { device: DEVICES, webhook: 18, evr: 1, rl: 1, dedup: 1 } });
    expect(migration.counts).toMatchObject({ devices: DEVICES, activeTokens: 18, revokedTokens: 0, events: 1,
      inferredTombstones: 0, ignoredTransientRecords: 2 });
  });

  it("imports matching row counts, ownership, and legacy timestamps", async () => {
    expect(await rows("SELECT (SELECT COUNT(*) FROM devices) AS d, (SELECT COUNT(*) FROM tokens) AS t, (SELECT COUNT(*) FROM events) AS e, (SELECT COUNT(*) FROM deliveries) AS q"))
      .toEqual([{ d: DEVICES, t: 18, e: 1, q: 0 }]);
    expect(await rows("SELECT device_id, COUNT(*) AS n FROM tokens GROUP BY device_id ORDER BY n DESC"))
      .toEqual(OWNERS.map((n, i) => ({ device_id: deviceFor(i), n })));
    expect(await rows("SELECT COUNT(*) AS n FROM tokens WHERE webhook_url = 'use-global'")).toEqual([{ n: 8 }]);
    expect((await rows("SELECT created_at FROM devices WHERE device_id = ?", [deviceFor(0)]))[0].created_at).toBeGreaterThan(0);
  });

  it("keeps trigger-maintained totals equal to row counts, at constant read cost", async () => {
    const [counted, exact] = await sql([
      { sql: "SELECT name, n FROM counts WHERE day = -1 AND name IN ('devices', 'tokens', 'tokens_active', 'events') ORDER BY name" },
      { sql: "SELECT (SELECT COUNT(*) FROM devices) AS devices, (SELECT COUNT(*) FROM events) AS events, (SELECT COUNT(*) FROM tokens) AS tokens, (SELECT COUNT(*) FROM tokens WHERE revoked = 0) AS tokens_active" },
    ]);
    expect(Object.fromEntries(counted.results.map(r => [r.name, r.n]))).toEqual(exact.results[0]);
    expect(counted.meta.rows_read).toBeLessThan(10);
    expect(exact.meta.rows_read).toBeGreaterThan(DEVICES);
  });

  it("authenticates original device secrets and keeps token owners immutable", async () => {
    const own = await api("/api/register", { device_id: deviceFor(0), token_id: "tok_rehearsal_000", webhook_url: "use-global",
      canary_type: "aws", label: "re-armed" }, secretFor(0));
    expect(own.status).toBe(200);
    const stolen = await api("/api/register", { device_id: deviceFor(1500), token_id: "tok_rehearsal_000",
      webhook_url: "https://discord.com/api/webhooks/0/attacker", canary_type: "aws" }, secretFor(1500));
    expect(stolen.status).toBe(403);
    expect((await api("/api/register", { device_id: deviceFor(2), token_id: "tok_rehearsal_new", webhook_url: "https://discord.com/api/webhooks/0/x",
      canary_type: "aws" }, secretFor(1))).status).toBe(401);
    expect((await rows("SELECT device_id FROM tokens WHERE token = 'tok_rehearsal_000'"))[0].device_id).toBe(deviceFor(0));
  });

  it("serves imported history and admits, stores, and delivers a new callback", async () => {
    const history = await (await api("/api/events/tok_rehearsal_017", undefined, secretFor(4), deviceFor(4))).json();
    expect(history.events.map(e => e.id)).toContain("evt_rehearsal_imported");
    const hit = await runtime.dispatchFetch(`${ORIGIN}/c/tok_rehearsal_017`, { method: "POST", headers: { "user-agent": "curl/rehearsal" } });
    await hit.arrayBuffer();
    expect(hit.status).toBe(200);
    expect(await rows("SELECT COUNT(*) AS n FROM events WHERE token = 'tok_rehearsal_017'")).toEqual([{ n: 2 }]);
    expect(await rows("SELECT COUNT(*) AS n FROM deliveries")).toEqual([{ n: 1 }]);
    const deadline = Date.now() + 5000;
    while (!outbound.length && Date.now() < deadline) await new Promise(r => setTimeout(r, 20));
    expect(outbound).toEqual(["https://discord.com/api/webhooks/0/synthetic-17"]);
  });

  it("refuses to re-import over the now-populated database", async () => {
    await expect(sql(statements(migration.sql))).rejects.toThrow(/NOT NULL/);
    expect(await rows("SELECT COUNT(*) AS n FROM devices")).toEqual([{ n: DEVICES }]);
  });
});
