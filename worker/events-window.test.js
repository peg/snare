import { describe, it, expect } from "vitest";
import worker, { buildTelegramPayload, CANARY_TYPES, eventKey, newestEventKeys } from "./index.js";

// In-memory KV with Cloudflare's lexicographic list order and pagination.
function memoryKV(entries = []) {
  const kv = new Map(entries);
  return {
    map: kv,
    get: async (k) => (kv.has(k) ? kv.get(k) : null),
    puts: [],
    async put(k, v, opts) { this.puts.push({ k, opts }); kv.set(k, v); },
    delete: async (k) => { kv.delete(k); },
    list: async ({ prefix, limit = 1000, cursor }) => {
      const all = [...kv.keys()].filter(k => k.startsWith(prefix)).sort();
      const start = cursor ? Number(cursor) : 0;
      const keys = all.slice(start, start + limit).map(name => ({ name }));
      const done = start + limit >= all.length;
      return { keys, list_complete: done, cursor: done ? undefined : String(start + limit) };
    },
  };
}

async function sha256(input) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

const SECRET = "ownersecret000000000000000000000001";
const DEVICE = "dev-owner";
const TOKEN = "token-window-abc123";

async function ownerEnv(extra = []) {
  return {
    GLOBAL_WEBHOOK_DEVICE_IDS: DEVICE,
    SNARE_KV: memoryKV([
      [`device:${DEVICE}`, JSON.stringify({ secret_hash: await sha256(SECRET) })],
      [`webhook:${TOKEN}`, JSON.stringify({ webhook_url: "use-global", canary_type: "git", device_id: DEVICE })],
      ...extra,
    ]),
  };
}

function readEvents(env, query = "") {
  return worker.fetch(
    new Request(`https://snare.sh/api/events/${TOKEN}${query}`, {
      headers: { authorization: `Bearer ${SECRET}`, "x-snare-device-id": DEVICE },
    }),
    env,
    { waitUntil() {} },
  );
}

function ev(i, extra = {}) {
  const ts = new Date(Date.UTC(2026, 10, 1, 0, i)).toISOString();
  return { token: TOKEN, device_id: DEVICE, timestamp: ts, n: i, ...extra };
}

describe("events window", () => {
  it("returns the newest events when more than 20 are stored", async () => {
    const rows = [];
    for (let i = 0; i < 25; i++) {
      const ms = Date.UTC(2026, 10, 1, 0, i);
      rows.push([eventKey(TOKEN, ms, `id${i}`), JSON.stringify(ev(i))]);
    }
    const resp = await readEvents(await ownerEnv(rows));
    expect(resp.status).toBe(200);
    const body = await resp.json();
    expect(body.events.map(e => e.n)).toEqual([24, 23, 22, 21, 20, 19, 18, 17, 16, 15]);
  });

  it("still finds the newest legacy (oldest-first) keys across list pages", async () => {
    const rows = [];
    for (let i = 0; i < 2100; i++) {
      const ms = Date.UTC(2026, 9, 1) + i * 1000;
      rows.push([`event:${TOKEN}:${ms}:id${i}`, JSON.stringify({ ...ev(0), timestamp: new Date(ms).toISOString(), n: i })]);
    }
    const resp = await readEvents(await ownerEnv(rows));
    const body = await resp.json();
    expect(body.events[0].n).toBe(2099);
    expect(body.events).toHaveLength(10);
  });

  it("prefers new-format keys over legacy ones", async () => {
    const env = await ownerEnv([
      [`event:${TOKEN}:${Date.UTC(2026, 9, 1)}:old`, JSON.stringify(ev(0))],
      [eventKey(TOKEN, Date.UTC(2026, 10, 2), "new"), JSON.stringify(ev(99))],
    ]);
    expect(await newestEventKeys(env, TOKEN, 1)).toEqual([eventKey(TOKEN, Date.UTC(2026, 10, 2), "new")]);
  });
});

describe("proof correlation", () => {
  const PROOF = "0123456789abcdef0123456789abcdef";

  it("stores proof_id and event id from a /proof/{nonce} callback", async () => {
    const env = await ownerEnv();
    let pending;
    const resp = await worker.fetch(
      new Request(`https://snare.sh/c/${TOKEN}/proof/${PROOF}`, {
        headers: { "cf-connecting-ip": "198.51.100.7", "user-agent": "git/2.47" },
      }),
      env,
      { waitUntil(p) { pending = p; } },
    );
    await pending;
    expect(resp.headers.get("content-type")).toBe("image/gif");

    const body = await (await readEvents(env, `?proof_id=${PROOF}`)).json();
    expect(body.events).toHaveLength(1);
    expect(body.events[0].proof_id).toBe(PROOF);
    expect(body.events[0].id).toMatch(/^[0-9a-f-]{36}$/);
  });

  it("does not credit an unrelated event to a proof", async () => {
    const env = await ownerEnv([[eventKey(TOKEN, Date.now(), "x"), JSON.stringify(ev(1))]]);
    expect((await (await readEvents(env, `?proof_id=${PROOF}`)).json()).events).toEqual([]);
  });

  const fireFrom = async (env, token, nonce) => {
    let pending;
    await worker.fetch(
      new Request(`https://snare.sh/c/${token}/proof/${nonce}`, { headers: { "cf-connecting-ip": "198.51.100.8" } }),
      env,
      { waitUntil(p) { pending = p; } },
    );
    await pending;
  };

  it("does not dedupe two self-test proofs from the same IP in the same minute", async () => {
    const TEST = "snare-test-window";
    const env = await ownerEnv([[`webhook:${TEST}`, JSON.stringify({ webhook_url: "use-global", canary_type: "test", device_id: DEVICE })]]);
    await fireFrom(env, TEST, PROOF);
    await fireFrom(env, TEST, "f".repeat(32));
    const { keys } = await env.SNARE_KV.list({ prefix: `evr:${TEST}:` });
    expect(keys).toHaveLength(2);
  });

  it("coalesces a real canary's notifications when the attacker varies the proof nonce", async () => {
    const env = await ownerEnv();
    const seen = new Set();
    env.NOTIFICATION_RATE_LIMITER = { limit: async ({ key }) => ({ success: !seen.has(key) && Boolean(seen.add(key)) }) };
    await fireFrom(env, TOKEN, PROOF);
    await fireFrom(env, TOKEN, "f".repeat(32));
    const { keys } = await env.SNARE_KV.list({ prefix: `evr:${TOKEN}:` });
    const stored = await Promise.all(keys.map(async k => JSON.parse(await env.SNARE_KV.get(k.name)).notification_suppressed));
    expect(stored.sort()).toEqual(["coalesced", null].sort());
  });

  it("rejects a malformed proof_id", async () => {
    expect((await readEvents(await ownerEnv(), "?proof_id=nothex")).status).toBe(400);
  });
});

describe("registration lifetime", () => {
  it("registers tokens without an expiry", async () => {
    const env = await ownerEnv();
    const resp = await worker.fetch(
      new Request("https://snare.sh/api/register", {
        method: "POST",
        headers: { authorization: `Bearer ${SECRET}`, "content-type": "application/json" },
        body: JSON.stringify({ token_id: "fresh-token-0001", webhook_url: "use-global", device_id: DEVICE, canary_type: "git" }),
      }),
      env,
      { waitUntil() {} },
    );
    expect(resp.status).toBe(200);
    const put = env.SNARE_KV.puts.find(p => p.k === "webhook:fresh-token-0001");
    expect(put.opts?.expirationTtl).toBeUndefined();
  });

  it("rewrites a legacy registration without TTL when the owner reads events", async () => {
    const env = await ownerEnv();
    expect((await (await readEvents(env)).json()).events).toEqual([]);
    const reg = JSON.parse(env.SNARE_KV.map.get(`webhook:${TOKEN}`));
    expect(reg.persistent).toBe(true);
    expect(reg.device_id).toBe(DEVICE);
    const writes = env.SNARE_KV.puts.filter(p => p.k === `webhook:${TOKEN}`);
    expect(writes).toHaveLength(1);
    expect(writes[0].opts?.expirationTtl).toBeUndefined();
    await readEvents(env);
    expect(env.SNARE_KV.puts.filter(p => p.k === `webhook:${TOKEN}`)).toHaveLength(1);
  });

  it("reports registered:false when only event history remains", async () => {
    const env = await ownerEnv([[eventKey(TOKEN, Date.now(), "x"), JSON.stringify(ev(1))]]);
    expect((await (await readEvents(env)).json()).registered).toBe(true);
    env.SNARE_KV.map.delete(`webhook:${TOKEN}`);
    const body = await (await readEvents(env)).json();
    expect(body.events).toHaveLength(1);
    expect(body.registered).toBe(false);
  });
});

describe("telegram payload", () => {
  it("escapes attacker-controlled HTML", () => {
    const payload = buildTelegramPayload(
      { token: TOKEN, timestamp: "2026-11-01T00:00:00.000Z", ip: "1.2.3.4", method: "GET",
        userAgent: "<script>x</script>", asnOrg: "AT&T", asn: 7018 },
      { label: "a<b" },
      CANARY_TYPES.git,
      false,
    );
    expect(payload.text).toContain("&lt;script&gt;x&lt;/script&gt;");
    expect(payload.text).toContain("AT&amp;T");
    expect(payload.text).toContain("a&lt;b");
    expect(payload.text).not.toContain("<script>");
  });
});
