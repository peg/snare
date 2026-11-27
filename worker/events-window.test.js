import { describe, it, expect, vi, afterEach } from "vitest";
import worker, { buildTelegramPayload, CANARY_TYPES, eventKey, newestEventKeys, LEGACY_EVENT_KEYS_UNTIL } from "./index.js";

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

  afterEach(() => { vi.useRealTimers(); });

  it("still finds the newest legacy (oldest-first) keys across list pages", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.UTC(2026, 11, 1));
    const rows = [];
    for (let i = 0; i < 1500; i++) {
      const ms = Date.UTC(2026, 9, 1) + i * 1000;
      rows.push([`event:${TOKEN}:${ms}:id${i}`, JSON.stringify({ ...ev(0), timestamp: new Date(ms).toISOString(), n: i })]);
    }
    const resp = await readEvents(await ownerEnv(rows));
    const body = await resp.json();
    expect(body.events[0].n).toBe(1499);
    expect(body.events).toHaveLength(10);
  });

  it("prefers new-format keys over legacy ones", async () => {
    const env = await ownerEnv([
      [`event:${TOKEN}:${Date.UTC(2026, 9, 1)}:old`, JSON.stringify(ev(0))],
      [eventKey(TOKEN, Date.UTC(2026, 10, 2), "new"), JSON.stringify(ev(99))],
    ]);
    expect(await newestEventKeys(env, TOKEN, 1)).toEqual([eventKey(TOKEN, Date.UTC(2026, 10, 2), "new")]);
  });

  it("bounds legacy paging and lists once for an unregistered token", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(Date.UTC(2026, 11, 1));
    const rows = [];
    for (let i = 0; i < 2500; i++) {
      rows.push([`event:${TOKEN}:${Date.UTC(2026, 9, 1) + i}:id${i}`, JSON.stringify(ev(i))]);
    }
    const env = await ownerEnv(rows);
    env.SNARE_KV.map.delete(`webhook:${TOKEN}`);
    let lists = 0;
    const list = env.SNARE_KV.list;
    env.SNARE_KV.list = (opts) => { lists++; return list(opts); };
    expect((await readEvents(env)).status).toBe(200);
    expect(lists).toBe(3);
  });

  it("stops listing legacy keys once they have all expired", async () => {
    const legacy = `event:${TOKEN}:${Date.UTC(2026, 9, 1)}:old`;
    const env = await ownerEnv([[legacy, JSON.stringify(ev(0))]]);
    const prefixes = [];
    const list = env.SNARE_KV.list;
    env.SNARE_KV.list = (opts) => { prefixes.push(opts.prefix); return list(opts); };

    expect(await newestEventKeys(env, TOKEN, 20, LEGACY_EVENT_KEYS_UNTIL - 1)).toEqual([legacy]);
    prefixes.length = 0;
    expect(await newestEventKeys(env, TOKEN, 20, LEGACY_EVENT_KEYS_UNTIL)).toEqual([]);
    expect(prefixes).toEqual([`evr:${TOKEN}:`]);
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
    const resp = await readEvents(env, `?proof_id=${PROOF}`);
    expect(resp.status).toBe(404);
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

  it("still dedupes a real canary when the attacker varies the proof nonce", async () => {
    const env = await ownerEnv();
    await fireFrom(env, TOKEN, PROOF);
    await fireFrom(env, TOKEN, "f".repeat(32));
    const { keys } = await env.SNARE_KV.list({ prefix: `evr:${TOKEN}:` });
    expect(keys).toHaveLength(1);
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

  it("never rewrites the registration when the owner reads events", async () => {
    const env = await ownerEnv();
    await readEvents(env);
    expect(env.SNARE_KV.puts.filter(p => p.k.startsWith("webhook:"))).toHaveLength(0);
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
