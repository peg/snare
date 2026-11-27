import { afterEach, describe, expect, it, vi } from "vitest";
import { timingSafeEqual, webcrypto } from "node:crypto";
import {
  MAX_MANAGEMENT_BYTES, PolicyError, readManagementJSON, validateManagementBody,
  authorizeEnrollment, authorizeGlobalWebhook, sanitizeCallbackMetadata,
  enforceSourceRateLimit, enforceDeviceRateLimit,
} from "./policy.js";

afterEach(() => vi.unstubAllGlobals());

const secret = "synthetic-enrollment-and-device-secret-1234567890";
function request(body, headers = {}, path = "/api/devices") {
  return new Request(`https://snare.invalid${path}`, {
    method: "POST", body,
    headers: { "content-type": "application/json", ...headers },
    ...(body instanceof ReadableStream ? { duplex: "half" } : {}),
  });
}
const registration = {
  token_id: "local-token-12345678", device_id: "dev-local-12345678",
  webhook_url: "https://hooks.slack.com/services/local/fixture", canary_type: "awsproc", label: "local fixture",
};

describe("bounded management JSON", () => {
  it("reads an object at the exact byte limit without calling request.json", async () => {
    const text = '{"ok":true}' + " ".repeat(MAX_MANAGEMENT_BYTES - 11);
    expect(new TextEncoder().encode(text)).toHaveLength(MAX_MANAGEMENT_BYTES);
    const req = request(text);
    req.json = () => { throw new Error("unbounded reader must not run"); };
    expect(await readManagementJSON(req)).toEqual({ ok: true });
  });

  it("enforces actual chunked bytes even with a smaller Content-Length and cancels overflow", async () => {
    const cancel = vi.fn();
    const chunks = [new Uint8Array(4096).fill(32), new Uint8Array(4097).fill(32)];
    const stream = new ReadableStream({
      pull(controller) { if (chunks.length) controller.enqueue(chunks.shift()); },
      cancel,
    });
    await expect(readManagementJSON(request(stream, { "content-length": "2" })))
      .rejects.toMatchObject({ status: 413, code: "body_too_large" });
    expect(cancel).toHaveBeenCalledOnce();
  });

  it("counts UTF-8 bytes, not JavaScript characters", async () => {
    const text = JSON.stringify({ label: "é".repeat(4200) });
    expect(text.length).toBeLessThan(MAX_MANAGEMENT_BYTES);
    await expect(readManagementJSON(request(text))).rejects.toMatchObject({ status: 413 });
  });

  it("rejects callbacks before accessing their body", async () => {
    const req = { url: "https://snare.invalid/c/local-token-12345678" };
    Object.defineProperty(req, "body", { get() { throw new Error("callback body touched"); } });
    await expect(readManagementJSON(req)).rejects.toMatchObject({ code: "management_route_required" });
  });

  it.each(["[]", "null", "42", '"hello"', "{invalid"])('rejects non-object or malformed JSON: %s', async text => {
    await expect(readManagementJSON(request(text))).rejects.toMatchObject({ status: 400, code: "invalid_json" });
  });

  it("rejects malformed UTF-8", async () => {
    await expect(readManagementJSON(request(new Uint8Array([123, 34, 120, 34, 58, 34, 0xff, 34, 125]))))
      .rejects.toMatchObject({ status: 400 });
  });

  it.each([
    { "content-type": "text/plain" }, { "content-encoding": "gzip" },
  ])("rejects unsupported JSON transport %j", async headers => {
    await expect(readManagementJSON(request("{}", headers))).rejects.toMatchObject({ status: 415 });
  });

  it("rejects an oversized declared body before pulling the stream", async () => {
    const req = request("{}", { "content-length": "9000" });
    const getReader = vi.spyOn(req.body, "getReader");
    await expect(readManagementJSON(req)).rejects.toMatchObject({ status: 413 });
    expect(getReader).not.toHaveBeenCalled();
  });
});

describe("typed field policy", () => {
  it("returns only permitted scalar fields and normalizes destination fragments", () => {
    expect(validateManagementBody("register", {
      ...registration, webhook_url: `${registration.webhook_url}#not-forwarded`,
      device_secret: secret, unknown: { body: "not persisted" },
    })).toEqual(registration);
    expect(validateManagementBody("devices", { device_secret: secret, nested: {} }))
      .toEqual({ device_secret: secret });
    expect(validateManagementBody("rotate", { device_id: registration.device_id, new_secret: secret }))
      .toEqual({ device_id: registration.device_id, new_secret: secret });
  });

  it.each([
    ["token_id", "short"], ["token_id", "a".repeat(81)], ["token_id", "../../token"],
    ["device_id", {}], ["device_id", ""], ["device_id", "device\nheader"],
    ["webhook_url", "https://user:password@example.com"], ["webhook_url", "http://example.com"],
    ["webhook_url", { secret }], ["webhook_url", `https://example.com/${"x".repeat(2048)}`],
    ["canary_type", {}], ["canary_type", "a".repeat(33)], ["canary_type", "<html>"],
    ["label", { body: "must not enter message" }], ["label", "é".repeat(65)], ["label", "line\nbreak"],
  ])("rejects invalid %s", (field, value) => {
    expect(() => validateManagementBody("register", { ...registration, [field]: value }))
      .toThrow(PolicyError);
  });

  it.each([null, {}, [], "a".repeat(31), "a".repeat(257), "a".repeat(32) + " "])("rejects invalid secrets", value => {
    expect(() => validateManagementBody("devices", { device_secret: value })).toThrow(PolicyError);
  });

  it("allows a syntactically valid future canary type and empty display label", () => {
    expect(validateManagementBody("register", { ...registration, canary_type: "future-native-client", label: "" }))
      .toMatchObject({ canary_type: "future-native-client", label: "" });
  });

  it("validates revoke IDs and drops extra data", () => {
    expect(validateManagementBody("revoke", { ...registration, body: "ignored" }))
      .toEqual({ token_id: registration.token_id, device_id: registration.device_id });
  });
});

describe("new-device enrollment and global destinations", () => {
  it("preserves open enrollment only when explicitly open or not configured", async () => {
    expect(await authorizeEnrollment(request("{}"), {})).toEqual({ mode: "open" });
    expect(await authorizeEnrollment(request("{}"), { ENROLLMENT_MODE: "open" })).toEqual({ mode: "open" });
  });

  it("authenticates invite enrollment using the existing CLI Bearer header", async () => {
    vi.stubGlobal("crypto", webcrypto);
    const env = { ENROLLMENT_MODE: "invite", SNARE_ENROLLMENT_TOKEN: secret };
    expect(await authorizeEnrollment(request("{}", { authorization: `Bearer ${secret}` }), env)).toEqual({ mode: "invite" });
    await expect(authorizeEnrollment(request("{}", { authorization: `Bearer ${secret}x` }), env))
      .rejects.toMatchObject({ status: 401 });
    await expect(authorizeEnrollment(request(JSON.stringify({ device_secret: secret })), env))
      .rejects.toMatchObject({ status: 401 });
  });

  it("uses the Worker-native timing-safe comparison on fixed-size hashes", async () => {
    const compare = vi.fn((a, b) => timingSafeEqual(Buffer.from(a), Buffer.from(b)));
    vi.stubGlobal("crypto", { subtle: { digest: webcrypto.subtle.digest.bind(webcrypto.subtle), timingSafeEqual: compare } });
    await authorizeEnrollment(request("{}", { authorization: `Bearer ${secret}` }), {
      ENROLLMENT_MODE: "invite", SNARE_ENROLLMENT_TOKEN: secret,
    });
    expect(compare).toHaveBeenCalledOnce();
    expect(compare.mock.calls[0][0].byteLength).toBe(32);
    expect(compare.mock.calls[0][1].byteLength).toBe(32);
  });

  it.each([
    [{ ENROLLMENT_MODE: "closed" }, 403],
    [{ ENROLLMENT_MODE: "invalid" }, 503],
    [{ ENROLLMENT_MODE: "invite" }, 503],
    [{ ENROLLMENT_MODE: "invite", SNARE_ENROLLMENT_TOKEN: "short" }, 503],
  ])("fails closed for unavailable enrollment policy", async (env, status) => {
    await expect(authorizeEnrollment(request("{}"), env)).rejects.toMatchObject({ status });
  });

  it("requires an exact operator-approved device for global webhook use", () => {
    expect(authorizeGlobalWebhook(registration.device_id)).toBe(false);
    const env = { GLOBAL_WEBHOOK_DEVICE_IDS: `other-device, ${registration.device_id}` };
    expect(authorizeGlobalWebhook(registration.device_id, env)).toBe(true);
    expect(authorizeGlobalWebhook("dev-local", env)).toBe(false);
    expect(() => authorizeGlobalWebhook(registration.device_id, { GLOBAL_WEBHOOK_DEVICE_IDS: "*" })).toThrow(PolicyError);
  });
});

describe("bounded callback metadata", () => {
  it("drops nested data and all non-whitelisted fields without coercion", () => {
    const hostile = { toString() { throw new Error("must not coerce"); }, body: "private" };
    const clean = sanitizeCallbackMetadata({
      userAgent: hostile, ip: "192.0.2.1", path: "/c/fixture", body: "private", authorization: secret,
      sdkHints: { hasAwsSig: hostile, isPost: true, amzTarget: hostile, authorization: secret },
      asn: Infinity, botScore: "90",
    });
    expect(clean.userAgent).toBeNull();
    expect(clean.asn).toBeNull();
    expect(clean.botScore).toBeNull();
    expect(clean.sdkHints).toMatchObject({ hasAwsSig: false, isPost: true, amzTarget: null });
    expect(JSON.stringify(clean)).not.toContain("private");
    expect(JSON.stringify(clean)).not.toContain(secret);
    expect(clean).not.toHaveProperty("body");
  });

  it("limits byte size across multibyte characters and strips control characters", () => {
    const clean = sanitizeCallbackMetadata({
      userAgent: "😀".repeat(1000), path: "\\".repeat(10000), city: "a\nb\rc\u0000d", asn: 123, botScore: 99,
      sdkHints: { contentType: "x".repeat(10000) },
    });
    expect(new TextEncoder().encode(clean.userAgent).byteLength).toBeLessThanOrEqual(512);
    expect(clean.path).toHaveLength(1024);
    expect(clean.city).toBe("a b c d");
    expect(clean.sdkHints.contentType).toHaveLength(128);
    expect(new TextEncoder().encode(JSON.stringify(clean)).byteLength).toBeLessThan(8192);
  });
});

describe("native rate-limit binding policy", () => {
  it("separates source classes and authenticated device operation keys", async () => {
    const limit = vi.fn().mockResolvedValue({ success: true });
    const env = {
      ENROLLMENT_RATE_LIMITER: { limit }, API_SOURCE_RATE_LIMITER: { limit },
      CALLBACK_SOURCE_RATE_LIMITER: { limit }, API_DEVICE_RATE_LIMITER: { limit },
    };
    const req = request("{}", { "cf-connecting-ip": "192.0.2.1" });
    await enforceSourceRateLimit(req, env, "enrollment");
    await enforceSourceRateLimit(req, env, "api");
    await enforceSourceRateLimit(req, env, "callback");
    await enforceDeviceRateLimit(env, registration.device_id, "events");
    await enforceDeviceRateLimit(env, registration.device_id, "register");
    expect(limit.mock.calls.map(call => call[0].key)).toEqual([
      "source:enrollment:192.0.2.1", "source:api:192.0.2.1", "source:callback:192.0.2.1",
      `device:events:${registration.device_id}`, `device:register:${registration.device_id}`,
    ]);
  });

  it("has no persistent-counter fallback for self-hosting without bindings", async () => {
    const forbidden = vi.fn(() => { throw new Error("KV must not be touched"); });
    const env = { SNARE_KV: { get: forbidden, put: forbidden } };
    expect(await enforceSourceRateLimit(request("{}"), env, "api")).toEqual({ enforced: false });
    expect(await enforceDeviceRateLimit(env, "dev-fixture", "events")).toEqual({ enforced: false });
    expect(forbidden).not.toHaveBeenCalled();
  });

  it.each([true, "true"])("requires bindings for managed deployment (%s)", async required => {
    await expect(enforceSourceRateLimit(request("{}"), { RATE_LIMITS_REQUIRED: required }, "enrollment"))
      .rejects.toMatchObject({ status: 503, code: "rate_limit_unavailable" });
  });

  it.each([{}, null, { success: "yes" }])("fails closed on malformed bound results", async result => {
    await expect(enforceDeviceRateLimit({ API_DEVICE_RATE_LIMITER: { limit: async () => result } }, "dev-fixture", "events"))
      .rejects.toMatchObject({ status: 503 });
  });

  it("does not expose backend error details or fall back when a bound limiter throws", async () => {
    const result = enforceSourceRateLimit(request("{}"), {
      API_SOURCE_RATE_LIMITER: { limit: async () => { throw new Error(`sensitive ${secret}`); } },
    }, "api");
    await expect(result).rejects.toMatchObject({ status: 503, message: "rate limiting unavailable" });
  });

  it("returns an explicit bounded retry delay on denied calls", async () => {
    await expect(enforceDeviceRateLimit({ API_DEVICE_RATE_LIMITER: { limit: async () => ({ success: false }) } }, "dev-fixture", "events"))
      .rejects.toMatchObject({ status: 429, code: "rate_limited", retryAfter: 60 });
  });
});
