// Input and admission policy. This module never reads callback request bodies,
// persists rate counters, or logs client-supplied values or secrets.
const MAX_MANAGEMENT_BYTES = 8 * 1024;
const IDENTIFIER_RE = /^[a-zA-Z0-9_-]{1,80}$/;
const TOKEN_RE = /^[a-zA-Z0-9_-]{8,80}$/;
const SECRET_RE = /^[\x21-\x7e]{32,256}$/;
const encoder = new TextEncoder();

class PolicyError extends Error {
  constructor(status, code, message, retryAfter) {
    super(message);
    this.name = "PolicyError";
    this.status = status;
    this.code = code;
    if (retryAfter !== undefined) this.retryAfter = retryAfter;
  }
}

function badField(field) {
  return new PolicyError(400, "invalid_field", `invalid ${field}`);
}

function plainObject(value) {
  return value !== null && typeof value === "object" &&
    !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function stringField(value, field, maxBytes, { minBytes = 1, pattern } = {}) {
  if (typeof value !== "string" || value.length > maxBytes) throw badField(field);
  const bytes = encoder.encode(value).byteLength;
  if (bytes < minBytes || bytes > maxBytes || /[\x00-\x1f\x7f]/.test(value) ||
      (pattern && !pattern.test(value))) throw badField(field);
  return value;
}

function validateTokenId(value) {
  return stringField(value, "token_id", 80, { pattern: TOKEN_RE });
}

function validateDeviceId(value) {
  // Older enrolled devices may predate the server-generated dev-<hex> shape.
  return stringField(value, "device_id", 80, { pattern: IDENTIFIER_RE });
}

function validateSecret(value, field = "device_secret") {
  return stringField(value, field, 256, { pattern: SECRET_RE });
}

async function readManagementJSON(request) {
  // Keep this guard before even accessing request.body.
  if (!new URL(request.url).pathname.startsWith("/api/")) {
    throw new PolicyError(400, "management_route_required", "JSON is only accepted on management routes");
  }
  const type = (request.headers.get("content-type") || "").split(";", 1)[0].trim().toLowerCase();
  const encoding = (request.headers.get("content-encoding") || "identity").trim().toLowerCase();
  if (type !== "application/json" || encoding !== "identity") {
    throw new PolicyError(415, "unsupported_media_type", "management requests require uncompressed application/json");
  }
  const length = request.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_MANAGEMENT_BYTES)) {
    throw new PolicyError(413, "body_too_large", "management request exceeds 8192 bytes");
  }
  if (!request.body) throw new PolicyError(400, "invalid_json", "invalid JSON object");

  const reader = request.body.getReader();
  const buffer = new Uint8Array(MAX_MANAGEMENT_BYTES);
  let used = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (!(value instanceof Uint8Array)) throw new Error("invalid stream chunk");
      if (value.byteLength > MAX_MANAGEMENT_BYTES - used) {
        throw new PolicyError(413, "body_too_large", "management request exceeds 8192 bytes");
      }
      buffer.set(value, used);
      used += value.byteLength;
    }
  } catch (error) {
    await reader.cancel().catch(() => {});
    if (error instanceof PolicyError) throw error;
    throw new PolicyError(400, "invalid_json", "invalid JSON object");
  } finally {
    reader.releaseLock();
  }
  try {
    const body = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(buffer.subarray(0, used)));
    if (!plainObject(body)) throw new Error("not an object");
    return body;
  } catch {
    throw new PolicyError(400, "invalid_json", "invalid JSON object");
  }
}

function validateManagementBody(operation, body) {
  if (!plainObject(body)) throw new PolicyError(400, "invalid_json", "invalid JSON object");
  // Return a fresh whitelist. Unknown fields never reach persistence.
  switch (operation) {
    case "devices":
      return { device_secret: validateSecret(body.device_secret) };
    case "register": {
      const token_id = validateTokenId(body.token_id);
      const device_id = validateDeviceId(body.device_id);
      let webhook_url = stringField(body.webhook_url, "webhook_url", 2048);
      if (webhook_url !== "use-global") {
        let destination;
        try { destination = new URL(webhook_url); } catch { throw badField("webhook_url"); }
        if (destination.protocol !== "https:" || destination.username || destination.password) {
          throw badField("webhook_url");
        }
        destination.hash = "";
        webhook_url = stringField(destination.href, "webhook_url", 2048);
        // Domain allowlisting must still run at registration and every send.
      }
      const canary_type = body.canary_type == null ? null : stringField(
        body.canary_type, "canary_type", 32, { pattern: /^[a-z][a-z0-9-]{0,31}$/ },
      );
      const label = body.label == null ? null : stringField(body.label, "label", 128, { minBytes: 0 });
      return { token_id, device_id, webhook_url, canary_type, label };
    }
    case "revoke":
      return { token_id: validateTokenId(body.token_id), device_id: validateDeviceId(body.device_id) };
    case "rotate":
      return { device_id: validateDeviceId(body.device_id), new_secret: validateSecret(body.new_secret, "new_secret") };
    default:
      throw new PolicyError(400, "unknown_operation", "unknown management operation");
  }
}

async function equalSecretHashes(expected, presented) {
  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", encoder.encode(expected)),
    crypto.subtle.digest("SHA-256", encoder.encode(presented)),
  ]);
  if (typeof crypto.subtle.timingSafeEqual === "function") {
    return crypto.subtle.timingSafeEqual(a, b);
  }
  // Portable Web Crypto fallback for self-hosted/test runtimes. Verification is
  // delegated to native HMAC verification, never a JS string/byte comparison.
  const key = await crypto.subtle.importKey("raw", a, { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  const signature = await crypto.subtle.sign("HMAC", key, a);
  return crypto.subtle.verify("HMAC", key, signature, b);
}

async function authorizeEnrollment(request, env = {}) {
  const mode = env.ENROLLMENT_MODE ?? "open";
  if (mode === "open") return { mode };
  if (mode === "closed") {
    throw new PolicyError(403, "enrollment_closed", "new device enrollment is closed");
  }
  if (mode !== "invite" || typeof env.SNARE_ENROLLMENT_TOKEN !== "string" ||
      !SECRET_RE.test(env.SNARE_ENROLLMENT_TOKEN)) {
    throw new PolicyError(503, "enrollment_unavailable", "device enrollment is unavailable");
  }
  const auth = request.headers.get("authorization") || "";
  const match = auth.match(/^Bearer ([\x21-\x7e]{32,256})$/i);
  if (!match || !(await equalSecretHashes(env.SNARE_ENROLLMENT_TOKEN, match[1]))) {
    throw new PolicyError(401, "enrollment_unauthorized", "enrollment authorization required");
  }
  return { mode };
}

function authorizeGlobalWebhook(deviceId, env = {}) {
  validateDeviceId(deviceId);
  const list = env.GLOBAL_WEBHOOK_DEVICE_IDS;
  if (list === undefined || list === "") return false;
  if (typeof list !== "string" || encoder.encode(list).byteLength > 8192) {
    throw new PolicyError(503, "global_webhook_policy_unavailable", "global webhook policy unavailable");
  }
  const ids = list.split(",").map(id => id.trim());
  if (ids.some(id => !IDENTIFIER_RE.test(id))) {
    throw new PolicyError(503, "global_webhook_policy_unavailable", "global webhook policy unavailable");
  }
  return ids.includes(deviceId);
}

function boundedText(value, maxBytes) {
  if (typeof value !== "string") return null;
  // Slice first to avoid allocating for an arbitrarily large supplied string.
  const text = value.slice(0, maxBytes).replace(/[\x00-\x1f\x7f]/g, " ");
  let bytes = 0;
  let result = "";
  for (const character of text) {
    const size = encoder.encode(character).byteLength;
    if (bytes + size > maxBytes) break;
    result += character;
    bytes += size;
  }
  return result;
}

function sanitizeCallbackMetadata(metadata = {}) {
  const source = plainObject(metadata) ? metadata : {};
  const clean = {};
  for (const [field, bytes] of Object.entries({
    timestamp: 40, ip: 64, userAgent: 512, method: 16, path: 1024,
    country: 8, city: 128, asnOrg: 256,
  })) clean[field] = boundedText(source[field], bytes);
  clean.asn = Number.isInteger(source.asn) && source.asn >= 0 && source.asn <= 0xffffffff ? source.asn : null;
  clean.botScore = Number.isInteger(source.botScore) && source.botScore >= 0 && source.botScore <= 100 ? source.botScore : null;
  const hints = plainObject(source.sdkHints) ? source.sdkHints : {};
  clean.sdkHints = {
    amzSdkRequest: boundedText(hints.amzSdkRequest, 128),
    amzTarget: boundedText(hints.amzTarget, 128),
    contentType: boundedText(hints.contentType, 128),
    hasAwsSig: typeof hints.hasAwsSig === "boolean" ? hints.hasAwsSig : false,
    isPost: typeof hints.isPost === "boolean" ? hints.isPost : false,
  };
  return clean;
}

const SOURCE_BINDINGS = Object.freeze({
  enrollment: "ENROLLMENT_RATE_LIMITER",
  api: "API_SOURCE_RATE_LIMITER",
  callback: "CALLBACK_SOURCE_RATE_LIMITER",
});
const DEVICE_OPERATIONS = new Set(["register", "revoke", "rotate", "events"]);

async function enforceRateLimit(env, bindingName, key) {
  const required = env.RATE_LIMITS_REQUIRED;
  if (required !== undefined && !["true", "false", true, false].includes(required)) {
    throw new PolicyError(503, "rate_limit_unavailable", "rate limiting unavailable", 60);
  }
  const binding = env[bindingName];
  if (binding === undefined && required !== true && required !== "true") {
    return { enforced: false };
  }
  let outcome;
  try {
    if (!binding || typeof binding.limit !== "function") throw new Error("missing binding");
    outcome = await binding.limit({ key });
    if (!outcome || typeof outcome.success !== "boolean") throw new Error("invalid outcome");
  } catch {
    // No fallback to KV or per-isolate counters: neither enforces the policy.
    throw new PolicyError(503, "rate_limit_unavailable", "rate limiting unavailable", 60);
  }
  if (!outcome.success) throw new PolicyError(429, "rate_limited", "rate limited", 60);
  return { enforced: true };
}

async function enforceSourceRateLimit(request, env = {}, operation) {
  if (!Object.hasOwn(SOURCE_BINDINGS, operation)) {
    throw new PolicyError(400, "unknown_operation", "unknown source rate-limit operation");
  }
  const candidate = request.headers.get("cf-connecting-ip");
  const source = typeof candidate === "string" && candidate.length <= 64 &&
    /^[a-fA-F0-9:.]+$/.test(candidate) ? candidate : "unknown";
  return enforceRateLimit(env, SOURCE_BINDINGS[operation], `source:${operation}:${source}`);
}

async function enforceDeviceRateLimit(env = {}, verifiedDeviceId, operation) {
  // Caller MUST authenticate before this call. IDs supplied in JSON alone are
  // not principals and must never consume another owner's quota.
  validateDeviceId(verifiedDeviceId);
  if (!DEVICE_OPERATIONS.has(operation)) {
    throw new PolicyError(400, "unknown_operation", "unknown device rate-limit operation");
  }
  return enforceRateLimit(env, "API_DEVICE_RATE_LIMITER", `device:${operation}:${verifiedDeviceId}`);
}

export {
  MAX_MANAGEMENT_BYTES, PolicyError, readManagementJSON, validateManagementBody,
  validateTokenId, validateDeviceId, validateSecret, authorizeEnrollment,
  authorizeGlobalWebhook, sanitizeCallbackMetadata, enforceSourceRateLimit,
  enforceDeviceRateLimit,
};
