import { PolicyError, readManagementJSON, validateManagementBody, authorizeEnrollment,
  authorizeGlobalWebhook, sanitizeCallbackMetadata, enforceSourceRateLimit, enforceDeviceRateLimit } from "./policy.js";
import { D1Store } from "./store.js";
import { createDeliveryMessage } from "./delivery.js";
import { dispatchOutbox, consumeQueue } from "./outbox.js";

/**
 * snare.sh — Cloudflare Worker callback receiver
 *
 * PRIVACY GUARANTEE (callback traffic):
 *   Canary callback requests (/c/{token}) NEVER have their bodies read,
 *   logged, stored, or forwarded. The worker captures only connection
 *   metadata (IP, User-Agent, method, country, ASN) from HEADERS.
 *   D1 deployments acknowledge callbacks after durable event admission.
 *   This is a deliberate design choice — canary callbacks may carry
 *   real credentials or sensitive data in their bodies, and we must
 *   never have access to that data, even transiently in memory.
 *
 *   Note: /api/* endpoints DO read request bodies (JSON payloads for
 *   registration/revocation). These are CLI-initiated management calls
 *   containing only token IDs, webhook URLs, and device IDs — never
 *   credentials or sensitive user data. Cloudflare terminates TLS and
 *   transports all requests; the privacy guarantee applies to our
 *   application code, not the network layer.
 *
 * AUTH MODEL:
 *   /c/{token}          — NO AUTH (SDKs/tools must hit this unknowingly)
 *   /api/register       — requires Authorization: Bearer <device_secret>
 *   /api/revoke         — requires Authorization: Bearer <device_secret>
 *   /api/events/{token} — requires Authorization: Bearer <device_secret>
 *   /health             — NO AUTH
 *
 *   Device secret is generated client-side during `snare init` and sent
 *   with every API call. The worker stores SHA-256(secret) keyed by
 *   device_id on first registration. Subsequent calls validate against
 *   the stored hash. Token IDs may leak (screenshots, accidental commits)
 *   but the device secret stays in ~/.snare/config.json (0600).
 *
 * Routes:
 *   GET/POST /c/{token}[/*]  — canary callback (metadata-only capture)
 *   POST     /api/register   — register webhook + metadata for a token
 *   POST     /api/revoke     — revoke registration and preserve ownership
 *   GET      /api/events/*   — retrieve recent events for a token
 *   GET      /health         — health check
 */

// Per-canary type config: emoji, color, display name
const CANARY_TYPES = {
  aws:       { emoji: "🔑", color: 0xFF9900, name: "AWS"       },
  gcp:       { emoji: "☁️",  color: 0x4285F4, name: "GCP"       },
  github:    { emoji: "⬛", color: 0x24292E, name: "GitHub"    },
  stripe:    { emoji: "💳", color: 0x6772E5, name: "Stripe"    },
  openai:    { emoji: "🤖", color: 0x10A37F, name: "OpenAI"    },
  anthropic: { emoji: "🟠", color: 0xD4572F, name: "Anthropic" },
  ssh:       { emoji: "🔒", color: 0x4EC9B0, name: "SSH"       },
  k8s:       { emoji: "☸️",  color: 0x326CE5, name: "Kubernetes"},
  npm:       { emoji: "📦", color: 0xCB3837, name: "npm"       },
  mcp:       { emoji: "🔌", color: 0x7C3AED, name: "MCP"       },
  pypi:      { emoji: "🐍", color: 0x3776AB, name: "PyPI"      },
  "pypi-upload": { emoji: "📤", color: 0x3776AB, name: "PyPI Upload" },
  awsproc:   { emoji: "⚙️",  color: 0xFF9900, name: "AWS (credential_process)" },
  docker:    { emoji: "🐳", color: 0x2496ED, name: "Docker"    },
  generic:   { emoji: "🗝️",  color: 0x888888, name: "Generic"   },
  huggingface: { emoji: "🤗", color: 0xFFD21E, name: "Hugging Face" },
  azure:     { emoji: "☁️",  color: 0x0078D4, name: "Azure"      },
  git:       { emoji: "🌿", color: 0xF05033, name: "Git"         },
  terraform: { emoji: "🏗️",  color: 0x7B42BC, name: "Terraform"  },
};

const DEFAULT_TYPE = { emoji: "🪤", color: 0xB2121A, name: "Canary" };

// Cloud infrastructure context; this does not establish AI or attacker origin.
const CLOUD_PROVIDERS = [
  "amazon", "google", "microsoft", "openai", "anthropic",
  "digitalocean", "linode", "akamai", "vultr", "hetzner",
  "fly.io", "railway", "render", "lambda labs", "coreweave",
  "together", "replicate", "modal",
];

// Preview hints suppress notifications; evidence remains available.
const PREVIEW_BOTS = [
  "Discordbot", "Slackbot", "Twitterbot", "facebookexternalhit",
  "LinkedInBot", "TelegramBot", "WhatsApp", "iMessage",
  "Googlebot", "bingbot", "DuckDuckBot",
];

// Known security scanner org names (substring match against cf.asOrganization).
// These hints can reduce notification noise but do not establish benign intent.
// List is intentionally conservative — only well-known, confirmed scanner orgs.
const SCANNER_ORGS = [
  "shodan",
  "censys",
  "rapid7",
  "shadowserver",
  "binaryedge",
  "intrinsec",
  "internet measurement",
  "stretchoid",
  "internet census",
  "ipip.net",
  "onyphe",
];

// Per-canary-type false-positive filtering.
// Returns true when notification should be suppressed. These are heuristics:
// unrecognized clients and forged metadata can trigger them. Evidence is retained.
function shouldFilter(canaryType, metadata) {
  const asnLower = (metadata.asnOrg || "").toLowerCase();
  const ua = metadata.userAgent || "";
  const hints = metadata.sdkHints || {};

  // Organization attribution is a notification hint, not proof of harmlessness.
  if (SCANNER_ORGS.some(s => asnLower.includes(s))) return true;

  switch (canaryType) {
    case "aws":
      // The supported AWS proof signs with SigV4. Unsigned requests remain
      // recorded as probes, including clients outside that detection contract.
      return !hints.hasAwsSig;

    case "awsproc":
      // The credential_process proof uses curl. Browser-like user agents are
      // only a suppression hint and are trivial for another client to forge.
      return /^mozilla\//i.test(ua) && !hints.hasAwsSig;

    case "gcp":
      // The supported OAuth exchange uses POST; preserve other methods as probes.
      return !hints.isPost;

    default:
      // For all other types (github, openai, anthropic, ssh, k8s, npm, pypi, mcp, stripe, generic):
      // scanner hints already applied above; no additional suppression.
      // These canaries may be triggered via GET by non-SDK clients (legitimate attack paths),
      // so we don't gate on method or auth headers.
      return false;
  }
}

export default {
  async fetch(request, env, ctx) {
    try {
      if (env.STORAGE_BACKEND === "d1" && !env.SNARE_DB) {
        throw new PolicyError(503, "storage_unavailable", "transactional storage is not configured");
      }
      const url = new URL(request.url);
      if (url.pathname === "/health") {
        return json({ status: "ok", environment: env.SNARE_ENVIRONMENT || "production",
          version: env.CF_VERSION_METADATA || {}, storage: env.SNARE_DB ? "d1" : "kv",
          delivery: env.SNARE_DB ? (env.WEBHOOK_DELIVERY_QUEUE ? "queue" : "outbox") : "best_effort",
          enrollment: env.ENROLLMENT_MODE || "open", ts: new Date().toISOString() });
      }
      if (url.pathname.startsWith("/api/")) {
        await enforceSourceRateLimit(request, env, url.pathname === "/api/devices" ? "enrollment" : "api");
        const routes = { "/api/devices": handleCreateDevice, "/api/register": handleRegister,
          "/api/revoke": handleRevoke, "/api/rotate": handleRotateSecret };
        if (Object.hasOwn(routes, url.pathname)) {
          if (request.method !== "POST") return json({ error: "method not allowed" }, 405);
          return await routes[url.pathname](request, env);
        }
        const eventMatch = url.pathname.match(/^\/api\/events\/([a-zA-Z0-9_-]{8,80})$/);
        if (eventMatch && request.method === "GET") return await handleEvents(eventMatch[1], request, env);
        return json({ error: "not found" }, 404);
      }
      const match = url.pathname.match(/^\/c\/([a-zA-Z0-9_-]{8,80})(\/.*)?$/);
      if (match) {
        await enforceSourceRateLimit(request, env, "callback");
        // Callback bodies are never accessed, including while awaiting durable
        // storage. An acknowledgement describes ingestion, not webhook receipt.
        const metadata = extractMetadata(request, url);
        metadata.proof_id = (match[2] || "").match(/^\/proof\/([0-9a-f]{32})(?:\/|$)/)?.[1] || null;
        if (env.SNARE_DB) {
          await processAlert(match[1], metadata, env, ctx);
        } else {
          // Legacy self-hosting mode remains explicitly best effort.
          ctx.waitUntil(processAlert(match[1], metadata, env, ctx).catch(() =>
            console.error("ALERT_ERROR token=***")));
        }
        return gif();
      }
      return new Response("not found", { status: 404 });
    } catch (error) {
      if (error instanceof PolicyError) {
        const response = json({ error: error.message, code: error.code }, error.status);
        if (error.retryAfter) response.headers.set("retry-after", String(error.retryAfter));
        return response;
      }
      console.error("REQUEST_STORAGE_UNAVAILABLE");
      return json({ error: "service temporarily unavailable" }, 503);
    }
  },
  async queue(batch, env) { await consumeQueue(batch, env, { resolveWebhooks, forwardAlert }); },
  async scheduled(_controller, env, ctx) {
    if (!env.SNARE_DB) return;
    ctx.waitUntil((async () => {
      await dispatchOutbox(env, { resolveWebhooks, forwardAlert });
      await new D1Store(env.SNARE_DB).cleanup(Date.now());
    })());
  },
};

// ─── Webhook domain allowlist ────────────────────────────────────────────────
// Prevent snare.sh being used as a free webhook spammer.
// Only well-known alerting platforms + HTTPS are allowed.
// Self-hosters can add their own domains via env var WEBHOOK_ALLOWED_DOMAINS.
const WEBHOOK_DOMAIN_ALLOWLIST = [
  "discord.com",
  "hooks.slack.com",
  "api.telegram.org",
  "hooks.zapier.com",
  "api.pagerduty.com",
  "events.pagerduty.com",
  "outlook.office.com",          // MS Teams
  "discordapp.com",
];

function hostnameMatches(hostname, domain) {
  return hostname === domain || hostname.endsWith("." + domain);
}

function configuredWebhookDomains(env = {}) {
  return (env.WEBHOOK_ALLOWED_DOMAINS || "")
    .split(",")
    .map(domain => domain.trim().toLowerCase().replace(/\.$/, ""))
    .filter(domain => /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(domain));
}

function parseAllowedWebhookURL(url, env = {}) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") return false;
    if (parsed.username || parsed.password) return false;

    const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");
    const builtInAllowed = WEBHOOK_DOMAIN_ALLOWLIST.includes(hostname);
    const operatorAllowed = configuredWebhookDomains(env)
      .some(domain => hostnameMatches(hostname, domain));
    if (!builtInAllowed && !operatorAllowed) {
      return false;
    }
    return parsed;
  } catch {
    return false;
  }
}

function isAllowedWebhookURL(url, env = {}) {
  return Boolean(parseAllowedWebhookURL(url, env));
}

function classifyWebhookURL(parsed) {
  const hostname = parsed.hostname.toLowerCase().replace(/\.$/, "");
  if ((hostname === "discord.com" || hostname === "discordapp.com") &&
      parsed.pathname.startsWith("/api/webhooks/")) {
    return "discord";
  }
  if (hostname === "hooks.slack.com") return "slack";
  if (hostname === "api.telegram.org") return "telegram";
  return "generic";
}

// ─── Auth ────────────────────────────────────────────────────────────────────

// Hash a secret using SHA-256 (same as CLI side)
async function hashSecret(secret) {
  const data = new TextEncoder().encode(secret);
  const hash = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, "0")).join("");
}

// Validate Authorization: Bearer <device_secret> against stored hash.
// Returns { ok, deviceId, error } where deviceId is from the request body or header.
async function validateAuth(request, env, deviceId) {
  const match = (request.headers.get("authorization") || "").match(/^Bearer ([\x21-\x7e]{32,256})$/i);
  if (!match) return { ok: false, error: "missing or invalid Authorization header" };
  if (typeof deviceId !== "string" || !/^[a-zA-Z0-9_-]{1,80}$/.test(deviceId)) return { ok: false, error: "invalid device_id" };
  const stored = env.SNARE_DB ? await new D1Store(env.SNARE_DB).getDevice(deviceId)
    : await readKVRecord(env, `device:${deviceId}`);
  if (!stored) return { ok: false, error: "unknown device_id" };
  const hash = await hashSecret(match[1]);
  // Native verification provides constant-time comparison in both Workers and
  // Web Crypto test runtimes without comparing secret-bearing JS strings.
  if (typeof stored.secret_hash !== "string" || !/^[0-9a-f]{64}$/.test(stored.secret_hash)) return { ok: false, error: "corrupt device record" };
  const bytes = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", bytes.encode(stored.secret_hash), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  const tag = await crypto.subtle.sign("HMAC", key, bytes.encode(stored.secret_hash));
  if (!await crypto.subtle.verify("HMAC", key, tag, bytes.encode(hash))) return { ok: false, error: "invalid device secret" };
  return { ok: true, deviceId };
}

// ─── Metadata extraction (HEADERS ONLY — never touches body) ────────────────

function extractMetadata(request, url) {
  const cf = request.cf || {};
  return sanitizeCallbackMetadata({
    timestamp: new Date().toISOString(),
    ip:        request.headers.get("cf-connecting-ip") || "unknown",
    userAgent: request.headers.get("user-agent") || "",
    method:    request.method,
    path:      url.pathname,
    country:   cf.country        || null,
    city:      cf.city           || null,
    asn:       cf.asn            || null,
    asnOrg:    cf.asOrganization || null,
    botScore:  cf.botManagement?.score ?? null,
    // Capture specific safe headers that indicate SDK type.
    // IMPORTANT: we check for the PRESENCE of auth headers, never their value.
    // The Authorization header may contain signed credential material — we only
    // record a boolean, never the header value itself.
    sdkHints: {
      amzSdkRequest: request.headers.get("x-amz-sdk-request") || null,
      amzTarget:     request.headers.get("x-amz-target") || null,
      contentType:   request.headers.get("content-type") || null,
      // Boolean: does this request look like a real AWS SDK call?
      // This recognizes the signature scheme used by the supported proof.
      hasAwsSig:  (request.headers.get("authorization") || "").startsWith("AWS4-HMAC-SHA256"),
      // Boolean: is this a POST? GCP token_uri exchange is always POST.
      isPost: request.method === "POST",
    },
  });
}

// ─── Event admission and notification scheduling ───────────────────────────

async function processAlert(token, metadata, env, ctx) {
  const registration = await resolveWebhooks(token, env);
  if (!registration.registered) return;
  const { webhooks, meta, revision } = registration;
  const preview = PREVIEW_BOTS.some(bot => metadata.userAgent.includes(bot));
  const scanner = SCANNER_ORGS.some(org => (metadata.asnOrg || "").toLowerCase().includes(org));
  const classification = preview ? "preview" : scanner ? "scanner" : shouldFilter(meta.canaryType, metadata) ? "probe" : "activity";
  let suppression = classification === "activity" ? null : classification;
  if (!suppression && env.NOTIFICATION_RATE_LIMITER) {
    const outcome = await env.NOTIFICATION_RATE_LIMITER.limit({ key: `notify:${token}:${metadata.ip}` });
    if (!outcome || typeof outcome.success !== "boolean") throw new Error("invalid notification limiter result");
    if (!outcome.success) suppression = "coalesced";
  }
  const event = { ...metadata, id: crypto.randomUUID(), token, device_id: meta.deviceId,
    token_revision: revision, is_test: token.startsWith("snare-test-"), classification,
    notification_suppressed: suppression };
  // No body, authorization value, or arbitrary request property is copied.
  if (env.SNARE_DB) {
    const messages = suppression ? [] : await Promise.all(webhooks.map(url =>
      createDeliveryMessage(url, event, meta, { tokenRevision: revision })));
    const admitted = await new D1Store(env.SNARE_DB).saveEvent(event, messages);
    if (!admitted) throw new PolicyError(429, "event_admission_limited", "event admission limit reached or registration changed", 60);
    if (messages.length) ctx.waitUntil(dispatchOutbox(env, { resolveWebhooks, forwardAlert }).catch(() => console.error("DELIVERY_DISPATCH_FAILED")));
    return;
  }
  if (env.SNARE_KV) {
    await env.SNARE_KV.put(`event:${token}:${Date.now()}:${event.id}`, JSON.stringify({ ...event, delivery_mode: "best_effort" }),
      { expirationTtl: 60 * 60 * 24 * 90 });
  }
  if (!suppression) {
    const results = await Promise.allSettled(webhooks.map(url => forwardAlert(url, event, meta, env)));
    if (results.some(result => result.status === "rejected")) console.error("WEBHOOK_FAILED url=*** token=***");
  }
}

// ─── Events lookup ───────────────────────────────────────────────────────────

async function handleEvents(token, request, env) {
  const proofId = new URL(request.url).searchParams.get("proof_id");
  if (proofId !== null && !/^[0-9a-f]{32}$/.test(proofId)) return json({ error: "invalid proof_id" }, 400);
  const record = await getTokenRecord(token, env);
  let legacyEvents;
  let owner = record?.device_id;
  if (!owner && !env.SNARE_DB) {
    legacyEvents = await readLegacyEvents(env, token);
    const owners = new Set(legacyEvents.map(event => event.device_id).filter(Boolean));
    if (owners.size === 1) owner = [...owners][0];
  }
  if (!owner) return json({ error: "token not registered" }, 401);
  const auth = await validateAuth(request, env, owner);
  if (!auth.ok) return json({ error: auth.error }, 401);
  await enforceDeviceRateLimit(env, owner, "events");
  const events = env.SNARE_DB ? await new D1Store(env.SNARE_DB).getEvents(token, { proofId })
    : (legacyEvents || await readLegacyEvents(env, token)).filter(event => event.device_id === owner && (proofId === null || event.proof_id === proofId)).slice(0, 10);
  if (record?.revoked && proofId === null && events.length === 0) return json({ error: "token not registered" }, 401);
  return json({ token, count: events.length, events, storage: env.SNARE_DB ? "d1" : "kv" });
}

// ─── Device creation ────────────────────────────────────────────────────────

// POST /api/devices — server mints a device_id, client sends only its secret.
// This prevents squatting on device IDs.
async function handleCreateDevice(request, env) {
  await authorizeEnrollment(request, env);
  const { device_secret } = validateManagementBody("devices", await readManagementJSON(request));
  const deviceId = `dev-${crypto.randomUUID().replaceAll("-", "")}`;
  const secretHash = await hashSecret(device_secret);
  if (env.SNARE_DB) {
    if (!await new D1Store(env.SNARE_DB).createDevice(deviceId, secretHash)) return json({ error: "device capacity reached" }, 429);
  } else {
    if (!env.SNARE_KV) return json({ error: "storage not configured" }, 503);
    await env.SNARE_KV.put(`device:${deviceId}`, JSON.stringify({ secret_hash: secretHash, created_at: new Date().toISOString() }));
  }
  return json({ status: "created", device_id: deviceId });
}

// ─── Registration ───────────────────────────────────────────────────────────

async function handleRegister(request, env) {
  const body = validateManagementBody("register", await readManagementJSON(request));
  const { token_id, webhook_url, device_id } = body;
  const auth = await validateAuth(request, env, device_id);
  if (!auth.ok) return json({ error: auth.error }, 401);
  await enforceDeviceRateLimit(env, device_id, "register");
  const existing = await getTokenRecord(token_id, env);
  if (existing && existing.device_id !== device_id) return json({ error: "token belongs to another device" }, 403);
  if (webhook_url === "use-global") {
    // Preserve existing operator-approved routes; a new token needs an explicit
    // device allowlist entry, even when enrollment itself is public.
    const previousGlobal = existing?.device_id === device_id && existing.webhook_url === "use-global";
    if (!previousGlobal && !authorizeGlobalWebhook(device_id, env)) return json({ error: "global webhook access is not authorized" }, 403);
  } else if (!isAllowedWebhookURL(webhook_url, env)) return json({ error: "webhook_url domain not allowed" }, 403);
  const changed = !existing || existing.revoked || existing.webhook_url !== webhook_url ||
    existing.canary_type !== body.canary_type || existing.label !== body.label;
  const record = { ...body, registered_at: new Date().toISOString(), revoked: false,
    revision: (existing?.revision || 1) + (existing && changed ? 1 : 0) };
  if (env.SNARE_DB) {
    const result = await new D1Store(env.SNARE_DB).registerToken(token_id, record);
    if (result !== "registered") return json({ error: result === "owner_mismatch" ? "token belongs to another device" : "token capacity reached" }, result === "owner_mismatch" ? 403 : 429);
  } else {
    if (!env.SNARE_KV) return json({ error: "storage not configured" }, 503);
    const history = existing ? [] : await readLegacyEvents(env, token_id);
    if (history.some(event => !event.device_id || event.device_id !== device_id)) return json({ error: "token history belongs to another device" }, 403);
    // Immutable tombstone in legacy mode. KV cannot serialize concurrent first
    // claims; managed deployments requiring atomic claims must enable D1.
    await env.SNARE_KV.put(`owner:${token_id}`, JSON.stringify({ device_id }));
    await env.SNARE_KV.put(`webhook:${token_id}`, JSON.stringify(record));
  }
  return json({ status: "registered", token_id });
}

async function handleRevoke(request, env) {
  const { token_id, device_id } = validateManagementBody("revoke", await readManagementJSON(request));
  const auth = await validateAuth(request, env, device_id);
  if (!auth.ok) return json({ error: auth.error }, 401);
  await enforceDeviceRateLimit(env, device_id, "revoke");
  const record = await getTokenRecord(token_id, env);
  if (record && record.device_id !== device_id) return json({ error: "token belongs to another device" }, 403);
  if (env.SNARE_DB) {
    if (record && !await new D1Store(env.SNARE_DB).revokeToken(token_id, device_id)) return json({ error: "token belongs to another device" }, 403);
  } else if (record) {
    await env.SNARE_KV.put(`owner:${token_id}`, JSON.stringify({ device_id }));
    await env.SNARE_KV.put(`webhook:${token_id}`, JSON.stringify({ ...record, revoked: true, revision: (record.revision || 0) + 1 }));
  }
  return json({ status: "revoked", token_id });
}

// ─── Device secret rotation ──────────────────────────────────────────────────

// POST /api/rotate — update device secret hash for an existing device.
// Requires: old secret for auth (proves ownership), new secret in body.
async function handleRotateSecret(request, env) {
  const { device_id, new_secret } = validateManagementBody("rotate", await readManagementJSON(request));
  const auth = await validateAuth(request, env, device_id);
  if (!auth.ok) return json({ error: auth.error }, 401);
  await enforceDeviceRateLimit(env, device_id, "rotate");
  const secret_hash = await hashSecret(new_secret);
  if (env.SNARE_DB) await new D1Store(env.SNARE_DB).rotateDevice(device_id, secret_hash);
  else {
    const record = await readKVRecord(env, `device:${device_id}`);
    await env.SNARE_KV.put(`device:${device_id}`, JSON.stringify({ ...record, secret_hash, rotated_at: new Date().toISOString() }));
  }
  return json({ status: "rotated", device_id });
}

// ─── Webhook resolution ─────────────────────────────────────────────────────

async function resolveWebhooks(token, env) {
  const record = await getTokenRecord(token, env);
  if (!record || record.revoked || !record.device_id) return { webhooks: [], meta: {}, registered: false };
  const meta = { canaryType: record.canary_type, label: record.label, deviceId: record.device_id };
  const destinations = isAllowedWebhookURL(record.webhook_url, env) ? [record.webhook_url]
    : (record.webhook_url === "use-global" ? (env.WEBHOOK_URLS || "").split(",") : []);
  const webhooks = [...new Set(destinations.map(url => url.trim()).filter(url => isAllowedWebhookURL(url, env)))].slice(0, 3);
  return { webhooks, meta, registered: true, revision: record.revision || 1 };
}

async function readKVRecord(env, key) {
  if (!env.SNARE_KV) return null;
  const raw = await env.SNARE_KV.get(key);
  if (raw === null || raw === undefined) return null;
  try { return JSON.parse(raw); } catch { throw new Error("invalid stored record"); }
}

async function getTokenRecord(token, env) {
  if (env.SNARE_DB) return new D1Store(env.SNARE_DB).getToken(token);
  const record = await readKVRecord(env, `webhook:${token}`);
  const owner = await readKVRecord(env, `owner:${token}`);
  if (owner && record && owner.device_id !== record.device_id) throw new Error("ownership conflict");
  return record || (owner ? { ...owner, revoked: true } : null);
}

async function readLegacyEvents(env, token) {
  if (!env.SNARE_KV?.list) return [];
  const events = [];
  let keysRead = 0;
  let cursor;
  // Compatibility path only: paginate before sorting, never call the oldest
  // first page 'recent'. D1 provides the indexed path for larger histories.
  for (let page = 0; page < 10; page++) {
    const result = await env.SNARE_KV.list({ prefix: `event:${token}:`, limit: 1000, ...(cursor ? { cursor } : {}) });
    if (keysRead + result.keys.length > 900) {
      throw new PolicyError(503, "history_migration_required", "history requires indexed storage migration");
    }
    keysRead += result.keys.length;
    for (const key of result.keys) {
      const event = await readKVRecord(env, key.name);
      if (event) events.push({ ...event, id: event.id || key.name.split(":").at(-1) });
    }
    if (result.list_complete !== false) return events.sort((a, b) => b.timestamp.localeCompare(a.timestamp) || b.id.localeCompare(a.id));
    if (!result.cursor || result.cursor === cursor) break;
    cursor = result.cursor;
  }
  throw new PolicyError(503, "history_migration_required", "history requires indexed storage migration");
}

// ─── Alert formatting ────────────────────────────────────────────────────────

async function forwardAlert(webhookURL, event, meta = {}, env = {}, { deliveryId } = {}) {
  // Validate again at the network boundary. Resolution may have happened
  // earlier, and callers or legacy records must not be able to bypass policy.
  const parsedWebhookURL = parseAllowedWebhookURL(webhookURL, env);
  if (!parsedWebhookURL) {
    throw new Error("webhook destination is not allowed");
  }
  const provider = classifyWebhookURL(parsedWebhookURL);

  const type     = CANARY_TYPES[meta.canaryType] || DEFAULT_TYPE;
  const asnLower = (event.asnOrg || "").toLowerCase();
  const fromCloud = CLOUD_PROVIDERS.some(p => asnLower.includes(p));

  let body;

  if (provider === "discord") {
    body = JSON.stringify(buildDiscordPayload(event, meta, type, fromCloud));
  } else if (provider === "slack") {
    body = JSON.stringify(buildSlackPayload(event, meta, type, fromCloud));
  } else if (provider === "telegram") {
    body = JSON.stringify(buildTelegramPayload(event, meta, type, fromCloud));
  } else {
    body = JSON.stringify(buildGenericPayload(event, meta, type, fromCloud));
  }

  const headers = {
    "content-type": "application/json",
    "user-agent": "snare.sh/1.0",
  };

  if (deliveryId) headers["x-snare-delivery-id"] = deliveryId;
  if (event.id) headers["x-snare-event-id"] = event.id;

  // Sign outbound webhook payload so receivers can verify it came from snare.sh
  // Signature: HMAC-SHA256(payload, WEBHOOK_SIGNING_SECRET) encoded as hex
  // Receivers check: X-Snare-Signature header
  if (env.WEBHOOK_SIGNING_SECRET) {
    try {
      const key = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(env.WEBHOOK_SIGNING_SECRET),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
      );
      const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
      headers["x-snare-signature"] = "sha256=" + Array.from(new Uint8Array(sig))
        .map(b => b.toString(16).padStart(2, "0")).join("");
    } catch {
      throw new Error("webhook signing unavailable");
    }
  }

  // Do not follow redirects: a trusted webhook endpoint must not be able to
  // redirect the Worker to an unapproved destination.
  const response = await fetch(parsedWebhookURL.href, {
    method: "POST",
    headers,
    body,
    redirect: "manual",
    signal: AbortSignal.timeout(5000),
  });
  if (response.status < 200 || response.status >= 300) {
    const error = new Error(`webhook returned ${response.status}`);
    error.status = response.status;
    const retryAfter = response.headers.get("retry-after");
    error.retryAfter = retryAfter && /^\d+$/.test(retryAfter) ? Math.min(3600, Number(retryAfter)) : undefined;
    await response.body?.cancel();
    throw error;
  }
  // No response body is needed; release the connection even if a destination
  // streams indefinitely after sending successful headers.
  await response.body?.cancel();
  return response;
}

function buildDiscordPayload(event, meta, type, fromCloud) {
  const isTest   = event.is_test;
  const ts       = event.timestamp.replace("T", " ").replace(/\.\d+Z$/, " UTC");
  const location = [event.city, event.country].filter(Boolean).join(", ") || "unknown";
  const network  = event.asnOrg ? `${event.asnOrg} (AS${event.asn})` : (event.ip || "unknown");

  let title;
  if (isTest) {
    title = `🧪 Test alert — ${type.name}`;
  } else if (meta.label) {
    title = `${type.emoji} ${type.name} canary fired — ${meta.label}`;
  } else {
    title = `${type.emoji} ${type.name} canary fired`;
  }

  const fields = [
    { name: "Token",    value: `\`${event.token}\``,  inline: false },
    { name: "Time",     value: ts,                    inline: true  },
    { name: "Method",   value: event.method,          inline: true  },
    { name: "IP",       value: event.ip || "unknown", inline: true  },
    { name: "Location", value: location,              inline: true  },
    { name: "Network",  value: network,               inline: true  },
    { name: "UA",       value: `\`${(event.userAgent || "unknown").slice(0, 120)}\``, inline: false },
  ];

  // SDK hints — show what SDK/service was being called (from headers, not body)
  if (event.sdkHints?.amzTarget) {
    fields.push({ name: "AWS Target", value: `\`${event.sdkHints.amzTarget}\``, inline: true });
  }

  if (fromCloud && !isTest) {
    fields.push({
      name:   "Cloud infrastructure",
      value:  `Request originated from **${event.asnOrg}** — cloud infrastructure`,
      inline: false,
    });
  }

  if (event.botScore !== null && event.botScore < 30) {
    fields.push({
      name:   "🤖 Bot score",
      value:  `${event.botScore}/100 — high confidence automated`,
      inline: false,
    });
  }

  // NO body field — never included, by design

  return {
    embeds: [{
      title,
      color:     isTest ? 0x888888 : type.color,
      fields,
      footer:    { text: "snare.sh · IP, UA, timestamp only — no request body" },
      timestamp: event.timestamp,
    }],
  };
}

function buildSlackPayload(event, meta, type, fromCloud) {
  const isTest   = event.is_test;
  const location = [event.city, event.country].filter(Boolean).join(", ") || "unknown";

  let title;
  if (isTest) {
    title = `🧪 Test alert — ${type.name}`;
  } else if (meta.label) {
    title = `${type.emoji} *${type.name} canary fired* — ${meta.label}`;
  } else {
    title = `${type.emoji} *${type.name} canary fired*`;
  }

  const fields = [
    { title: "Token",    value: `\`${event.token}\``,                         short: false },
    { title: "IP",       value: event.ip || "unknown",                        short: true  },
    { title: "Location", value: location,                                     short: true  },
    { title: "UA",       value: (event.userAgent || "unknown").slice(0, 100), short: false },
  ];

  if (fromCloud && !isTest) {
    fields.push({ title: "⚠️ Source", value: `Cloud infrastructure: ${event.asnOrg}`, short: false });
  }

  return {
    text: title,
    attachments: [{
      color:  isTest ? "#888888" : `#${type.color.toString(16).padStart(6, "0")}`,
      fields,
      footer: "snare.sh · IP, UA, timestamp only — no request body",
      ts:     Math.floor(new Date(event.timestamp).getTime() / 1000),
    }],
  };
}

function escapeHTML(value) {
  return String(value).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

function buildTelegramPayload(event, meta, type, fromCloud) {
  const isTest   = event.is_test;
  const location = [event.city, event.country].filter(Boolean).join(", ") || "unknown";
  const network  = event.asnOrg ? `${event.asnOrg} (AS${event.asn})` : (event.ip || "unknown");

  let title;
  if (isTest) {
    title = `🧪 <b>Test alert — ${type.name}</b>`;
  } else if (meta.label) {
    title = `${type.emoji} <b>${type.name} canary fired — ${escapeHTML(meta.label)}</b>`;
  } else {
    title = `${type.emoji} <b>${type.name} canary fired</b>`;
  }

  const lines = [
    title,
    "",
    `<b>Token:</b> <code>${escapeHTML(event.token)}</code>`,
    `<b>Time:</b> ${escapeHTML(event.timestamp.replace("T", " ").replace(/\.\d+Z$/, " UTC"))}`,
    `<b>IP:</b> ${escapeHTML(event.ip || "unknown")}`,
    `<b>Location:</b> ${escapeHTML(location)}`,
    `<b>Network:</b> ${escapeHTML(network)}`,
    `<b>Method:</b> ${escapeHTML(event.method)}`,
    `<b>UA:</b> <code>${escapeHTML((event.userAgent || "unknown").slice(0, 100))}</code>`,
  ];

  if (fromCloud && !isTest) {
    lines.push("", `<b>Cloud infrastructure</b> — actor identity is unknown`);
  }

  lines.push("", "<i>Request body was never captured</i>");

  return { parse_mode: "HTML", text: lines.join("\n") };
}

function buildGenericPayload(event, meta, type, fromCloud) {
  return {
    event:       "canary.fired",
    id:          event.id || null,
    proof_id:    event.proof_id || null,
    classification: event.classification || "activity",
    is_test:     event.is_test,
    token:       event.token,
    canary_type: meta.canaryType || null,
    label:       meta.label      || null,
    device_id:   meta.deviceId   || null,
    timestamp:   event.timestamp,
    ip:          event.ip,
    location: {
      city:    event.city,
      country: event.country,
    },
    network: {
      asn:      event.asn,
      org:      event.asnOrg,
      is_cloud: fromCloud,
    },
    request: {
      method:     event.method,
      user_agent: event.userAgent,
      path:       event.path,
      sdk_hints:  event.sdkHints,
      // body: intentionally omitted — snare never captures request bodies
    },
    bot_score: event.botScore,
    privacy:   "request_body_never_captured",
  };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────



function gif() {
  // 1x1 transparent GIF — smallest valid response
  return new Response(
    "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x00\x00\x00\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b",
    {
      status: 200,
      headers: {
        "content-type": "image/gif",
        "cache-control": "no-store, max-age=0",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "cross-origin-resource-policy": "cross-origin",
      },
    }
  );
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "content-type": "application/json",
      "cache-control": "no-store, max-age=0",
      "x-content-type-options": "nosniff",
    },
  });
}

// Named exports for unit testing — not used by the worker runtime
export {
  CANARY_TYPES,
  SCANNER_ORGS,
  forwardAlert,
  isAllowedWebhookURL,
  resolveWebhooks,
  shouldFilter,
  validateAuth,
};
