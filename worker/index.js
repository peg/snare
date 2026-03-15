/**
 * snare.sh — Cloudflare Worker callback receiver
 *
 * PRIVACY GUARANTEE (callback traffic):
 *   Canary callback requests (/c/{token}) NEVER have their bodies read,
 *   logged, stored, or forwarded. The worker captures only connection
 *   metadata (IP, User-Agent, method, country, ASN) from HEADERS.
 *   The response is returned BEFORE any body could be consumed.
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
 *   POST     /api/revoke     — remove a token registration
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
  awsproc:   { emoji: "⚙️",  color: 0xFF9900, name: "AWS (credential_process)" },
  docker:    { emoji: "🐳", color: 0x2496ED, name: "Docker"    },
  generic:   { emoji: "🗝️",  color: 0x888888, name: "Generic"   },
};

const DEFAULT_TYPE = { emoji: "🪤", color: 0xB2121A, name: "Canary" };

// Known cloud/AI infrastructure ASNs — strong indicator of agent origin
const CLOUD_PROVIDERS = [
  "amazon", "google", "microsoft", "openai", "anthropic",
  "digitalocean", "linode", "akamai", "vultr", "hetzner",
  "fly.io", "railway", "render", "lambda labs", "coreweave",
  "together", "replicate", "modal",
];

// Known link-preview bots — ignore these
const PREVIEW_BOTS = [
  "Discordbot", "Slackbot", "Twitterbot", "facebookexternalhit",
  "LinkedInBot", "TelegramBot", "WhatsApp", "iMessage",
  "Googlebot", "bingbot", "DuckDuckBot",
];

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/health") {
      return json({ status: "ok", ts: new Date().toISOString() });
    }

    // Rate limit all /api/* endpoints: 30 requests per minute per IP
    if (url.pathname.startsWith("/api/")) {
      const ip = request.headers.get("cf-connecting-ip") || "unknown";
      const rateLimited = await checkRateLimit(env, `api:${ip}`, 30, 60);
      if (rateLimited) {
        return json({ error: "rate limited" }, 429);
      }
    }

    if (url.pathname === "/api/devices" && request.method === "POST") {
      return handleCreateDevice(request, env);
    }

    if (url.pathname === "/api/register" && request.method === "POST") {
      return handleRegister(request, env);
    }

    if (url.pathname === "/api/revoke" && request.method === "POST") {
      return handleRevoke(request, env);
    }

    if (url.pathname === "/api/rotate" && request.method === "POST") {
      return handleRotateSecret(request, env);
    }

    // Events lookup: GET /api/events/{token}
    const eventsMatch = url.pathname.match(/^\/api\/events\/([a-zA-Z0-9_-]{8,80})$/);
    if (eventsMatch && request.method === "GET") {
      return handleEvents(eventsMatch[1], request, env);
    }

    // Canary callback: /c/{token} or /c/{token}/anything (for OpenAI /v1 suffix etc.)
    // NO AUTH — SDKs/tools must hit this unknowingly
    // Rate limited: 10 alerts per token per minute (prevents alert flooding)
    const match = url.pathname.match(/^\/c\/([a-zA-Z0-9_-]{8,80})(\/.*)?$/);
    if (match) {
      // Rate limit per token (prevent alert spam if token ID leaks)
      const tokenRateLimited = await checkRateLimit(env, `cb:${match[1]}`, 10, 60);
      if (tokenRateLimited) {
        return gif(); // Still return valid response, just don't process
      }
      // ═══════════════════════════════════════════════════════════════════
      // PRIVACY CRITICAL PATH
      //
      // 1. Extract metadata from HEADERS ONLY — body is never touched
      // 2. Return the response IMMEDIATELY — before any body is consumed
      // 3. Process the alert asynchronously via ctx.waitUntil
      //
      // The request body may contain real credentials, API keys, prompts,
      // or other sensitive data. We MUST return before it reaches us.
      // ═══════════════════════════════════════════════════════════════════
      const token = match[1];
      const metadata = extractMetadata(request, url);

      // Process alert asynchronously AFTER response is sent to caller
      ctx.waitUntil(
        processAlert(token, metadata, env).catch(err =>
          console.error(`ALERT_ERROR token=${token} err=${err.message}`)
        )
      );

      // Return immediately — body is never read
      return gif();
    }

    return new Response("not found", { status: 404 });
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

function isAllowedWebhookURL(url, env) {
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== "https:") return false;

    // Check built-in allowlist
    if (WEBHOOK_DOMAIN_ALLOWLIST.some(d => parsed.hostname === d || parsed.hostname.endsWith("." + d))) {
      return true;
    }

    // Check operator-configured domains (comma-separated env var)
    const extra = (env.WEBHOOK_ALLOWED_DOMAINS || "").split(",").filter(Boolean);
    if (extra.some(d => parsed.hostname === d.trim() || parsed.hostname.endsWith("." + d.trim()))) {
      return true;
    }

    return false;
  } catch {
    return false;
  }
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
  const authHeader = request.headers.get("authorization") || "";
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) {
    return { ok: false, error: "missing Authorization header" };
  }
  const secret = match[1];

  if (!deviceId) {
    return { ok: false, error: "missing device_id" };
  }

  if (!env.SNARE_KV) {
    return { ok: false, error: "KV not configured" };
  }

  const secretHash = await hashSecret(secret);

  // Check if device is registered
  const storedRaw = await env.SNARE_KV.get(`device:${deviceId}`);
  if (!storedRaw) {
    // First time — register this device
    await env.SNARE_KV.put(`device:${deviceId}`, JSON.stringify({
      secret_hash: secretHash,
      registered_at: new Date().toISOString(),
    }));
    return { ok: true, deviceId, isNew: true };
  }

  // Validate secret against stored hash
  try {
    const stored = JSON.parse(storedRaw);
    if (stored.secret_hash !== secretHash) {
      return { ok: false, error: "invalid device secret" };
    }
    return { ok: true, deviceId };
  } catch {
    return { ok: false, error: "corrupt device record" };
  }
}

// ─── Metadata extraction (HEADERS ONLY — never touches body) ────────────────

function extractMetadata(request, url) {
  const cf = request.cf || {};
  return {
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
    // Capture specific safe headers that indicate SDK type
    sdkHints: {
      amzSdkRequest: request.headers.get("x-amz-sdk-request") || null,
      amzTarget:     request.headers.get("x-amz-target") || null,
      contentType:   request.headers.get("content-type") || null,
    },
  };
}

// ─── Alert processing (runs after response is already sent) ─────────────────

async function processAlert(token, metadata, env) {
  const ua = metadata.userAgent;

  // Ignore link preview bots
  if (PREVIEW_BOTS.some(b => ua.includes(b))) return;

  // Deduplicate: same token+IP within 60 seconds fires only once
  if (await isDuplicate(env, token, metadata.ip)) return;

  const isTest = token.startsWith("snare-test-");

  const event = {
    token,
    is_test:   isTest,
    timestamp: metadata.timestamp,
    ip:        metadata.ip,
    userAgent: metadata.userAgent,
    method:    metadata.method,
    path:      metadata.path,
    country:   metadata.country,
    city:      metadata.city,
    asn:       metadata.asn,
    asnOrg:    metadata.asnOrg,
    botScore:  metadata.botScore,
    sdkHints:  metadata.sdkHints,
    // EXPLICITLY: no body field. This is intentional and must never be added.
  };

  // Log metadata only — never body content
  console.log("CANARY_FIRED", JSON.stringify({
    token: event.token,
    is_test: event.is_test,
    ip: event.ip,
    method: event.method,
    country: event.country,
    asnOrg: event.asnOrg,
    userAgent: (event.userAgent || "").slice(0, 100),
  }));

  // Store event (metadata only)
  if (env.SNARE_KV) {
    const key = `event:${token}:${Date.now()}:${crypto.randomUUID()}`;
    await env.SNARE_KV.put(key, JSON.stringify(event), {
      expirationTtl: 60 * 60 * 24 * 90,
    });
  }

  // Resolve webhook + metadata
  const { webhooks, meta } = await resolveWebhooks(token, env);

  const results = await Promise.allSettled(
    webhooks.map(wh => forwardAlert(wh, event, meta, env))
  );
  results.forEach((r, i) => {
    if (r.status === "rejected") {
      console.error(`WEBHOOK_FAILED url=${webhooks[i]} token=${token} err=${r.reason}`);
    }
  });
}

// ─── Events lookup ───────────────────────────────────────────────────────────

async function handleEvents(token, request, env) {
  if (!env.SNARE_KV) return json({ error: "KV not configured" }, 500);

  // Auth: require device secret
  // Look up which device owns this token
  const regRaw = await env.SNARE_KV.get(`webhook:${token}`);
  let deviceId = null;
  if (regRaw) {
    try {
      const reg = JSON.parse(regRaw);
      deviceId = reg.device_id;
    } catch { /* fall through */ }
  }

  // Auth required for ALL event reads — no unauthenticated fallback
  const headerDeviceId = deviceId || request.headers.get("x-snare-device-id") || "";
  if (!headerDeviceId) {
    return json({ error: "authentication required" }, 401);
  }
  const auth = await validateAuth(request, env, headerDeviceId);
  if (!auth.ok) {
    return json({ error: auth.error }, 401);
  }

  const prefix = `event:${token}:`;
  const list = await env.SNARE_KV.list({ prefix, limit: 20 });

  const events = [];
  for (const key of list.keys) {
    const raw = await env.SNARE_KV.get(key.name);
    if (raw) {
      try { events.push(JSON.parse(raw)); } catch { /* skip corrupt */ }
    }
  }

  if (events.length === 0) {
    return json({ token, events: [] }, 404);
  }

  events.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  return json({ token, events: events.slice(0, 10) });
}

// ─── Device creation ────────────────────────────────────────────────────────

// POST /api/devices — server mints a device_id, client sends only its secret.
// This prevents squatting on device IDs.
async function handleCreateDevice(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return json({ error: "invalid JSON" }, 400); }

  const { device_secret } = body;
  if (!device_secret || typeof device_secret !== "string" || device_secret.length < 32) {
    return json({ error: "device_secret required (min 32 chars)" }, 400);
  }
  if (!env.SNARE_KV) return json({ error: "KV not configured" }, 500);

  // Server-minted device ID — client cannot predict or squat it
  const randomBytes = crypto.getRandomValues(new Uint8Array(16));
  const deviceId = "dev-" + Array.from(randomBytes).map(b => b.toString(16).padStart(2, "0")).join("");

  const secretHash = await hashSecret(device_secret);
  await env.SNARE_KV.put(`device:${deviceId}`, JSON.stringify({
    secret_hash: secretHash,
    created_at: new Date().toISOString(),
  }));

  return json({ status: "created", device_id: deviceId });
}

// ─── Registration ───────────────────────────────────────────────────────────

async function handleRegister(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return json({ error: "invalid JSON" }, 400); }

  const { token_id, webhook_url, device_id, canary_type, label } = body;

  if (!token_id?.match(/^[a-zA-Z0-9_-]{8,80}$/)) {
    return json({ error: "invalid token_id" }, 400);
  }
  // "use-global" sentinel binds token ownership without a per-token webhook;
  // delivery routes through the global WEBHOOK_URLS CF secret.
  if (webhook_url !== "use-global") {
    if (!webhook_url?.startsWith("https://")) {
      return json({ error: "webhook_url must be https:// or 'use-global'" }, 400);
    }
    if (!isAllowedWebhookURL(webhook_url, env)) {
      return json({ error: "webhook_url domain not allowed — must be Discord, Slack, Telegram, PagerDuty, Teams, or 'use-global'" }, 403);
    }
  }
  if (!device_id) {
    return json({ error: "missing device_id" }, 400);
  }
  if (!env.SNARE_KV) {
    return json({ error: "KV not configured" }, 500);
  }

  // Validate device auth
  const auth = await validateAuth(request, env, device_id);
  if (!auth.ok) {
    return json({ error: auth.error }, 401);
  }

  // Check if this token is already registered to a DIFFERENT device
  const existingRaw = await env.SNARE_KV.get(`webhook:${token_id}`);
  if (existingRaw) {
    try {
      const existing = JSON.parse(existingRaw);
      if (existing.device_id && existing.device_id !== device_id) {
        return json({ error: "token already registered to another device" }, 403);
      }
    } catch { /* corrupt entry — allow overwrite */ }
  }

  await env.SNARE_KV.put(`webhook:${token_id}`, JSON.stringify({
    webhook_url,
    device_id:     device_id   || null,
    canary_type:   canary_type || null,
    label:         label       || null,
    registered_at: new Date().toISOString(),
  }), { expirationTtl: 60 * 60 * 24 * 365 }); // 1 year TTL

  return json({ status: "registered", token_id });
}

async function handleRevoke(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return json({ error: "invalid JSON" }, 400); }

  if (!body.token_id) return json({ error: "missing token_id" }, 400);
  if (!body.device_id) return json({ error: "missing device_id" }, 400);
  if (!env.SNARE_KV)  return json({ error: "KV not configured" }, 500);

  // Validate: only the device that registered can revoke
  const regRaw = await env.SNARE_KV.get(`webhook:${body.token_id}`);
  if (regRaw) {
    try {
      const reg = JSON.parse(regRaw);
      if (reg.device_id && reg.device_id !== body.device_id) {
        return json({ error: "device_id mismatch — only the registering device can revoke" }, 403);
      }
    } catch { /* fall through */ }
  }

  // Validate device auth
  const auth = await validateAuth(request, env, body.device_id);
  if (!auth.ok) {
    return json({ error: auth.error }, 401);
  }

  await env.SNARE_KV.delete(`webhook:${body.token_id}`);
  return json({ status: "revoked", token_id: body.token_id });
}

// ─── Device secret rotation ──────────────────────────────────────────────────

// POST /api/rotate — update device secret hash for an existing device.
// Requires: old secret for auth (proves ownership), new secret in body.
async function handleRotateSecret(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return json({ error: "invalid JSON" }, 400); }

  const { device_id, new_secret } = body;
  if (!device_id)   return json({ error: "missing device_id" }, 400);
  if (!new_secret)  return json({ error: "missing new_secret" }, 400);
  if (new_secret.length < 32) return json({ error: "new_secret too short (min 32 chars)" }, 400);
  if (!env.SNARE_KV) return json({ error: "KV not configured" }, 500);

  // Auth with current secret (Authorization header)
  const auth = await validateAuth(request, env, device_id);
  if (!auth.ok) return json({ error: auth.error }, 401);

  // Hash the new secret and update device record
  const encoder = new TextEncoder();
  const keyData = encoder.encode(new_secret);
  const hashBuf = await crypto.subtle.digest("SHA-256", keyData);
  const newHash = Array.from(new Uint8Array(hashBuf)).map(b => b.toString(16).padStart(2, "0")).join("");

  const deviceRaw = await env.SNARE_KV.get(`device:${device_id}`);
  let deviceRecord = {};
  try { deviceRecord = JSON.parse(deviceRaw || "{}"); } catch { /**/ }

  deviceRecord.secret_hash = newHash;
  deviceRecord.rotated_at = new Date().toISOString();

  await env.SNARE_KV.put(`device:${device_id}`, JSON.stringify(deviceRecord));

  return json({ status: "rotated", device_id });
}

// ─── Webhook resolution ─────────────────────────────────────────────────────

async function resolveWebhooks(token, env) {
  let meta = {};
  let perTokenWebhook = null;

  // Always try to load registration metadata (type, label, device)
  if (env.SNARE_KV) {
    const raw = await env.SNARE_KV.get(`webhook:${token}`);
    if (raw) {
      try {
        const reg = JSON.parse(raw);
        meta = { canaryType: reg.canary_type, label: reg.label, deviceId: reg.device_id };
        // Use per-token webhook if it's a valid https URL
        // (fixed: proper parentheses for operator precedence)
        if (reg.webhook_url &&
            reg.webhook_url.startsWith("https://") &&
            !reg.webhook_url.includes("use-global")) {
          perTokenWebhook = reg.webhook_url;
        }
      } catch { /* fall through */ }
    }
  }

  // Per-token webhook takes priority; otherwise fall back to global
  const webhooks = perTokenWebhook
    ? [perTokenWebhook]
    : (env.WEBHOOK_URLS || "").split(",").filter(Boolean);

  return { webhooks, meta };
}

// ─── Alert formatting ────────────────────────────────────────────────────────

async function forwardAlert(webhookURL, event, meta = {}, env = {}) {
  const isDiscord  = webhookURL.includes("discord.com/api/webhooks");
  const isSlack    = webhookURL.includes("hooks.slack.com");
  const isTelegram = webhookURL.includes("api.telegram.org");

  const type     = CANARY_TYPES[meta.canaryType] || DEFAULT_TYPE;
  const asnLower = (event.asnOrg || "").toLowerCase();
  const fromCloud = CLOUD_PROVIDERS.some(p => asnLower.includes(p));

  let body;

  if (isDiscord) {
    body = JSON.stringify(buildDiscordPayload(event, meta, type, fromCloud));
  } else if (isSlack) {
    body = JSON.stringify(buildSlackPayload(event, meta, type, fromCloud));
  } else if (isTelegram) {
    body = JSON.stringify(buildTelegramPayload(event, meta, type, fromCloud));
  } else {
    body = JSON.stringify(buildGenericPayload(event, meta, type, fromCloud));
  }

  const headers = {
    "content-type": "application/json",
    "user-agent": "snare.sh/1.0",
  };

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
    } catch (e) {
      console.error("SIGN_ERROR", e.message);
    }
  }

  return fetch(webhookURL, { method: "POST", headers, body });
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
      name:   "⚠️ Likely AI agent",
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
      footer:    { text: "snare.sh · request body was never captured" },
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
      footer: "snare.sh · request body was never captured",
      ts:     Math.floor(new Date(event.timestamp).getTime() / 1000),
    }],
  };
}

function buildTelegramPayload(event, meta, type, fromCloud) {
  const isTest   = event.is_test;
  const location = [event.city, event.country].filter(Boolean).join(", ") || "unknown";
  const network  = event.asnOrg ? `${event.asnOrg} (AS${event.asn})` : (event.ip || "unknown");

  let title;
  if (isTest) {
    title = `🧪 <b>Test alert — ${type.name}</b>`;
  } else if (meta.label) {
    title = `${type.emoji} <b>${type.name} canary fired — ${meta.label}</b>`;
  } else {
    title = `${type.emoji} <b>${type.name} canary fired</b>`;
  }

  const lines = [
    title,
    "",
    `<b>Token:</b> <code>${event.token}</code>`,
    `<b>Time:</b> ${event.timestamp.replace("T", " ").replace(/\.\d+Z$/, " UTC")}`,
    `<b>IP:</b> ${event.ip || "unknown"}`,
    `<b>Location:</b> ${location}`,
    `<b>Network:</b> ${network}`,
    `<b>Method:</b> ${event.method}`,
    `<b>UA:</b> <code>${(event.userAgent || "unknown").slice(0, 100)}</code>`,
  ];

  if (fromCloud && !isTest) {
    lines.push("", `⚠️ <b>Likely AI agent</b> — request from cloud infrastructure`);
  }

  lines.push("", "<i>Request body was never captured</i>");

  return { parse_mode: "HTML", text: lines.join("\n") };
}

function buildGenericPayload(event, meta, type, fromCloud) {
  return {
    event:       "canary.fired",
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

// Rate limiter using KV.
// Note: KV is eventually consistent — this is a best-effort rate limit.
// It will not prevent every concurrent burst but stops sustained abuse.
// For strict atomicity, migrate to Durable Objects (v2 milestone).
async function checkRateLimit(env, key, maxRequests, windowSeconds) {
  if (!env.SNARE_KV) return false;
  const bucket = `rl:${key}:${Math.floor(Date.now() / (windowSeconds * 1000))}`;
  // Write-then-read: write optimistically, then check the count
  // This doesn't fully prevent races but reduces the window significantly
  const current = parseInt(await env.SNARE_KV.get(bucket) || "0", 10);
  if (current >= maxRequests) return true;
  // Increment — may race under high concurrency but worst case is minor overshoot
  await env.SNARE_KV.put(bucket, String(current + 1), { expirationTtl: windowSeconds * 2 });
  return false;
}

// Dedup: prevent duplicate alerts for same token+IP within the window.
// KV is eventually consistent — duplicate events are possible under race.
// The 60-second window significantly reduces duplicate noise in practice.
// Strict dedup requires Durable Objects (v2 milestone).
async function isDuplicate(env, token, ip) {
  if (!env.SNARE_KV) return false;
  const key = `dedup:${token}:${ip}:${Math.floor(Date.now() / 60000)}`;
  if (await env.SNARE_KV.get(key)) return true;
  await env.SNARE_KV.put(key, "1", { expirationTtl: 120 });
  return false;
}

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
    headers: { "content-type": "application/json" },
  });
}
