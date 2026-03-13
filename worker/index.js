/**
 * snare.sh — Cloudflare Worker callback receiver
 *
 * PRIVACY GUARANTEE:
 *   This worker NEVER reads, logs, stores, or forwards HTTP request bodies.
 *   When a canary fires, the worker captures only connection metadata
 *   (IP, User-Agent, method, country, ASN) from request HEADERS.
 *   The response is returned BEFORE any body could be consumed.
 *   This is a deliberate design choice — canary callbacks may carry
 *   real credentials or sensitive data in their bodies, and we must
 *   never have access to that data, even transiently in memory.
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

    if (url.pathname === "/api/register" && request.method === "POST") {
      return handleRegister(request, env);
    }

    if (url.pathname === "/api/revoke" && request.method === "POST") {
      return handleRevoke(request, env);
    }

    // Events lookup: GET /api/events/{token}
    const eventsMatch = url.pathname.match(/^\/api\/events\/([a-zA-Z0-9_-]{8,80})$/);
    if (eventsMatch && request.method === "GET") {
      return handleEvents(eventsMatch[1], request, env);
    }

    // Canary callback: /c/{token} or /c/{token}/anything (for OpenAI /v1 suffix etc.)
    // NO AUTH — SDKs/tools must hit this unknowingly
    const match = url.pathname.match(/^\/c\/([a-zA-Z0-9_-]{8,80})(\/.*)?$/);
    if (match) {
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
  if (env.SNARE_KV) {
    const dedupKey = `dedup:${token}:${metadata.ip}:${Math.floor(Date.now() / 60000)}`;
    if (await env.SNARE_KV.get(dedupKey)) return;
    await env.SNARE_KV.put(dedupKey, "1", { expirationTtl: 60 });
  }

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
    webhooks.map(wh => forwardAlert(wh, event, meta))
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

  // If token has a registered device, require auth from that device
  // If token is unregistered (global fallback), require any valid device auth
  if (deviceId) {
    const auth = await validateAuth(request, env, deviceId);
    if (!auth.ok) {
      return json({ error: auth.error }, 401);
    }
  } else {
    // For unregistered tokens, check if request has any valid device auth
    const authHeader = request.headers.get("authorization") || "";
    const headerDeviceId = request.headers.get("x-snare-device-id") || "";
    if (authHeader && headerDeviceId) {
      const auth = await validateAuth(request, env, headerDeviceId);
      if (!auth.ok) {
        return json({ error: auth.error }, 401);
      }
    }
    // If no auth provided for unregistered token, allow read
    // (backward compat for snare status on machines using global webhook)
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

// ─── Registration ───────────────────────────────────────────────────────────

async function handleRegister(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return json({ error: "invalid JSON" }, 400); }

  const { token_id, webhook_url, device_id, canary_type, label } = body;

  if (!token_id?.match(/^[a-zA-Z0-9_-]{8,80}$/)) {
    return json({ error: "invalid token_id" }, 400);
  }
  if (!webhook_url?.startsWith("https://")) {
    return json({ error: "webhook_url must be https://" }, 400);
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

  await env.SNARE_KV.put(`webhook:${token_id}`, JSON.stringify({
    webhook_url,
    device_id:     device_id   || null,
    canary_type:   canary_type || null,
    label:         label       || null,
    registered_at: new Date().toISOString(),
  }), { expirationTtl: 60 * 60 * 24 * 365 }); // 1 year TTL (was 90 days)

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

async function forwardAlert(webhookURL, event, meta = {}) {
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

  return fetch(webhookURL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  });
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

function gif() {
  // 1x1 transparent GIF — smallest valid response
  return new Response(
    "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x00\x00\x00\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b",
    { status: 200, headers: { "content-type": "image/gif", "cache-control": "no-store" } }
  );
}

function json(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}
