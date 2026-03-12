/**
 * snare.sh — Cloudflare Worker callback receiver
 *
 * Routes:
 *   GET/POST /c/{token}     — canary callback receiver
 *   POST     /api/register  — register webhook + metadata for a token
 *   POST     /api/revoke    — remove a token registration
 *   GET      /health        — health check
 */

// Per-canary type config: emoji, color, display name
const CANARY_TYPES = {
  aws:       { emoji: "🔑", color: 0xFF9900, name: "AWS"       },
  gcp:       { emoji: "☁️",  color: 0x4285F4, name: "GCP"       },
  github:    { emoji: "⬛", color: 0x24292E, name: "GitHub"    },
  stripe:    { emoji: "💳", color: 0x6772E5, name: "Stripe"    },
  openai:    { emoji: "🤖", color: 0x10A37F, name: "OpenAI"    },
  anthropic: { emoji: "🟠", color: 0xD4572F, name: "Anthropic" },
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
  async fetch(request, env) {
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
      return handleEvents(eventsMatch[1], env);
    }

    const match = url.pathname.match(/^\/c\/([a-zA-Z0-9_-]{8,80})$/);
    if (match) {
      return handleCallback(match[1], request, env, url);
    }

    return new Response("not found", { status: 404 });
  },
};

// ─── Events lookup ───────────────────────────────────────────────────────────

async function handleEvents(token, env) {
  if (!env.SNARE_KV) return json({ error: "KV not configured" }, 500);

  // List all event keys for this token
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

  // Sort newest first
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
  if (!env.SNARE_KV) {
    return json({ error: "KV not configured" }, 500);
  }

  await env.SNARE_KV.put(`webhook:${token_id}`, JSON.stringify({
    webhook_url,
    device_id:   device_id   || null,
    canary_type: canary_type || null,
    label:       label       || null,
    registered_at: new Date().toISOString(),
  }), { expirationTtl: 60 * 60 * 24 * 90 });

  return json({ status: "registered", token_id });
}

async function handleRevoke(request, env) {
  let body;
  try { body = await request.json(); }
  catch { return json({ error: "invalid JSON" }, 400); }

  if (!body.token_id) return json({ error: "missing token_id" }, 400);
  if (!env.SNARE_KV)  return json({ error: "KV not configured" }, 500);

  await env.SNARE_KV.delete(`webhook:${body.token_id}`);
  return json({ status: "revoked", token_id: body.token_id });
}

// ─── Callback ───────────────────────────────────────────────────────────────

async function handleCallback(token, request, env, url) {
  const ua = request.headers.get("user-agent") || "";

  if (PREVIEW_BOTS.some(b => ua.includes(b))) return gif();

  const ip = request.headers.get("cf-connecting-ip") || "unknown";

  // Deduplicate: same token+IP within 60 seconds fires only once
  if (env.SNARE_KV) {
    const dedupKey = `dedup:${token}:${ip}:${Math.floor(Date.now() / 60000)}`;
    if (await env.SNARE_KV.get(dedupKey)) return gif();
    await env.SNARE_KV.put(dedupKey, "1", { expirationTtl: 60 });
  }

  const cf = request.cf || {};
  const isTest = token.startsWith("snare-test-");

  const event = {
    token,
    is_test:   isTest,
    timestamp: new Date().toISOString(),
    ip,
    userAgent: ua,
    method:    request.method,
    path:      url.pathname + url.search,
    country:   cf.country       || null,
    city:      cf.city          || null,
    asn:       cf.asn           || null,
    asnOrg:    cf.asOrganization || null,
    botScore:  cf.botManagement?.score ?? null,
    body: request.method === "POST"
      ? (await request.text().catch(() => "")).slice(0, 4096) || null
      : null,
  };

  console.log("CANARY_FIRED", JSON.stringify(event));

  // Store event
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

  return gif();
}

// Resolve webhook(s) + registration metadata for a token
async function resolveWebhooks(token, env) {
  if (env.SNARE_KV) {
    const raw = await env.SNARE_KV.get(`webhook:${token}`);
    if (raw) {
      try {
        const reg = JSON.parse(raw);
        if (reg.webhook_url) {
          return {
            webhooks: [reg.webhook_url],
            meta: { canaryType: reg.canary_type, label: reg.label, deviceId: reg.device_id },
          };
        }
      } catch { /* fall through */ }
    }
  }
  // Global fallback (operator-configured CF secret)
  return {
    webhooks: (env.WEBHOOK_URLS || "").split(",").filter(Boolean),
    meta: {},
  };
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
    // Telegram uses chat_id embedded in the URL as a query param or path
    // Format: https://api.telegram.org/bot{token}/sendMessage?chat_id={id}
    body = JSON.stringify(buildTelegramPayload(event, meta, type, fromCloud));
  } else {
    // Generic webhook — clean JSON event with metadata
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
  const ts       = new Date(event.timestamp).toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
  const location = [event.city, event.country].filter(Boolean).join(", ") || "unknown";
  const network  = event.asnOrg ? `${event.asnOrg} (AS${event.asn})` : (event.ip || "unknown");

  // Title: show canary type + label if we have it
  let title;
  if (isTest) {
    title = `🧪 Test alert — ${type.name}`;
  } else if (meta.label) {
    title = `${type.emoji} ${type.name} canary fired — ${meta.label}`;
  } else {
    title = `${type.emoji} ${type.name} canary fired`;
  }

  const fields = [
    { name: "Token",    value: `\`${event.token}\``,      inline: false },
    { name: "Time",     value: ts,                        inline: true  },
    { name: "Method",   value: event.method,              inline: true  },
    { name: "IP",       value: event.ip || "unknown",     inline: true  },
    { name: "Location", value: location,                  inline: true  },
    { name: "Network",  value: network,                   inline: true  },
    { name: "UA",       value: `\`${(event.userAgent || "unknown").slice(0, 120)}\``, inline: false },
  ];

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

  if (event.body) {
    fields.push({
      name:   "Request body",
      value:  `\`\`\`\n${event.body.slice(0, 400)}\n\`\`\``,
      inline: false,
    });
  }

  return {
    embeds: [{
      title,
      color:     isTest ? 0x888888 : type.color,
      fields,
      footer:    { text: "snare.sh" },
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
    { title: "Token",    value: `\`${event.token}\``,                              short: false },
    { title: "IP",       value: event.ip || "unknown",                             short: true  },
    { title: "Location", value: location,                                          short: true  },
    { title: "UA",       value: (event.userAgent || "unknown").slice(0, 100),      short: false },
  ];

  if (fromCloud && !isTest) {
    fields.push({ title: "⚠️ Source", value: `Cloud infrastructure: ${event.asnOrg}`, short: false });
  }

  return {
    text: title,
    attachments: [{
      color:  isTest ? "#888888" : `#${type.color.toString(16).padStart(6, "0")}`,
      fields,
      footer: "snare.sh",
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
      asn:     event.asn,
      org:     event.asnOrg,
      is_cloud: fromCloud,
    },
    request: {
      method:     event.method,
      user_agent: event.userAgent,
      body:       event.body,
    },
    bot_score: event.botScore,
  };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function gif() {
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
