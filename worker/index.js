/**
 * snare.sh — Cloudflare Worker callback receiver
 *
 * Routes:
 *   GET/POST /c/{token}     — canary callback receiver
 *   POST     /api/register  — register a webhook for a token
 *   POST     /api/revoke    — remove a token webhook registration
 *   GET      /health        — health check
 *
 * Deploy: wrangler deploy
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Health check
    if (url.pathname === "/health") {
      return new Response(JSON.stringify({ status: "ok" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }

    // Token registration: POST /api/register
    // Body: { token_id, webhook_url, device_id }
    if (url.pathname === "/api/register" && request.method === "POST") {
      return handleRegister(request, env);
    }

    // Token revocation: POST /api/revoke
    // Body: { token_id }
    if (url.pathname === "/api/revoke" && request.method === "POST") {
      return handleRevoke(request, env);
    }

    // Canary callback: GET or POST /c/{token}
    const match = url.pathname.match(/^\/c\/([a-zA-Z0-9_-]{8,80})$/);
    if (match) {
      return handleCallback(match[1], request, env, url);
    }

    return new Response("not found", { status: 404 });
  },
};

// Register a per-token webhook URL
async function handleRegister(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }

  const { token_id, webhook_url, device_id } = body;
  if (!token_id || typeof token_id !== "string" || !token_id.match(/^[a-zA-Z0-9_-]{8,80}$/)) {
    return json({ error: "invalid token_id" }, 400);
  }
  if (!webhook_url || typeof webhook_url !== "string" || !webhook_url.startsWith("https://")) {
    return json({ error: "invalid webhook_url — must be https://" }, 400);
  }

  if (!env.SNARE_KV) {
    return json({ error: "KV not configured" }, 500);
  }

  const value = JSON.stringify({
    webhook_url,
    device_id: device_id || null,
    registered_at: new Date().toISOString(),
  });

  // 90-day TTL — refreshed on re-registration (e.g. snare plant again)
  await env.SNARE_KV.put(`webhook:${token_id}`, value, {
    expirationTtl: 60 * 60 * 24 * 90,
  });

  return json({ status: "registered", token_id });
}

// Revoke a per-token webhook registration (called on teardown)
async function handleRevoke(request, env) {
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }

  const { token_id } = body;
  if (!token_id || typeof token_id !== "string") {
    return json({ error: "missing token_id" }, 400);
  }

  if (!env.SNARE_KV) {
    return json({ error: "KV not configured" }, 500);
  }

  await env.SNARE_KV.delete(`webhook:${token_id}`);
  return json({ status: "revoked", token_id });
}

// Handle incoming canary callback
async function handleCallback(token, request, env, url) {
  // Ignore known link-preview bots — they auto-crawl URLs in messages
  const ua = request.headers.get("user-agent") || "";
  const PREVIEW_BOTS = [
    "Discordbot", "Slackbot", "Twitterbot", "facebookexternalhit",
    "LinkedInBot", "TelegramBot", "WhatsApp", "iMessage",
    "Googlebot", "bingbot",
  ];
  if (PREVIEW_BOTS.some(b => ua.includes(b))) {
    return gif();
  }

  // Rate limit: deduplicate events per token+IP within 60 seconds
  if (env.SNARE_KV) {
    const ip = request.headers.get("cf-connecting-ip") || "unknown";
    const dedupKey = `dedup:${token}:${ip}:${Math.floor(Date.now() / 60000)}`;
    const seen = await env.SNARE_KV.get(dedupKey);
    if (seen) {
      return gif();
    }
    await env.SNARE_KV.put(dedupKey, "1", { expirationTtl: 60 });
  }

  const cf = request.cf || {};
  const event = {
    token,
    timestamp: new Date().toISOString(),
    ip: request.headers.get("cf-connecting-ip"),
    userAgent: ua,
    method: request.method,
    path: url.pathname + url.search,
    country: cf.country || null,
    city: cf.city || null,
    asn: cf.asn || null,
    asnOrg: cf.asOrganization || null,
    botScore: cf.botManagement?.score ?? null,
    body: request.method === "POST"
      ? (await request.text().catch(() => "")).slice(0, 4096) || null
      : null,
  };

  console.log("CANARY_FIRED", JSON.stringify(event));

  // Store event in KV
  if (env.SNARE_KV) {
    const key = `event:${token}:${Date.now()}:${crypto.randomUUID()}`;
    await env.SNARE_KV.put(key, JSON.stringify(event), {
      expirationTtl: 60 * 60 * 24 * 90,
    });
  }

  // Look up per-token webhook first, fall back to global WEBHOOK_URLS secret
  const webhooks = await resolveWebhooks(token, env);

  const results = await Promise.allSettled(
    webhooks.map(wh => forwardAlert(wh, event))
  );
  results.forEach((r, i) => {
    if (r.status === "rejected") {
      console.error(`WEBHOOK_FAILED url=${webhooks[i]} token=${token} error=${r.reason}`);
    }
  });

  return gif();
}

// Resolve webhooks for a token: per-token registration takes priority,
// falls back to the global WEBHOOK_URLS CF secret.
async function resolveWebhooks(token, env) {
  if (env.SNARE_KV) {
    const raw = await env.SNARE_KV.get(`webhook:${token}`);
    if (raw) {
      try {
        const reg = JSON.parse(raw);
        if (reg.webhook_url) return [reg.webhook_url];
      } catch { /* fall through */ }
    }
  }
  // Global fallback (Trevor's CF secret for testing/self-hosted)
  return (env.WEBHOOK_URLS || "").split(",").filter(Boolean);
}

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

async function forwardAlert(webhookURL, event) {
  const isSlack   = webhookURL.includes("hooks.slack.com");
  const isDiscord = webhookURL.includes("discord.com/api/webhooks");

  let body;

  if (isDiscord) {
    const cloudProviders = ["amazon", "google", "microsoft", "openai", "anthropic",
      "digitalocean", "linode", "vultr", "hetzner", "fly.io", "railway", "render"];
    const asnLower = (event.asnOrg || "").toLowerCase();
    const likelyAgent = cloudProviders.some(p => asnLower.includes(p));

    const ts = new Date(event.timestamp);
    const tsFormatted = ts.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");
    const location = [event.city, event.country].filter(Boolean).join(", ") || "unknown";
    const network = event.asnOrg
      ? `${event.asnOrg} (AS${event.asn})`
      : (event.ip || "unknown");

    const fields = [
      { name: "Token",    value: `\`${event.token}\``,                                       inline: true  },
      { name: "Time",     value: tsFormatted,                                                 inline: true  },
      { name: "Method",   value: event.method,                                                inline: true  },
      { name: "IP",       value: event.ip || "unknown",                                       inline: true  },
      { name: "Location", value: location,                                                    inline: true  },
      { name: "Network",  value: network,                                                     inline: true  },
      { name: "UA",       value: `\`${(event.userAgent || "unknown").slice(0, 100)}\``,       inline: false },
    ];

    if (likelyAgent) {
      fields.push({
        name: "⚠️ Likely AI agent",
        value: `Request originated from ${event.asnOrg} — cloud infrastructure`,
        inline: false,
      });
    }
    if (event.botScore !== null && event.botScore < 30) {
      fields.push({
        name: "🤖 Bot score",
        value: `${event.botScore}/100 — high confidence automated`,
        inline: false,
      });
    }
    if (event.body) {
      fields.push({
        name: "Body",
        value: `\`\`\`${event.body.slice(0, 300)}\`\`\``,
        inline: false,
      });
    }

    body = JSON.stringify({
      embeds: [{
        title: "🪤 Snare fired",
        color: 0xb2121a,
        fields,
        footer: { text: "snare.sh" },
        timestamp: event.timestamp,
      }],
    });
  } else if (isSlack) {
    body = JSON.stringify({
      text: `🪤 *Canary fired* — \`${event.token}\``,
      attachments: [{
        color: "#b2121a",
        fields: [
          { title: "IP",     value: event.ip || "unknown",                        short: true  },
          { title: "Method", value: event.method,                                 short: true  },
          { title: "UA",     value: (event.userAgent || "unknown").slice(0, 80),  short: false },
        ],
        footer: "snare.sh",
        ts: Math.floor(new Date(event.timestamp).getTime() / 1000),
      }],
    });
  } else {
    // Generic webhook — send raw JSON event
    body = JSON.stringify(event);
  }

  return fetch(webhookURL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  });
}
