/**
 * snare.sh — Cloudflare Worker callback receiver
 *
 * Any request to /c/{token} is a fired canary.
 * Logs the event, forwards to configured webhooks.
 *
 * Deploy: wrangler deploy
 */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Health check
    if (url.pathname === "/health") {
      return new Response("ok", { status: 200 });
    }

    // Canary callback: GET or POST /c/{token}
    const match = url.pathname.match(/^\/c\/([a-zA-Z0-9_-]{8,64})$/);
    if (match) {
      const token = match[1];

      // Ignore known link-preview bots — they auto-crawl URLs in messages
      const ua = request.headers.get("user-agent") || "";
      const PREVIEW_BOTS = [
        "Discordbot", "Slackbot", "Twitterbot", "facebookexternalhit",
        "LinkedInBot", "TelegramBot", "WhatsApp", "iMessage",
        "Googlebot", "bingbot",
      ];
      if (PREVIEW_BOTS.some(b => ua.includes(b))) {
        return new Response("", { status: 200 });
      }

      // Rate limit: deduplicate events per token within a 10-second window
      if (env.SNARE_KV) {
        const dedupKey = `dedup:${token}:${Math.floor(Date.now() / 10000)}`;
        const seen = await env.SNARE_KV.get(dedupKey);
        if (seen) {
          return new Response("", { status: 200, headers: { "cache-control": "no-store" } });
        }
        await env.SNARE_KV.put(dedupKey, "1", { expirationTtl: 30 });
      }
      const cf = request.cf || {};
      const event = {
        token,
        timestamp: new Date().toISOString(),
        ip: request.headers.get("cf-connecting-ip"),
        userAgent: request.headers.get("user-agent"),
        method: request.method,
        path: url.pathname + url.search,
        // Cloudflare geo + network intel (free)
        country: cf.country || null,
        city: cf.city || null,
        asn: cf.asn || null,
        asnOrg: cf.asOrganization || null,
        botScore: cf.botManagement?.score ?? null,
        // Capture body for POST callbacks
        body: request.method === "POST"
          ? (await request.text().catch(() => "")).slice(0, 4096) || null
          : null,
      };

      // Log to console (visible in wrangler tail)
      console.log("CANARY_FIRED", JSON.stringify(event));

      // Store in KV if configured
      if (env.SNARE_KV) {
        const key = `event:${token}:${Date.now()}:${crypto.randomUUID()}`;
        await env.SNARE_KV.put(key, JSON.stringify(event), {
          expirationTtl: 60 * 60 * 24 * 90, // 90 days
        });
      }

      // Forward to webhook(s)
      const webhooks = (env.WEBHOOK_URLS || "").split(",").filter(Boolean);
      await Promise.allSettled(webhooks.map(wh => forwardAlert(wh, event, env)));

      // Return a blank 1x1 pixel response (looks like a tracking pixel)
      return new Response(
        "\x47\x49\x46\x38\x39\x61\x01\x00\x01\x00\x00\x00\x00\x21\xf9\x04\x01\x00\x00\x00\x00\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02\x44\x01\x00\x3b",
        {
          status: 200,
          headers: { "content-type": "image/gif", "cache-control": "no-store" },
        }
      );
    }

    return new Response("not found", { status: 404 });
  },
};

async function forwardAlert(webhookURL, event, env) {
  const isSlack   = webhookURL.includes("hooks.slack.com");
  const isDiscord = webhookURL.includes("discord.com/api/webhooks");

  let body;

  if (isDiscord) {
    // Infer if likely an AI agent based on cloud ASN
    const cloudProviders = ["amazon", "google", "microsoft", "openai", "anthropic",
      "digitalocean", "linode", "vultr", "hetzner", "fly.io", "railway", "render"];
    const asnLower = (event.asnOrg || "").toLowerCase();
    const likelyAgent = cloudProviders.some(p => asnLower.includes(p));

    // Format timestamp as both exact + relative hint
    const ts = new Date(event.timestamp);
    const tsFormatted = ts.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC");

    // Location string
    const location = [event.city, event.country].filter(Boolean).join(", ") || "unknown";
    const network = event.asnOrg
      ? `${event.asnOrg} (AS${event.asn})`
      : (event.ip || "unknown");

    const fields = [
      { name: "Token",     value: `\`${event.token}\``,        inline: true  },
      { name: "Time",      value: tsFormatted,                  inline: true  },
      { name: "Method",    value: event.method,                 inline: true  },
      { name: "IP",        value: event.ip || "unknown",        inline: true  },
      { name: "Location",  value: location,                     inline: true  },
      { name: "Network",   value: network,                      inline: true  },
      { name: "UA",        value: `\`${(event.userAgent || "unknown").slice(0, 100)}\``, inline: false },
    ];

    if (likelyAgent) {
      fields.push({ name: "⚠️ Likely AI agent", value: `Request originated from ${event.asnOrg} — cloud infrastructure`, inline: false });
    }

    if (event.botScore !== null && event.botScore < 30) {
      fields.push({ name: "🤖 Bot score", value: `${event.botScore}/100 — high confidence automated`, inline: false });
    }

    if (event.body) {
      fields.push({ name: "Body", value: `\`\`\`${event.body.slice(0, 300)}\`\`\``, inline: false });
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
          { title: "IP",     value: event.ip || "unknown",  short: true },
          { title: "Method", value: event.method,           short: true },
          { title: "UA",     value: (event.userAgent || "unknown").slice(0, 80), short: false },
        ],
        footer: "snare.sh",
        ts: Math.floor(new Date(event.timestamp).getTime() / 1000),
      }],
    });
  } else {
    body = JSON.stringify(event);
  }

  return fetch(webhookURL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  });
}
