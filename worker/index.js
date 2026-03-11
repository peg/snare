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
        "Googlebot", "bingbot", "curl/", // also filter our own test curls in prod
      ];
      // Only filter preview bots, not curl (curl is useful for testing)
      const isPreviewBot = PREVIEW_BOTS.slice(0, -1).some(b => ua.includes(b));
      if (isPreviewBot) {
        return new Response("", { status: 200 });
      }
      const event = {
        token,
        timestamp: new Date().toISOString(),
        ip: request.headers.get("cf-connecting-ip"),
        userAgent: request.headers.get("user-agent"),
        method: request.method,
        path: url.pathname + url.search,
        // Capture body for POST callbacks (e.g. from MCP canary server)
        body: request.method === "POST"
          ? await request.text().catch(() => null)
          : null,
      };

      // Log to console (visible in wrangler tail)
      console.log("CANARY_FIRED", JSON.stringify(event));

      // Store in KV if configured
      if (env.SNARE_KV) {
        const key = `event:${token}:${Date.now()}`;
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
  // Format differs by webhook type
  const isSlack = webhookURL.includes("hooks.slack.com");
  const isDiscord = webhookURL.includes("discord.com/api/webhooks");

  let body;

  if (isSlack || isDiscord) {
    const text = [
      "🚨 *Snare canary fired*",
      `Token: \`${event.token}\``,
      `Time: ${event.timestamp}`,
      `IP: ${event.ip || "unknown"}`,
      `UA: ${event.userAgent || "unknown"}`,
      event.body ? `Body: \`${event.body.slice(0, 200)}\`` : null,
    ].filter(Boolean).join("\n");

    body = JSON.stringify(
      isDiscord ? { content: text } : { text }
    );
  } else {
    // Generic webhook — send full event JSON
    body = JSON.stringify(event);
  }

  return fetch(webhookURL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body,
  });
}
