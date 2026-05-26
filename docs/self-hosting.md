# Self-hosting Snare

Snare supports two self-hosting paths:

1. `snare serve` — a standalone HTTP server with SQLite storage and a built-in dashboard.
2. Cloudflare Worker — the same Worker-style callback path used by managed `snare.sh`, deployed to your own Cloudflare account.

Use self-hosting when you need a custom callback domain, network-layer control, enterprise lab isolation, custom retention, or SIEM relays that require private credentials.

## Option A: Docker Compose with `snare serve`

```sh
{
  echo "SNARE_DASHBOARD_TOKEN=$(openssl rand -hex 32)"
  echo "SNARE_PORT=8080"
  echo "SNARE_WEBHOOK_URL="
  echo "SNARE_TLS_DOMAIN="
} > .env

docker compose up -d
curl -fsS http://localhost:8080/health
```

The Compose file stores SQLite data in the `snare-data` volume at `/data/snare.db` inside the container.

Important settings:

| Setting | Purpose |
|---|---|
| `SNARE_DASHBOARD_TOKEN` | Required. Protects the dashboard and dashboard API. Generate with `openssl rand -hex 32`. |
| `SNARE_PORT` | Host port mapped to container port 8080. |
| `SNARE_DB` / `--db` | SQLite database path. In Compose this is `/data/snare.db`. |
| `SNARE_WEBHOOK_URL` / `--webhook-url` | Global fallback alert destination. Per-token webhooks still take priority. |
| `SNARE_TLS_DOMAIN` / `--tls-domain` | Enables built-in Let's Encrypt TLS when running directly on 80/443. |
| `--trusted-proxy` | Comma-separated CIDRs trusted to supply `X-Forwarded-For` or `X-Real-IP`. |

`snare serve --help` prints the complete flag reference.

## Option B: run the server directly

```sh
SNARE_DASHBOARD_TOKEN="$(openssl rand -hex 32)" \
  snare serve \
    --port 8080 \
    --db /var/lib/snare/snare.db \
    --webhook-url https://example.com/snare-webhook
```

For a reverse-proxy deployment, bind Snare on an internal port and expose only the proxy:

```sh
SNARE_DASHBOARD_TOKEN="$(openssl rand -hex 32)" \
  snare serve \
    --port 8080 \
    --db /var/lib/snare/snare.db \
    --trusted-proxy 10.0.0.0/8,127.0.0.1/32
```

Do not trust broad proxy CIDRs unless every host in that range is allowed to set client IP headers.

## Reverse proxy notes

A minimal Caddy-style shape is:

```caddyfile
snare.example.com {
  reverse_proxy 127.0.0.1:8080
}
```

If the proxy terminates TLS and forwards traffic to Snare over HTTP, set `--trusted-proxy` only to the proxy IP or CIDR so event IP attribution can use forwarded headers safely.

## Pointing clients at the self-hosted callback base

Initialize Snare, then edit `~/.snare/config.json` so `callback_base` points to your deployment's `/c` path:

```json
{
  "callback_base": "https://snare.example.com/c"
}
```

Then arm fresh canaries so registrations and planted callback URLs use the self-hosted server:

```sh
snare arm --webhook https://example.com/snare-webhook
snare doctor --test
```

If you already planted canaries against another callback base, disarm and re-arm during a maintenance window so on-disk bait is regenerated with the new URL:

```sh
snare disarm
snare arm --webhook https://example.com/snare-webhook
snare doctor --test
```

## Backups and restore

Back up the SQLite database and the server configuration/secrets together:

```sh
# Direct server path example.
sqlite3 /var/lib/snare/snare.db ".backup /var/backups/snare/snare.db.$(date +%Y%m%d%H%M%S)"

# Docker volume example: copy the database file out of the named volume with a temporary container.
volume="$(docker volume ls --format '{{.Name}}' | grep 'snare-data$' | head -n1)"
docker run --rm -v "$volume:/data:ro" -v "$PWD:/backup" alpine \
  sh -c 'cp /data/snare.db /backup/snare.db.backup'
```

Restore by stopping the server, replacing the database file, fixing permissions, and starting the server again.

## Upgrades

For source-built Compose deployments:

```sh
git fetch --tags origin
git checkout <release-tag-or-commit>
docker compose build --pull
docker compose up -d
curl -fsS http://localhost:8080/health
```

After upgrade, run from a pilot client:

```sh
snare doctor --test
snare prove --run --report --redact --format json --output proof.json
```

## Cloudflare Worker self-hosting

The Worker source lives in `worker/`.

```sh
cd worker
npm install
npx wrangler kv namespace create SNARE_KV
# Update worker/wrangler.toml with your account, route, and KV namespace.
npx wrangler secret put WEBHOOK_URLS
npx wrangler secret put WEBHOOK_SIGNING_SECRET
npx wrangler deploy
curl -fsS https://snare.example.com/health
```

Adjust `worker/wrangler.toml` routes from `snare.sh` to your domain before deploying. `WEBHOOK_URLS` is a comma-separated fallback list. `WEBHOOK_SIGNING_SECRET` enables `X-Snare-Signature` on outbound webhook posts.

## Security checklist

- [ ] Dashboard token is at least 32 random hex bytes and stored outside source control.
- [ ] Dashboard is behind TLS and an access-controlled reverse proxy if exposed beyond localhost.
- [ ] `--trusted-proxy` is limited to actual reverse proxy addresses.
- [ ] SQLite database backups are encrypted or stored in a restricted backup system.
- [ ] Webhook URLs and signing secrets are treated as credentials.
- [ ] Client `callback_base` points to the intended `/c` path and was verified with `snare doctor --test`.
- [ ] `snare disarm --purge` cleanup is tested on a pilot host.
