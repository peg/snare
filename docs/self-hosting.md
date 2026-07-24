# Self-hosting Snare

Snare supports two self-hosting paths:

1. `snare serve` — a standalone HTTP server with SQLite storage and a built-in dashboard.
2. Cloudflare Worker — the same Worker-style callback path used by managed `snare.sh`, deployed to your own Cloudflare account.

Use self-hosting when you need a custom callback domain, network-layer control, enterprise lab isolation, custom retention, or SIEM relays that require private credentials.

## Option A: Docker Compose with `snare serve`

```sh
{
  echo "SNARE_DASHBOARD_TOKEN=$(openssl rand -hex 32)"
  echo "SNARE_ENROLLMENT_TOKEN=$(openssl rand -hex 32)"
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
| `SNARE_ENROLLMENT_TOKEN` | Required. Separately authorizes creation of new devices. Generate with `openssl rand -hex 32` and provide it only during enrollment. |
| `SNARE_PORT` | Host port mapped to container port 8080. |
| `SNARE_DB` / `--db` | SQLite database path. In Compose this is `/data/snare.db`. |
| `SNARE_WEBHOOK_URL` / `--webhook-url` | Global fallback alert destination. Per-token webhooks still take priority. |
| `SNARE_TLS_DOMAIN` / `--tls-domain` | Enables built-in Let's Encrypt TLS when running directly on 80/443. |
| `--trusted-proxy` | Comma-separated CIDRs trusted to supply `X-Forwarded-For` or `X-Real-IP`. |

`snare serve --help` prints the complete flag reference.

## Option B: run the server directly

```sh
SNARE_DASHBOARD_TOKEN="$(openssl rand -hex 32)" \
SNARE_ENROLLMENT_TOKEN="$(openssl rand -hex 32)" \
  snare serve \
    --port 8080 \
    --db /var/lib/snare/snare.db \
    --webhook-url https://example.com/snare-webhook
```

For a reverse-proxy deployment, bind Snare on an internal port and expose only the proxy:

```sh
SNARE_DASHBOARD_TOKEN="$(openssl rand -hex 32)" \
SNARE_ENROLLMENT_TOKEN="$(openssl rand -hex 32)" \
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

Enroll and arm each new client by providing the callback base and enrollment token as environment variables. The enrollment token is sent only to `POST /api/devices`; it is not saved in `~/.snare/config.json`.

```sh
SNARE_CALLBACK_BASE=https://snare.example.com/c \
SNARE_ENROLLMENT_TOKEN="$SNARE_ENROLLMENT_TOKEN" \
  snare arm --webhook https://example.com/snare-webhook
snare doctor --test
```

Existing enrolled clients do not need the enrollment token for ordinary registration, event retrieval, rotation, or callback traffic. If you already planted canaries against another callback base, disarm and re-arm during a maintenance window:

```sh
snare disarm
SNARE_CALLBACK_BASE=https://snare.example.com/c \
SNARE_ENROLLMENT_TOKEN="$SNARE_ENROLLMENT_TOKEN" \
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

### Security upgrade from v0.4.0 or earlier

Device creation was not enrollment-protected in these releases. If `/api/devices` was reachable from an untrusted network, a database row alone does not prove that an existing device was approved.

Before exposing the upgraded service:

1. Back up the current SQLite database and keep that copy offline if historical events must be retained.
2. Configure distinct dashboard and enrollment tokens.
3. Start the upgraded service with a fresh active database.
4. Disarm and re-enroll approved clients during a maintenance window using `SNARE_CALLBACK_BASE` and `SNARE_ENROLLMENT_TOKEN`.

If the device API was never reachable outside a trusted administrative network, known existing clients can continue using their current device secrets.

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
- [ ] Enrollment token is distinct from the dashboard token, stored outside source control, and shared only with administrators enrolling devices.
- [ ] Dashboard is behind TLS and an access-controlled reverse proxy if exposed beyond localhost.
- [ ] `--trusted-proxy` is limited to actual reverse proxy addresses.
- [ ] SQLite database backups are encrypted or stored in a restricted backup system.
- [ ] Webhook URLs and signing secrets are treated as credentials.
- [ ] Webhook destinations use public HTTPS endpoints; Snare refuses private/reserved destinations and redirects.
- [ ] Client `callback_base` points to the intended `/c` path and was verified with `snare doctor --test`.
- [ ] `snare disarm --purge` cleanup is tested on a pilot host.
