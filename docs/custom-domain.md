# Callback domains

Every canary contains a callback URL. If that URL names the project, anyone who
finds one canary can search for the rest and skip them all. Snare therefore
keeps two receiver addresses apart:

| Setting | Used for | Hosted default |
|---|---|---|
| Callback base (`callback_base`) | The URL written into planted files | A neutral host, assigned at enrollment |
| API base (`api_base`) | Enrollment, registration, events | `https://snare.sh` |

The callback host answers only `/c/...` requests and returns a plain `404` for
everything else, so probing it reveals nothing about the receiver behind it.

You have three choices, from least to most effort:

1. **Shared neutral host (default).** Nothing to set up. The hosted receiver
   assigns it when the machine enrolls, so it is not in Snare's source, and it
   can change without a CLI release. Every hosted user shares it, so anyone who
   enrolls can learn it.
2. **Your own domain on your own Cloudflare Worker** (free plan). Nobody else
   uses your host, so there is nothing public to match. See [Option A](#option-a-your-own-cloudflare-worker).
3. **Your own domain with `snare serve`** on a server you run. See [Option B](#option-b-snare-serve-on-your-own-server).

Pointing your own domain at the hosted receiver is not available yet.

## Check what you have

```sh
snare config
```

`Callback base` is what new canaries will contain. Configs enrolled before the
receiver assigned hosts show `https://snare.sh/c`. Those canaries keep working;
to move them, see [Moving existing canaries](#moving-existing-canaries).

## Choosing a hostname

- Use a subdomain of a domain that already has a normal website. A bare,
  newly registered domain stands out more.
- Pick a dull name such as `edge`, `api`, `cdn`, `registry` or `sso`. Avoid
  `canary`, `honey`, `trap`, `decoy`, `snare` and your security team's name.
- On your own Worker, use a separate hostname for the API. Planted files
  should never contain the host that serves `/api` or `/health`.
- The host needs a publicly trusted TLS certificate. Some canaries, such as
  `k8s`, verify TLS and send nothing when the certificate is untrusted.
- Certificates are published in Certificate Transparency logs, so the hostname
  becomes public when it gets a certificate. That is fine as long as nothing
  links the name to Snare.

## Option A: your own Cloudflare Worker

You need a Cloudflare account (free plan is enough), a domain whose DNS is on
Cloudflare, a current Node.js LTS release, and a clone of this repository. The example
uses `edge.example.com` for callbacks and `ops.example.com` for the API.

1. **Install and sign in.**

   ```sh
   cd worker
   npm ci
   npx wrangler login
   ```

2. **Create the database.**

   ```sh
   npx wrangler d1 create snare-state
   ```

   Note the `database_id` it prints.

3. **Write a private config.** Copy the example. Do not commit the copy.

   ```sh
   cp wrangler.d1.example.jsonc wrangler.private.jsonc
   ```

   In `wrangler.private.jsonc`:

   - set `name` to a neutral Worker name, `database_name` to `snare-state` and
     `database_id` to the ID from step 2;
   - add both hosts as custom domains, which also creates their DNS records
     and certificates:

     ```jsonc
     "routes": [
       { "pattern": "edge.example.com", "custom_domain": true },
       { "pattern": "ops.example.com", "custom_domain": true }
     ],
     ```

   - in `vars`, set `"API_HOSTS": "ops.example.com"` so the callback host serves
     only callbacks, and set `"ENROLLMENT_MODE": "invite"`;
   - give each rate limiter a `namespace_id` that is unused in your account.

4. **Create the tables.**

   ```sh
   npx wrangler d1 migrations apply snare-state --remote -c wrangler.private.jsonc
   ```

5. **Deploy and check.**

   ```sh
   npx wrangler deploy -c wrangler.private.jsonc
   curl -fsS https://ops.example.com/health           # JSON status
   curl -s -o /dev/null -w '%{http_code}\n' https://edge.example.com/health   # 404
   ```

   The first request to a new custom domain can take a minute while the
   certificate is issued.

6. **Add secrets.** Invite enrollment refuses every new device until the
   enrollment token exists. Save the printed token in your password manager.

   ```sh
   SNARE_ENROLLMENT_TOKEN="$(openssl rand -hex 32)"; echo "$SNARE_ENROLLMENT_TOKEN"
   printf %s "$SNARE_ENROLLMENT_TOKEN" | npx wrangler secret put SNARE_ENROLLMENT_TOKEN -c wrangler.private.jsonc
   npx wrangler secret put WEBHOOK_SIGNING_SECRET -c wrangler.private.jsonc   # optional
   npx wrangler secret put WEBHOOK_ALLOWED_DOMAINS -c wrangler.private.jsonc  # optional, extra webhook domains
   ```

7. **Enroll each machine.**

   ```sh
   SNARE_CALLBACK_BASE=https://edge.example.com/c \
   SNARE_API_BASE=https://ops.example.com \
   SNARE_ENROLLMENT_TOKEN=<token from step 6> \
     snare arm --webhook <your Discord, Slack or Telegram webhook>
   snare doctor --test
   ```

   The enrollment token is used once and is not saved.

[Receiver activation](receiver-activation.md) explains the storage limits and
[abuse controls](cloudflare-abuse-controls.md) explains enrollment modes and
rate limits.

## Option B: `snare serve` on your own server

`snare serve` is one process with SQLite storage. It serves the API and
callbacks on the same host, so give it a host you are happy to see in planted
files.

1. Point a DNS record such as `edge.example.com` at your server.
2. Start the server with built-in TLS, or behind your own reverse proxy as
   described in [Self-hosting](self-hosting.md):

   ```sh
   SNARE_DASHBOARD_TOKEN="$(openssl rand -hex 32)" \
   SNARE_ENROLLMENT_TOKEN="$(openssl rand -hex 32)" \
     snare serve --tls-domain edge.example.com --db /var/lib/snare/snare.db
   ```

   Save both tokens. The dashboard token protects the dashboard, and the
   enrollment token admits new machines.

3. Enroll each machine. With no `SNARE_API_BASE`, the API is the callback host
   without `/c`.

   ```sh
   SNARE_CALLBACK_BASE=https://edge.example.com/c \
   SNARE_ENROLLMENT_TOKEN=<enrollment token> \
     snare arm --webhook <webhook URL>
   snare doctor --test
   ```

## Moving existing canaries

Canaries keep the URL they were planted with. To move a machine to a new
receiver, remove them, enroll against the new receiver and plant again:

```sh
snare disarm
SNARE_CALLBACK_BASE=https://edge.example.com/c \
SNARE_API_BASE=https://ops.example.com \
SNARE_ENROLLMENT_TOKEN=<token> \
  snare init --force --webhook <webhook URL>
snare arm
snare doctor --test
```

To move hosted canaries from `snare.sh/c` to the neutral host, run the same
commands without any of the environment variables. Re-enrolling gives the
machine a new device ID.

`snare scan` finds leftover canaries on any host whose callback base ends in
`/c`, so it still works after a move.

## What a custom domain does not hide

Callback URLs still share a shape: `/c/` followed by a label and 32 hex
characters. A neutral or private host defeats a search for a known host name,
not a search for that pattern.

## Environment variables

| Variable | Effect at `snare init` and first `snare arm` |
|---|---|
| `SNARE_CALLBACK_BASE` | Callback base written into canaries. Must be `http(s)://host[/path]`. Unset, the hosted receiver assigns one. |
| `SNARE_API_BASE` | API base. If unset with a custom callback base, the callback base without `/c` is used. |
| `SNARE_ENROLLMENT_TOKEN` | Sent once to `POST /api/devices` on receivers with invite enrollment. Never saved. |

Both bases are stored in `~/.snare/config.json` and used until you run
`snare init --force`.
