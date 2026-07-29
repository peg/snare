# Managed Worker staging

The managed callback service has an isolated Cloudflare staging environment:

- Worker: `snare-callback-staging`
- Hostname: `https://staging.snare.sh`
- KV namespace: `snare-events-staging`
- GitHub environment: `snare-worker-staging`

The staging Worker never binds production KV. Its runtime secrets must also be
staging-only; do not copy production webhook destinations into staging.

## Deployment flow

After CI succeeds for a commit on `main`, the staging workflow deploys that
exact commit, waits for `/health` to report the exact new Cloudflare version,
and runs a synthetic lifecycle test:

1. Create a staging device.
2. Register a `snare-test-*` token.
3. Trigger its callback.
4. Read the stored event with device authentication.
5. Revoke the token and remove the synthetic device and event keys.

The workflow can also be dispatched manually. Production remains a separate,
manually dispatched workflow protected by `snare-worker-production`.

## Required GitHub environment configuration

Create `snare-worker-staging` in repository settings with:

- environment secret `CLOUDFLARE_WORKER_API_TOKEN`;
- environment variable `CLOUDFLARE_ACCOUNT_ID`;
- deployment branches restricted to `main`.

Use a dedicated staging token scoped to this Cloudflare account with only
`Workers Scripts: Edit` and `Workers KV Storage: Edit`. The latter is required
because the smoke test deletes its synthetic KV records after verification.
The staging custom domain is managed by the Workers Scripts permission; DNS
Edit and broad zone permissions are not required.

## Optional staging webhook

The lifecycle test proves registration, callback ingestion, KV storage, and
authenticated event reads without requiring an outbound webhook. To exercise
delivery manually, set the staging Worker's `WEBHOOK_URLS` secret to a dedicated
non-production destination:

```sh
cd worker
npx wrangler secret put WEBHOOK_URLS --env staging
```
