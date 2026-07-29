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

The workflow can also be dispatched manually. A manual staging run is useful
for diagnosis, but it does not qualify a commit for production because it is
not chained to a successful `CI` push run.

## Production promotion

Production remains a separate, manually dispatched workflow protected by
`snare-worker-production`. To deploy:

1. Copy the exact 40-character commit SHA from `main`.
2. Confirm the automatic staging workflow for that commit passed.
3. Dispatch `Deploy Cloudflare Worker` from the `main` branch, choose `deploy`,
   and enter that commit SHA.
4. If a reviewer gate is configured, approve the protected production
   environment deployment when prompted.

The production workflow checks out the requested commit, proves that it belongs
to `main`, and uses the GitHub Actions API to require a successful automatic
staging run for that exact SHA. A successful manual staging run does not satisfy
the gate. Production then reports and verifies the exact Cloudflare Worker
version that became active.

Use `validate` with a `main` commit SHA to test the production credentials and
deployment bundle without requiring a staging run or changing production.

## Required GitHub environment configuration

Create `snare-worker-staging` in repository settings with:

- environment secret `CLOUDFLARE_WORKER_API_TOKEN`;
- environment variable `CLOUDFLARE_ACCOUNT_ID`;
- deployment branches restricted to `main`.

Use a dedicated staging token with:

- account-scoped `Workers Scripts: Edit`;
- account-scoped `Workers KV Storage: Edit`; and
- zone-scoped `Workers Routes: Edit` restricted to `snare.sh`.

KV write access is required because the smoke test deletes its synthetic
records after verification. Wrangler also reconciles Worker routes during a
deploy, including when the configured target is a custom domain. DNS Edit and
broad access to other zones are not required.

Configure `snare-worker-production` separately with its production-scoped
Cloudflare token and account ID, restrict deployments to `main`, and require an
environment reviewer when the repository has a second trusted maintainer. The
workflow exposes the Cloudflare credentials only to the steps that inspect or
change the production Worker.

## Optional staging webhook

The lifecycle test proves registration, callback ingestion, KV storage, and
authenticated event reads without requiring an outbound webhook. To exercise
delivery manually, set the staging Worker's `WEBHOOK_URLS` secret to a dedicated
non-production destination:

```sh
cd worker
npx wrangler secret put WEBHOOK_URLS --env staging
```
