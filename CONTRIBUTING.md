# Contributing to Snare

Thanks for your interest. Snare is early-stage and moving fast — contributions are very welcome.

## Development setup

```sh
git clone https://github.com/peg/snare
cd snare
go build ./...
go test ./...
```

No external dependencies required. The CLI is a single static binary.

## Project layout

```
cmd/snare/          entrypoint
internal/cli/       command routing and UX
internal/bait/      canary templates and plant/remove logic
internal/manifest/  ~/.snare/manifest.json management
internal/config/    ~/.snare/config.json management
internal/token/     credential token generation (crypto/rand)
internal/serve/     self-hosted callback server (snare serve)
worker/             Cloudflare Worker (snare.sh backend)
```

## Adding a new canary type

1. Add a `Type` constant in `internal/bait/bait.go`
2. Add a template in the `templates` map
3. Add a `case` in `Plant()` to set template data fields
4. Add the type to `highReliabilityTypes` or leave it as medium (default)
5. Add the type string to the `CANARY_TYPES` array in `worker/index.js`
6. Add a test in `internal/bait/bait_test.go`

The key constraint: **the callback URL must be the real service endpoint**, not a comment or secondary field. If the SDK won't call it during normal credential use, it's medium reliability at best.

## Running tests

```sh
go test ./...                    # all packages
go test ./internal/bait/... -v   # verbose, single package
go test ./... -race -count=1     # with race detector (matches CI)
```

## Submitting changes

- Open an issue first for significant changes
- Keep PRs focused — one thing per PR
- Tests required for new canary types and CLI commands
- No giveaway strings in generated credentials (`SNARE`, `FAKE`, `TEST`, `canary`)

## Worker development

```sh
cd worker
npx wrangler dev    # local dev server
npx wrangler deploy # deploy to your own CF account
```

The worker never reads request bodies. Please maintain this invariant.

## License

Apache 2.0. By contributing, you agree your contributions are licensed under the same terms.
