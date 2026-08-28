# x402eCash H3WC client build workspace

This disposable development workspace produces the self-hosted browser
adapter at `experiments/webmcp/vendor/tonalli-connect-client-v1.mjs`.
It is not a runtime server and is never loaded when the committed H3WC flag
is off.

## Rebuild

Use Node `24.19.0` and npm `11.9.0` with the checked-in lockfile:

```sh
npm ci
npm run build -- --summary
npm test
```

The bundle is built from one entry point with `esbuild 0.28.2`, browser
platform, ESM format, no source map, no code splitting, no runtime CDN import,
and no WASM. The generated provenance and license inventory are deterministic.
Run the command twice from clean copies and compare the artifact SHA-256; the
two builds must be byte-identical before a candidate is reviewed.

## Local human QA

The production repository intentionally has no user-facing switch and keeps
H3WC disabled. For a disposable local review only, set these globals before
loading `/experiments/webmcp/` in a development browser profile:

```js
globalThis.__X402_H3WC_ENABLED__ = true
globalThis.__X402_H3WC_CONFIG__ = {
  projectId: '<authorized-development-project-id>',
  requesterOrigin: 'https://x402.ecash.mx'
}
```

The project ID is configuration, not a signing secret, and must not be
committed. The panel only exercises connect/restore/identity/disconnect and a
transport request expected to fail with `H3WC_SIGNING_NOT_ENABLED` on the
feature-flagged B1 wallet candidate. No real signing or payment is part of B1.
