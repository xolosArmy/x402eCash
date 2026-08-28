# H3WC B1B static client candidate

**IMPLEMENTATION COMPLETE — LIVE TRANSPORT QUALIFICATION PENDING HUMAN QA**

This candidate is a dormant alternative transport for the existing Gate H3C
experiment. The committed site has no H3WC enablement global, so
`webmcp-bootstrap.js` does not import `h3wc-client.js`, the generated module,
or any WalletConnect code in the default GitHub Pages deployment. The current
H3A/H3B-tab/H3C callback path remains unchanged.

## Adapter contract

`experiments/webmcp/h3wc-client.js` is the only x402eCash-facing boundary. It
lazy-loads the generated module only after the explicit local QA flag
`globalThis.__X402_H3WC_ENABLED__ === true`. The generated adapter exposes
only:

```text
createTonalliConnectClient
connect
restore
getAccountIdentity
requestH3BAuthorization
disconnect
```

The WalletConnect namespace is exact: `ecash:1`, methods
`ecash_getAccountIdentity` and `ecash_signMessage`, no events, and one
canonical account. Every approved/restored session is requalified before a
request; proposal shape is not authority. The storage purpose is the fixed
`tonalli-h3wc-v1` prefix. The client sends no transaction or payment method.

## Build provenance

The isolated `tooling/h3wc-client/` workspace pins Node `24.19.0`, npm
`11.9.0`, `@walletconnect/core@2.23.10`,
`@walletconnect/sign-client@2.23.10`, and `esbuild@0.28.2` in its own lockfile.
`npm run build` emits one browser ES module and deterministic provenance and
license files. The generated artifact is self-hosted; it has no runtime CDN
JavaScript, dynamic chunk, or WASM import. Two clean builds must have equal
SHA-256 before publication.

## Local QA only

Provide an authorized development project ID through an uncommitted browser
global, together with the exact requester origin. The generated client is
transport-only. `ecash_signMessage` is expected to reach the B1 wallet
boundary and fail with `H3WC_SIGNING_NOT_ENABLED`; no signature, payment,
transaction, broadcast, or real credential is used by this candidate. Relay,
session restore, two-tab Web Locks, and human approval remain pending the
separate B1-QA review.
