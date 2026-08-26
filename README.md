# x402eCash

Public research, engineering, and evidence portal for x402 on eCash (XEC),
Tonalli Wallet, paid APIs, agent-to-agent payments, and policy-controlled
machine commerce.

- Public site: <https://x402.ecash.mx>
- English: `/`
- Spanish: `/es/`
- WebMCP experiment: `/experiments/webmcp/`

## Project relationship

`x402eCash` is the static public laboratory and evidence portal.
[`x402-XEC`](https://github.com/xolosArmy/x402-XEC) is the separate experimental
protocol implementation. The portal documents verified repository evidence; it
does not execute payments and does not turn experimental code into a production
service.

## Local preview

No build step or dependencies are required. From the repository root:

```sh
python3 -m http.server 8000
```

Then open `http://localhost:8000/` or `http://localhost:8000/es/`.

## Repository structure

```text
.
├── index.html                 # English homepage
├── es/index.html              # Spanish mirror
├── styles.css                 # Shared responsive design system
├── script.js                  # Optional navigation enhancement
├── experiments/webmcp/       # Static WebMCP H3C experiment and harnesses
├── assets/x402ecash-mark.svg  # Original vector mark and favicon
├── robots.txt
├── sitemap.xml
├── CNAME
└── README.md
```

## Evidence sources

The public status and roadmap are grounded in immutable revisions of:

- [`xolosArmy/x402-XEC`](https://github.com/xolosArmy/x402-XEC)
- [`xolosArmy/RMZWallet`](https://github.com/xolosArmy/RMZWallet)
- [`xolosArmy/tonalli-core`](https://github.com/xolosArmy/tonalli-core)
- [`xolosArmy/tonalli-agents`](https://github.com/xolosArmy/tonalli-agents)
- [`xolosArmy/tonalli-commerce-relay`](https://github.com/xolosArmy/tonalli-commerce-relay)
- [`x402-foundation/x402`](https://github.com/x402-foundation/x402)

Source links in the site are pinned to the commit inspected for the build so
that claims remain auditable when upstream branches advance.

## Deployment

The repository is deployed as a zero-build static site through GitHub Pages.
`CNAME` is part of the production configuration and must remain exactly:

```text
x402.ecash.mx
```

## WebMCP Gate H3C

Gate H3C extends the live H2B HTTP 402 validation and H3A human decision with
an ephemeral, browser-only rendezvous for Tonalli H3B authorization proofs:

```text
WebMCP → HTTP 402 → human approval → same-origin handoff
→ Tonalli authorization-only proof → callback → local cryptographic verification
→ STOP
```

The canonical Tonalli origin is pinned to `https://app.tonalli.cash`, as
confirmed by Tonalli's canonical repository metadata and the live Tonalli
Wallet site. The route contract is:

```text
https://app.tonalli.cash/connect/x402-authorize#request=<canonical-base64url>
```

The first tool, `get_paid_xec_resource`, no longer declares
`annotations.readOnlyHint = true`: after H3A approval it opens an interactive
wallet-authorization workflow. This does not spend funds, but it is not merely
a read. The second tool, `get_x402_authorization_result`, retains
`readOnlyHint = true` because it only reads page-owned in-memory state.

The callback proof is verified locally with a specialized, MIT-licensed
verifier built from Bitcoin ABC's `ecash-lib` 4.5.2—the exact primitive used
by canonical Tonalli H3B—and `ecashaddrjs` 2.0.0. Its public JavaScript surface
is limited to recovery, hashing, and address handling. No verifier is loaded
from a CDN and no remote verification API is called. See
`experiments/webmcp/vendor/NOTICE.md` for the exact embedded-asset boundary.

All H3C state is intentionally ephemeral. It is not written to localStorage,
sessionStorage, IndexedDB, cookies, analytics, or a server. The canonical H3B
request and callback use URL fragments only for cross-application transport;
the same-origin bootstrap captures them in memory and immediately removes them
with `history.replaceState` before loading the verifier graph. Cleanup failure
stops the flow. Reloading the original page destroys the rendezvous.

Tonalli H3B remains disabled by default with
`VITE_X402_H3B_ENABLED=false`. This repository does not enable or deploy it,
so the H3C implementation is not a production end-to-end pass by itself. A
future manual round trip requires a separately authorized Tonalli deployment
with H3B deliberately enabled.

Gate H3C creates no `PAYMENT-SIGNATURE`, transaction, settlement, broadcast,
Chronik request, protected-resource retry, or XEC transfer.

## Experimental status

x402eCash is an experimental xolosArmy Network research project. The site does
not represent every architecture path as live. It does not provide a paid
backend, automatic XEC mainnet payments, autonomous real-fund spending, or
wallet custody. References to upstream projects do not imply endorsement.
