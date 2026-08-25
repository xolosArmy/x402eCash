# x402eCash

Public research, engineering, and evidence portal for x402 on eCash (XEC),
Tonalli Wallet, paid APIs, agent-to-agent payments, and policy-controlled
machine commerce.

- Public site: <https://x402.ecash.mx>
- English: `/`
- Spanish: `/es/`

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

## Experimental status

x402eCash is an experimental xolosArmy Network research project. The site does
not represent every architecture path as live. It does not provide a paid
backend, automatic XEC mainnet payments, autonomous real-fund spending, or
wallet custody. References to upstream projects do not imply endorsement.
