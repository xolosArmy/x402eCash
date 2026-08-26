# Local H3C cryptographic verifier

`ecash-lib-4.5.2-verifier.js` is a browser ESM bundle with a deliberately
narrow public and JavaScript call surface for Gate H3C:

- `ecash-lib` 4.5.2 (`ecc_recoverSig`, `sha256d`, and `shaRmd160`)
- `ecashaddrjs` 2.0.0 (canonical eCash CashAddr encode/decode)

Both packages are maintained in the
[Bitcoin ABC repository](https://github.com/Bitcoin-ABC/bitcoin-abc) and are
distributed under the MIT license. The exact `ecash-lib` package is the version
locked by canonical Tonalli H3B commit
`e92981840b30f0b9a70d2519c1264c09e22f04ab` with npm integrity:

```text
sha512-klP5D6PABh16vwj3qs8nOQZx0rjJqCm4D2qHVJvJTFMKxv2AHZBJh2O3UmxzzagXXW28JYIp/7+PEDQfJgf6Yg==
```

The canonical lockfile also pins `ecashaddrjs` 2.0.0 with npm integrity:

```text
sha512-EvK1V4D3+nIEoD0ggy/b0F4lW39/72R9aOs/scm6kxMVuXu16btc+H74eQv7okNfXaQWKgolEekZkQ6wfcMMLw==
```

The bundle was produced locally with esbuild from the installed, lockfile-
verified packages. Specialized glue was derived from the package's generated
wasm-bindgen browser wrapper and retains only public-key recovery plus the two
hash calls H3C needs. It omits the asynchronous loader and all JavaScript
signing wrappers. The exact upstream WebAssembly asset is embedded and is
initialized synchronously; its SHA-256 is:

```text
c8f9e1f4d4af70dd68ab9568c54aec0bcd33b033c87f87c82dd4957a9028508b
```

The resulting verifier bundle has SHA-256:

```text
e750d466d2064170d40af5e855a5b1a13237d02adb0aea019b2d465687c42158
```

It has no external runtime import, network loader, signing wrapper, or remote
verification call. The embedded upstream WebAssembly module is the unmodified
general-purpose package asset, but the H3C JavaScript closure neither calls nor
exposes its signing exports.

The production H3C code only recovers and verifies public authorization-proof
signatures. It contains no signing secret and exposes no signing function.
