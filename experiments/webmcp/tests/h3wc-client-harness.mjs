import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { test, after } from 'node:test'

const testsDirectory = dirname(fileURLToPath(import.meta.url))
const webmcpDirectory = resolve(testsDirectory, '..')
const repositoryDirectory = resolve(webmcpDirectory, '../..')
const artifactPath = join(webmcpDirectory, 'vendor/tonalli-connect-client-v1.mjs')
const sourcePath = join(repositoryDirectory, 'tooling/h3wc-client/src/tonalli-connect-client.mjs')
const clientPath = join(webmcpDirectory, 'h3wc-client.js')
const bootstrapPath = join(webmcpDirectory, 'webmcp-bootstrap.js')
const webmcpPath = join(webmcpDirectory, 'webmcp.js')
const contractPath = join(webmcpDirectory, 'h3wc-contract-v1.json')
const rmzContractPath = join(repositoryDirectory, '../RMZWallet/src/lib/h3wc/h3wc-contract-v1.json')

const [artifact, source, clientSource, bootstrapSource, webmcpSource, contractBytes, rmzContractBytes] = await Promise.all([
  readFile(artifactPath, 'utf8'),
  readFile(sourcePath, 'utf8'),
  readFile(clientPath, 'utf8'),
  readFile(bootstrapPath, 'utf8'),
  readFile(webmcpPath, 'utf8'),
  readFile(contractPath),
  readFile(rmzContractPath)
])

const client = await import('../vendor/tonalli-connect-client-v1.mjs')
const runtime = await import('../h3wc-client.js')
const fixture = {
  topic: 'h3wc-test-topic',
  expiry: 4_000_000_000,
  acknowledged: true,
  namespaces: {
    ecash: {
      chains: ['ecash:1'],
      methods: ['ecash_signMessage', 'ecash_getAccountIdentity'],
      events: [],
      accounts: ['ecash:1:qdeterministicfixture']
    }
  },
  peer: { metadata: { url: 'https://app.tonalli.cash' } }
}

test('exact H3WC namespace is exported', () => {
  assert.deepEqual(client.H3WC_REQUIRED_NAMESPACES, {
    ecash: { chains: ['ecash:1'], methods: ['ecash_getAccountIdentity', 'ecash_signMessage'], events: [] }
  })
})

test('effective session qualifier accepts only the exact grant', () => {
  const qualified = client.qualifyH3wcSession(fixture, { nowSeconds: 1_000 })
  assert.equal(qualified.account, 'ecash:1:qdeterministicfixture')
  assert.equal(qualified.peerOrigin, 'https://app.tonalli.cash')
})

for (const [name, mutate] of [
  ['extra method', (session) => { session.namespaces.ecash.methods.push('ecash_signAndBroadcast') }],
  ['extra chain', (session) => { session.namespaces.ecash.chains.push('ecash:2') }],
  ['extra event', (session) => { session.namespaces.ecash.events.push('accountsChanged') }],
  ['extra account', (session) => { session.namespaces.ecash.accounts.push('ecash:1:pother') }],
  ['wrong peer origin', (session) => { session.peer.metadata.url = 'https://evil.example' }]
]) {
  test(`qualifier rejects ${name}`, () => {
    const candidate = structuredClone(fixture)
    mutate(candidate)
    assert.throws(() => client.qualifyH3wcSession(candidate, { nowSeconds: 1_000 }))
  })
}

test('qualifier rejects an expired effective session', () => {
  assert.throws(() => client.qualifyH3wcSession({ ...fixture, expiry: 1_000 }, { nowSeconds: 1_000 }))
})

test('qualifier rejects unknown namespace authority fields', () => {
  const candidate = structuredClone(fixture)
  candidate.namespaces.ecash.sessionProperties = {}
  assert.throws(() => client.qualifyH3wcSession(candidate, { nowSeconds: 1_000 }))
})

test('identity schema is exact and public-only', () => {
  assert.deepEqual(client.__testing.canonicalIdentity({
    address: 'ecash:qdeterministicfixture',
    publicKey: '02' + 'a'.repeat(64)
  }), {
    address: 'ecash:qdeterministicfixture',
    publicKey: '02' + 'a'.repeat(64)
  })
  assert.throws(() => client.__testing.canonicalIdentity({ address: 'ecash:qdeterministicfixture', publicKey: '02' + 'A'.repeat(64) }))
  assert.throws(() => client.__testing.canonicalIdentity({ address: 'ecash:qdeterministicfixture', publicKey: '02' + 'a'.repeat(64), mnemonic: 'x' }))
})

test('requester-facing module is dormant with the flag absent', async () => {
  delete globalThis.__X402_H3WC_ENABLED__
  assert.equal(runtime.H3WC_DEFAULT_ENABLED, false)
  assert.equal(runtime.isH3wcEnabled(), false)
  assert.equal(await runtime.mountH3wcQaPanel(), null)
})

test('QA panel requires an explicit project ID and exact requester origin', async () => {
  globalThis.__X402_H3WC_ENABLED__ = true
  globalThis.__X402_H3WC_CONFIG__ = { projectId: 'dev-only', requesterOrigin: 'https://evil.example' }
  await assert.rejects(() => runtime.mountH3wcQaPanel({ documentImplementation: { body: {} } }), /requester origin/u)
  delete globalThis.__X402_H3WC_ENABLED__
  delete globalThis.__X402_H3WC_CONFIG__
})

test('bootstrap dynamically imports H3WC only behind the hard flag', () => {
  assert.match(bootstrapSource, /globalThis\[H3WC_FLAG_NAME\] === true/u)
  assert.match(bootstrapSource, /await import\('\.\/h3wc-client\.js'\)/u)
})

test('H3WC client does not depend on WebMCP internals', () => {
  assert.doesNotMatch(clientSource, /modelContext|registerTool/u)
  assert.doesNotMatch(source, /document\.modelContext|navigator\.modelContext/u)
})

test('source contains no signing primitive, payment, transaction, or persistence path', () => {
  assert.doesNotMatch(source, /signMsg|getSignatory|withPrivateKey|PAYMENT-SIGNATURE|Chronik|localStorage|sessionStorage|indexedDB|BroadcastChannel/u)
  assert.match(source, /ecash_signMessage/u)
})

test('adapter uses the fixed H3WC storage prefix and direct SignClient', () => {
  assert.match(source, /tonalli-h3wc-v1/u)
  assert.match(source, /@walletconnect\/sign-client/u)
  assert.match(source, /requiredNamespaces: H3WC_REQUIRED_NAMESPACES/u)
  assert.doesNotMatch(source, /UniversalProvider|AppKit|WalletKit/u)
})

test('bundle has one self-contained ESM artifact and no dynamic code loader', () => {
  assert.doesNotMatch(artifact, /import\s*\(/u)
  assert.doesNotMatch(artifact, /\.wasm/u)
  assert.doesNotMatch(artifact, /(?:unpkg|jsdelivr|cdnjs|skypack)/iu)
  assert.match(artifact, /ecash_getAccountIdentity/u)
  assert.match(artifact, /ecash_signMessage/u)
})

test('contract fixture bytes match RMZWallet', () => {
  assert.equal(createHash('sha256').update(contractBytes).digest('hex'), '6f98007d77d0feaa8aeabadc16f18b5234e800582f645d0bc974422ab5de3d7a')
  assert.deepEqual(contractBytes, rmzContractBytes)
})

test('existing H3C keeps exactly one protected-resource fetch path', () => {
  assert.equal((webmcpSource.match(/fetchImplementation\(LIVE_RESOURCE_URL/g) ?? []).length, 1)
  assert.doesNotMatch(webmcpSource, /PAYMENT-SIGNATURE|Chronik|ecash_signAndBroadcast/u)
})

after(() => {
  delete globalThis.__X402_H3WC_ENABLED__
  delete globalThis.__X402_H3WC_CONFIG__
  console.log('H3WC B1B deterministic harness: 19/19 PASS')
})
