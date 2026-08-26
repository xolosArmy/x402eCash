import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import {
  H3B_MAX_PROOF_BASE64URL_LENGTH,
  H3C_CALLBACK_ACK_TIMEOUT_MS,
  H3C_HANDOFF_PATH,
  H3C_TTL_SECONDS,
  canonicalizeJson,
  createH3BRequest,
  decodeCanonicalBase64Url,
  decodeCanonicalH3BProof,
  encodeBase64UrlBytes,
  encodeCanonicalBase64Url,
  h3cChannelName,
  parseH3BCallback,
  parseH3BRequestTransport,
  recoverH3BCallbackChallenge,
  sha256CanonicalJson,
  tonalliH3BUrl,
  validatePaymentRequired
} from '../h3c-contract.js'
import { createH3CBridge } from '../h3c-bridge.js'
import { buildH3BAuthorizationMessage, verifySignedH3BProof } from '../h3c-verify.js'

const HERE = new URL('.', import.meta.url)
const WEBMCP_ROOT = fileURLToPath(new URL('../', import.meta.url))
const NOW = 1_800_000_000
const CHALLENGE = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'
const PAYMENT_REQUIRED_SHA256 = 'd865139386538ad3fddaa400d95c4074333cd52fdbbf8c1c6d42984fe214d793'

const PAYMENT_REQUIRED = Object.freeze({
  x402Version: 2,
  error: 'PAYMENT-SIGNATURE header is required',
  resource: Object.freeze({
    url: 'https://api.x402.ecash.mx/v1/resource/demo',
    description: 'x402eCash WebMCP Challenge demo resource',
    mimeType: 'application/json',
    serviceName: 'x402eCash'
  }),
  accepts: Object.freeze([Object.freeze({
    scheme: 'xec-prepaid-utxo',
    network: 'xec:mainnet',
    amount: '10000',
    asset: 'XEC',
    payTo: 'ecash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyquz9y96w',
    maxTimeoutSeconds: 60,
    extra: Object.freeze({ displayAmount: '100 XEC', experimental: true, gate: 'H2A' })
  })]),
  extensions: Object.freeze({})
})

const deterministicCrypto = Object.freeze({
  subtle: globalThis.crypto.subtle,
  getRandomValues (bytes) {
    assert.equal(bytes.byteLength, 32)
    for (let index = 0; index < bytes.length; index += 1) bytes[index] = index
    return bytes
  }
})

const vector = JSON.parse(await readFile(new URL('./fixtures/h3b-message-signature-vector.json', HERE), 'utf8'))
const unsignedVectorProof = JSON.parse(vector.message.split('\n').slice(1).join('\n'))
const signedVectorProof = Object.freeze({
  ...unsignedVectorProof,
  authorizationMessage: vector.message,
  authorizationSignature: Object.freeze({
    type: 'tonalli-message-signature',
    publicKey: vector.publicKey,
    signature: vector.signature
  })
})

const vectorRendezvous = Object.freeze({
  challengeId: CHALLENGE,
  issuedAt: NOW,
  expiresAt: NOW + H3C_TTL_SECONDS,
  paymentRequired: PAYMENT_REQUIRED,
  paymentRequiredSha256: PAYMENT_REQUIRED_SHA256
})

const tests = []
const test = (name, run) => tests.push({ name, run })

const clone = (value) => JSON.parse(JSON.stringify(value))
const sha256 = (value) => createHash('sha256').update(value).digest()
const compactSize = (value) => {
  if (value <= 252) return Buffer.from([value])
  if (value <= 0xffff) return Buffer.from([0xfd, value & 0xff, value >>> 8])
  if (value <= 0xffffffff) {
    return Buffer.from([0xfe, value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff])
  }
  throw new Error('fixture message is too large')
}
const expectFailure = async (operation, pattern = /./u) => {
  await assert.rejects(Promise.resolve().then(operation), pattern)
}

class MockBroadcastChannel {
  static rooms = new Map()

  static reset () {
    for (const room of this.rooms.values()) {
      for (const channel of room) channel.closed = true
    }
    this.rooms.clear()
  }

  constructor (name) {
    this.name = name
    this.closed = false
    this.onmessage = null
    const room = MockBroadcastChannel.rooms.get(name) ?? new Set()
    room.add(this)
    MockBroadcastChannel.rooms.set(name, room)
  }

  postMessage (data) {
    if (this.closed) throw new Error('closed')
    const room = MockBroadcastChannel.rooms.get(this.name) ?? new Set()
    for (const channel of room) {
      if (channel === this || channel.closed) continue
      const payload = structuredClone(data)
      queueMicrotask(() => {
        if (!channel.closed) channel.onmessage?.({ data: payload })
      })
    }
  }

  close () {
    if (this.closed) return
    this.closed = true
    const room = MockBroadcastChannel.rooms.get(this.name)
    room?.delete(this)
    if (room?.size === 0) MockBroadcastChannel.rooms.delete(this.name)
  }
}

const waitFor = async (predicate, timeoutMilliseconds = 1_000) => {
  const deadline = Date.now() + timeoutMilliseconds
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error('condition timeout')
    await new Promise((resolve) => setTimeout(resolve, 1))
  }
}

const createManualScheduler = () => {
  let nextId = 1
  const tasks = new Map()
  return {
    set (callback, delay) {
      const id = nextId
      nextId += 1
      tasks.set(id, { callback, delay, cleared: false })
      return id
    },
    clear (id) {
      const task = tasks.get(id)
      if (task) task.cleared = true
    },
    runDelay (delay) {
      for (const [id, task] of tasks) {
        if (task.cleared || task.delay !== delay) continue
        task.cleared = true
        tasks.set(id, task)
        task.callback()
      }
    }
  }
}

const autoHandshakeOpen = (openedUrls) => (url) => {
  openedUrls.push(url)
  const hash = new URL(url, 'https://x402.ecash.mx').hash
  const request = parseH3BRequestTransport({ hash, search: '', nowSeconds: NOW }).request
  const child = new MockBroadcastChannel(h3cChannelName(request.challengeId))
  queueMicrotask(() => {
    child.postMessage({ type: 'h3c-handoff-opened', challengeId: request.challengeId })
    child.close()
  })
  return null
}

const createAutoBridge = (overrides = {}) => {
  MockBroadcastChannel.reset()
  const openedUrls = []
  const trace = []
  const bridge = createH3CBridge({
    BroadcastChannelImplementation: MockBroadcastChannel,
    openWindow: autoHandshakeOpen(openedUrls),
    cryptoImplementation: deterministicCrypto,
    nowSeconds: () => NOW,
    handoffTimeoutMs: 100,
    addTraceEvent: (message) => trace.push(message),
    ...overrides
  })
  return { bridge, openedUrls, trace }
}

const sendCallback = async (bridge, message) => {
  const client = new MockBroadcastChannel(h3cChannelName(message.challengeId))
  const acknowledgements = []
  client.onmessage = (event) => {
    if (event.data?.type === 'h3c-ack') acknowledgements.push(event.data)
  }
  client.postMessage(message)
  await waitFor(() => ['verified', 'rejected', 'failed'].includes(bridge.getSnapshot().state))
  await new Promise((resolve) => setTimeout(resolve, 1))
  return { client, acknowledgements }
}

test('32-byte challenge generation is canonical unpadded Base64URL', async () => {
  const created = await createH3BRequest({ paymentRequired: PAYMENT_REQUIRED, nowSeconds: NOW, cryptoImplementation: deterministicCrypto })
  assert.equal(created.request.challengeId, CHALLENGE)
  assert.equal(created.request.challengeId.length, 43)
  assert.equal(decodeCanonicalBase64Url(created.request.challengeId).byteLength, 32)
})

test('H3B request has exact root keys and a 240-second lifetime', async () => {
  const created = await createH3BRequest({ paymentRequired: PAYMENT_REQUIRED, nowSeconds: NOW, cryptoImplementation: deterministicCrypto })
  assert.deepEqual(Object.keys(created.request).sort(), [
    'approval', 'challengeId', 'expiresAt', 'issuedAt', 'paymentRequired', 'returnUrl',
    'sourceOrigin', 'targetGate', 'type', 'version'
  ])
  assert.equal(created.request.issuedAt, NOW)
  assert.equal(created.request.expiresAt, NOW + 240)
})

test('H3B request carries the exact validated PaymentRequired object', async () => {
  const created = await createH3BRequest({ paymentRequired: PAYMENT_REQUIRED, nowSeconds: NOW, cryptoImplementation: deterministicCrypto })
  assert.equal(created.request.paymentRequired, PAYMENT_REQUIRED)
  assert.deepEqual(created.request.paymentRequired, PAYMENT_REQUIRED)
})

test('H3B request contains the exact approved H3A marker', async () => {
  const created = await createH3BRequest({ paymentRequired: PAYMENT_REQUIRED, nowSeconds: NOW, cryptoImplementation: deterministicCrypto })
  assert.deepEqual(created.request.approval, {
    status: 'payment_approved', gate: 'H3A', approved: true, performed: false
  })
})

test('H3B request canonical JSON and Base64URL round-trip exactly', async () => {
  const created = await createH3BRequest({ paymentRequired: PAYMENT_REQUIRED, nowSeconds: NOW, cryptoImplementation: deterministicCrypto })
  const parsed = parseH3BRequestTransport({ hash: `#request=${created.encodedRequest}`, search: '', nowSeconds: NOW })
  assert.equal(canonicalizeJson(parsed.request), created.canonicalRequest)
  assert.equal(encodeCanonicalBase64Url(parsed.request), created.encodedRequest)
})

test('PaymentRequired SHA-256 matches canonical Tonalli H3B fixture', async () => {
  assert.equal(await sha256CanonicalJson(PAYMENT_REQUIRED), PAYMENT_REQUIRED_SHA256)
})

test('Tonalli handoff URL is pinned to one HTTPS origin and hash transport', async () => {
  const created = await createH3BRequest({ paymentRequired: PAYMENT_REQUIRED, nowSeconds: NOW, cryptoImplementation: deterministicCrypto })
  assert.equal(tonalliH3BUrl(created.encodedRequest), `https://app.tonalli.cash/connect/x402-authorize#request=${created.encodedRequest}`)
})

test('PaymentRequired validation rejects unknown fields', () => {
  const changed = clone(PAYMENT_REQUIRED)
  changed.unknown = true
  assert.throws(() => validatePaymentRequired(changed))
})

test('valid signed callback is accepted', () => {
  const parsed = parseH3BCallback({ hash: `#h3bStatus=signed&challengeId=${CHALLENGE}&proof=e30`, search: '' })
  assert.deepEqual(parsed, { status: 'signed', challengeId: CHALLENGE, proof: 'e30' })
})

test('valid rejected callback is accepted', () => {
  const parsed = parseH3BCallback({ hash: `#h3bStatus=rejected&challengeId=${CHALLENGE}`, search: '' })
  assert.deepEqual(parsed, { status: 'rejected', challengeId: CHALLENGE })
})

for (const [name, hash, search = ''] of [
  ['query string callback', '', `?h3bStatus=rejected&challengeId=${CHALLENGE}`],
  ['missing hash', '', ''],
  ['unknown status', `#h3bStatus=paid&challengeId=${CHALLENGE}`, ''],
  ['duplicate fields', `#h3bStatus=rejected&challengeId=${CHALLENGE}&challengeId=${CHALLENGE}`, ''],
  ['unknown fields', `#h3bStatus=rejected&challengeId=${CHALLENGE}&extra=1`, ''],
  ['missing challenge', '#h3bStatus=rejected', ''],
  ['wrong challenge', '#h3bStatus=rejected&challengeId=c2hvcnQ', ''],
  ['empty proof', `#h3bStatus=signed&challengeId=${CHALLENGE}&proof=`, ''],
  ['invalid Base64URL', `#h3bStatus=signed&challengeId=${CHALLENGE}&proof=abc+`, ''],
  ['padded Base64URL', `#h3bStatus=signed&challengeId=${CHALLENGE}&proof=e30=`, '']
]) {
  test(`callback parser rejects ${name}`, () => {
    assert.throws(() => parseH3BCallback({ hash, search }))
  })
}

test('callback parser rejects oversized proof before decoding', () => {
  assert.throws(() => parseH3BCallback({
    hash: `#h3bStatus=signed&challengeId=${CHALLENGE}&proof=${'A'.repeat(H3B_MAX_PROOF_BASE64URL_LENGTH + 1)}`,
    search: ''
  }))
})

test('invalid callback can recover only one unambiguous canonical challenge', () => {
  assert.equal(recoverH3BCallbackChallenge({
    hash: `#h3bStatus=signed&challengeId=${CHALLENGE}&proof=e30&extra=1`,
    search: ''
  }), CHALLENGE)
  assert.equal(recoverH3BCallbackChallenge({
    hash: `#h3bStatus=rejected&challengeId=${CHALLENGE}&challengeId=${CHALLENGE}`,
    search: ''
  }), CHALLENGE)
  assert.equal(recoverH3BCallbackChallenge({
    hash: '',
    search: `?h3bStatus=rejected&challengeId=${CHALLENGE}`
  }), CHALLENGE)
  assert.throws(() => recoverH3BCallbackChallenge({
    hash: `#h3bStatus=rejected&challengeId=${CHALLENGE}`,
    search: `?challengeId=${encodeBase64UrlBytes(new Uint8Array(32).fill(1))}`
  }))
})

test('callback ACK lifetime matches the authorization TTL', () => {
  assert.equal(H3C_CALLBACK_ACK_TIMEOUT_MS, H3C_TTL_SECONDS * 1_000)
})

test('proof decoder rejects invalid UTF-8', () => {
  assert.throws(() => decodeCanonicalH3BProof(encodeBase64UrlBytes(Uint8Array.from([0xc3, 0x28]))))
})

test('proof decoder rejects invalid JSON', () => {
  assert.throws(() => decodeCanonicalH3BProof(encodeBase64UrlBytes(new TextEncoder().encode('{'))))
})

test('real canonical Tonalli message signature and public key verify', async () => {
  const verified = await verifySignedH3BProof({
    encodedProof: encodeCanonicalBase64Url(signedVectorProof),
    rendezvous: vectorRendezvous,
    nowSeconds: NOW
  })
  assert.equal(verified.publicKey, vector.publicKey)
  assert.equal(verified.payer, vector.payer)
  assert.equal(verified.paymentRequiredSha256, PAYMENT_REQUIRED_SHA256)
})

test('authorization message rebuild matches the exact vector bytes', () => {
  assert.equal(buildH3BAuthorizationMessage(unsignedVectorProof), vector.message)
})

test('fixture message hash independently matches Tonalli magicHash bytes', () => {
  const message = Buffer.from(vector.message, 'utf8')
  const payload = Buffer.concat([
    Buffer.from('\u0016eCash Signed Message:\n', 'utf8'),
    compactSize(message.length),
    message
  ])
  assert.equal(sha256(sha256(payload)).toString('hex'), vector.messageHashHex)
})

test('cryptographic verifier rejects a compact signature bit flip with a valid header', async () => {
  const changed = clone(signedVectorProof)
  const signatureBytes = Buffer.from(changed.authorizationSignature.signature, 'base64')
  signatureBytes[10] ^= 0x01
  changed.authorizationSignature.signature = signatureBytes.toString('base64')
  assert.ok(signatureBytes[0] >= 31 && signatureBytes[0] <= 34)
  await expectFailure(() => verifySignedH3BProof({
    encodedProof: encodeCanonicalBase64Url(changed),
    rendezvous: vectorRendezvous,
    nowSeconds: NOW
  }), /H3C proof verification failed/u)
})

test('cryptographic verifier rejects a coherent public-key substitution', async () => {
  const changed = clone(signedVectorProof)
  changed.publicKey = `02${'11'.repeat(32)}`
  changed.authorizationSignature.publicKey = changed.publicKey
  const { authorizationMessage: _message, authorizationSignature: _signature, ...unsigned } = changed
  changed.authorizationMessage = buildH3BAuthorizationMessage(unsigned)
  await expectFailure(() => verifySignedH3BProof({
    encodedProof: encodeCanonicalBase64Url(changed),
    rendezvous: vectorRendezvous,
    nowSeconds: NOW
  }), /H3C proof verification failed/u)
})

const proofMutations = [
  ['type', (proof) => { proof.type = 'wrong' }],
  ['version', (proof) => { proof.version = 2 }],
  ['gate', (proof) => { proof.gate = 'H3C' }],
  ['mode', (proof) => { proof.mode = 'payment' }],
  ['challengeId', (proof) => { proof.challengeId = 'AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE' }],
  ['sourceOrigin', (proof) => { proof.sourceOrigin = 'https://example.com' }],
  ['resourceUrl', (proof) => { proof.resourceUrl = 'https://example.com/resource' }],
  ['paymentRequiredSha256', (proof) => { proof.paymentRequiredSha256 = '0'.repeat(64) }],
  ['x402Version', (proof) => { proof.x402Version = 1 }],
  ['scheme', (proof) => { proof.scheme = 'wrong' }],
  ['network', (proof) => { proof.network = 'xec:testnet' }],
  ['asset', (proof) => { proof.asset = 'BCH' }],
  ['amount', (proof) => { proof.amount = '10001' }],
  ['displayAmount', (proof) => { proof.displayAmount = '101 XEC' }],
  ['payTo', (proof) => { proof.payTo = vector.payer }],
  ['payer', (proof) => { proof.payer = PAYMENT_REQUIRED.accepts[0].payTo }],
  ['publicKey', (proof) => { proof.publicKey = `02${'11'.repeat(32)}` }],
  ['issuedAt', (proof) => { proof.issuedAt += 1 }],
  ['expiresAt', (proof) => { proof.expiresAt += 1 }],
  ['paymentPerformed', (proof) => { proof.paymentPerformed = true }],
  ['transactionCreated', (proof) => { proof.transactionCreated = true }],
  ['broadcasted', (proof) => { proof.broadcasted = true }],
  ['authorizationMessage', (proof) => { proof.authorizationMessage += ' ' }],
  ['authorizationSignature.type', (proof) => { proof.authorizationSignature.type = 'wrong' }],
  ['authorizationSignature.publicKey', (proof) => { proof.authorizationSignature.publicKey = `02${'22'.repeat(32)}` }],
  ['authorizationSignature.signature', (proof) => { proof.authorizationSignature.signature = `H${proof.authorizationSignature.signature.slice(1)}` }]
]

for (const [field, mutate] of proofMutations) {
  test(`proof binding rejects mutation of ${field}`, async () => {
    const changed = clone(signedVectorProof)
    mutate(changed)
    await expectFailure(() => verifySignedH3BProof({
      encodedProof: encodeCanonicalBase64Url(changed),
      rendezvous: vectorRendezvous,
      nowSeconds: NOW
    }), /H3C proof verification failed/u)
  })
}

test('proof schema rejects unknown root field', async () => {
  const changed = { ...clone(signedVectorProof), unexpected: true }
  await expectFailure(() => verifySignedH3BProof({ encodedProof: encodeCanonicalBase64Url(changed), rendezvous: vectorRendezvous, nowSeconds: NOW }))
})

test('proof schema rejects unknown signature field', async () => {
  const changed = clone(signedVectorProof)
  changed.authorizationSignature.unexpected = true
  await expectFailure(() => verifySignedH3BProof({ encodedProof: encodeCanonicalBase64Url(changed), rendezvous: vectorRendezvous, nowSeconds: NOW }))
})

test('bridge opens the same-origin handoff only after creating a live rendezvous', async () => {
  const { bridge, openedUrls } = createAutoBridge()
  const result = await bridge.startHandoff({ paymentRequired: PAYMENT_REQUIRED })
  assert.equal(result.status, 'authorization_pending')
  assert.equal(result.payment.performed, false)
  assert.equal(result.transaction.created, false)
  assert.equal(result.transaction.broadcasted, false)
  assert.equal(openedUrls.length, 1)
  assert.ok(openedUrls[0].startsWith(`${H3C_HANDOFF_PATH}#request=`))
  bridge.dispose()
})

test('handoff window opens synchronously within the startHandoff call', async () => {
  MockBroadcastChannel.reset()
  let startReturned = false
  let openedSynchronously = false
  let child
  const bridge = createH3CBridge({
    BroadcastChannelImplementation: MockBroadcastChannel,
    openWindow: (url) => {
      openedSynchronously = !startReturned
      const request = parseH3BRequestTransport({
        hash: new URL(url, 'https://x402.ecash.mx').hash,
        search: '',
        nowSeconds: NOW
      }).request
      child = new MockBroadcastChannel(h3cChannelName(request.challengeId))
      queueMicrotask(() => child.postMessage({
        type: 'h3c-handoff-opened',
        challengeId: request.challengeId
      }))
      return null
    },
    cryptoImplementation: deterministicCrypto,
    nowSeconds: () => NOW,
    handoffTimeoutMs: 100
  })
  const handoff = bridge.startHandoff({ paymentRequired: PAYMENT_REQUIRED })
  startReturned = true
  assert.equal(openedSynchronously, true)
  await handoff
  child.close()
  bridge.dispose()
})

test('noopener-style null window handle is accepted only with a valid handoff ACK', async () => {
  const { bridge } = createAutoBridge()
  await assert.doesNotReject(bridge.startHandoff({ paymentRequired: PAYMENT_REQUIRED }))
  assert.equal(bridge.getSnapshot().state, 'awaiting-tonalli')
  bridge.dispose()
})

test('result tool view is pending while Tonalli has not returned', async () => {
  const { bridge } = createAutoBridge()
  await bridge.startHandoff({ paymentRequired: PAYMENT_REQUIRED })
  assert.deepEqual(bridge.readResult(), {
    status: 'authorization_pending', gate: 'H3C', challengeId: CHALLENGE,
    authorization: { signed: false, verified: false, pending: true },
    payment: { performed: false }
  })
  bridge.dispose()
})

test('duplicate concurrent handoff fails closed', async () => {
  MockBroadcastChannel.reset()
  let handoffChild
  const bridge = createH3CBridge({
    BroadcastChannelImplementation: MockBroadcastChannel,
    openWindow: (url) => {
      const request = parseH3BRequestTransport({ hash: new URL(url, 'https://x402.ecash.mx').hash, search: '', nowSeconds: NOW }).request
      handoffChild = new MockBroadcastChannel(h3cChannelName(request.challengeId))
      return null
    },
    cryptoImplementation: deterministicCrypto,
    nowSeconds: () => NOW,
    handoffTimeoutMs: 100
  })
  const first = bridge.startHandoff({ paymentRequired: PAYMENT_REQUIRED })
  await waitFor(() => Boolean(handoffChild))
  await expectFailure(() => bridge.startHandoff({ paymentRequired: PAYMENT_REQUIRED }), /already pending/u)
  handoffChild.postMessage({ type: 'h3c-handoff-opened', challengeId: CHALLENGE })
  await first
  handoffChild.close()
  bridge.dispose()
})

test('missing handoff ACK fails closed', async () => {
  MockBroadcastChannel.reset()
  const bridge = createH3CBridge({
    BroadcastChannelImplementation: MockBroadcastChannel,
    openWindow: () => null,
    cryptoImplementation: deterministicCrypto,
    nowSeconds: () => NOW,
    handoffTimeoutMs: 5
  })
  await expectFailure(() => bridge.startHandoff({ paymentRequired: PAYMENT_REQUIRED }), /did not acknowledge/u)
  assert.equal(bridge.getSnapshot().state, 'failed')
  bridge.dispose()
})

test('popup exception fails closed', async () => {
  MockBroadcastChannel.reset()
  const bridge = createH3CBridge({
    BroadcastChannelImplementation: MockBroadcastChannel,
    openWindow: () => { throw new Error('blocked') },
    cryptoImplementation: deterministicCrypto,
    nowSeconds: () => NOW,
    handoffTimeoutMs: 100
  })
  await expectFailure(() => bridge.startHandoff({ paymentRequired: PAYMENT_REQUIRED }), /could not open/u)
  assert.equal(bridge.getSnapshot().state, 'failed')
  bridge.dispose()
})

test('BroadcastChannel support is mandatory', async () => {
  const bridge = createH3CBridge({
    BroadcastChannelImplementation: null,
    cryptoImplementation: deterministicCrypto,
    nowSeconds: () => NOW
  })
  await expectFailure(() => bridge.startHandoff({ paymentRequired: PAYMENT_REQUIRED }), /BroadcastChannel is unavailable/u)
})

test('AbortSignal during handoff fails closed without becoming approve or reject', async () => {
  MockBroadcastChannel.reset()
  const controller = new AbortController()
  const bridge = createH3CBridge({
    BroadcastChannelImplementation: MockBroadcastChannel,
    openWindow: () => {
      queueMicrotask(() => controller.abort())
      return null
    },
    cryptoImplementation: deterministicCrypto,
    nowSeconds: () => NOW,
    handoffTimeoutMs: 100
  })
  await expectFailure(() => bridge.startHandoff({ paymentRequired: PAYMENT_REQUIRED, signal: controller.signal }), /aborted/u)
  assert.equal(bridge.getSnapshot().state, 'failed')
  bridge.dispose()
})

test('rendezvous expires in memory and accepts no later callback', async () => {
  MockBroadcastChannel.reset()
  const scheduler = createManualScheduler()
  const openedUrls = []
  const trace = []
  let now = NOW
  const bridge = createH3CBridge({
    BroadcastChannelImplementation: MockBroadcastChannel,
    openWindow: autoHandshakeOpen(openedUrls),
    cryptoImplementation: deterministicCrypto,
    nowSeconds: () => now,
    setTimeoutImplementation: scheduler.set,
    clearTimeoutImplementation: scheduler.clear,
    handoffTimeoutMs: 100,
    addTraceEvent: (message) => trace.push(message)
  })
  await bridge.startHandoff({ paymentRequired: PAYMENT_REQUIRED })
  now = NOW + H3C_TTL_SECONDS
  scheduler.runDelay(H3C_TTL_SECONDS * 1_000)
  assert.equal(bridge.getSnapshot().state, 'expired')
  assert.ok(trace.includes('H3C authorization request expired'))
  assert.throws(() => bridge.readResult(), /expired/u)
  bridge.dispose()
})

test('result reads lazily expire a throttled live rendezvous', async () => {
  let now = NOW
  const { bridge } = createAutoBridge({ nowSeconds: () => now })
  await bridge.startHandoff({ paymentRequired: PAYMENT_REQUIRED })
  now = NOW + H3C_TTL_SECONDS
  assert.throws(() => bridge.readResult(), /expired/u)
  assert.equal(bridge.getSnapshot().state, 'expired')
  bridge.dispose()
})

test('live-state checks release a throttled expired rendezvous', async () => {
  let now = NOW
  const { bridge } = createAutoBridge({ nowSeconds: () => now })
  await bridge.startHandoff({ paymentRequired: PAYMENT_REQUIRED })
  now = NOW + H3C_TTL_SECONDS
  assert.equal(bridge.hasLiveRendezvous(), false)
  assert.equal(bridge.getSnapshot().state, 'expired')
  bridge.dispose()
})

test('handoff finishing after deadline never receives parent acceptance', async () => {
  MockBroadcastChannel.reset()
  let now = NOW
  const childMessages = []
  let child
  const bridge = createH3CBridge({
    BroadcastChannelImplementation: MockBroadcastChannel,
    openWindow: (url) => {
      const request = parseH3BRequestTransport({
        hash: new URL(url, 'https://x402.ecash.mx').hash,
        search: '',
        nowSeconds: NOW
      }).request
      child = new MockBroadcastChannel(h3cChannelName(request.challengeId))
      child.onmessage = (event) => childMessages.push(event.data)
      now = NOW + H3C_TTL_SECONDS
      queueMicrotask(() => child.postMessage({
        type: 'h3c-handoff-opened',
        challengeId: request.challengeId
      }))
      return null
    },
    cryptoImplementation: deterministicCrypto,
    nowSeconds: () => now,
    handoffTimeoutMs: 100
  })
  await expectFailure(
    () => bridge.startHandoff({ paymentRequired: PAYMENT_REQUIRED }),
    /expired before handoff acknowledgement/u
  )
  await new Promise((resolve) => setTimeout(resolve, 1))
  assert.equal(bridge.getSnapshot().state, 'expired')
  assert.equal(childMessages.some((message) => message.type === 'h3c-handoff-accepted'), false)
  child.close()
  bridge.dispose()
})

test('callback after deadline expires even when the timer was throttled', async () => {
  let now = NOW
  const { bridge } = createAutoBridge({ nowSeconds: () => now })
  await bridge.startHandoff({ paymentRequired: PAYMENT_REQUIRED })
  now = NOW + H3C_TTL_SECONDS
  const client = new MockBroadcastChannel(h3cChannelName(CHALLENGE))
  const acknowledgements = []
  client.onmessage = (event) => acknowledgements.push(event.data)
  client.postMessage({ type: 'h3c-callback', challengeId: CHALLENGE, status: 'rejected' })
  await waitFor(() => bridge.getSnapshot().state === 'expired')
  await new Promise((resolve) => setTimeout(resolve, 1))
  assert.deepEqual(acknowledgements[0], {
    type: 'h3c-ack', challengeId: CHALLENGE, accepted: false, verified: false
  })
  assert.throws(() => bridge.readResult(), /expired/u)
  client.close()
  bridge.dispose()
})

test('proof finishing after deadline cannot become verified when the timer was throttled', async () => {
  let now = NOW
  let finishVerification
  const verification = new Promise((resolve) => { finishVerification = resolve })
  const { bridge } = createAutoBridge({
    nowSeconds: () => now,
    verifyProof: () => verification
  })
  await bridge.startHandoff({ paymentRequired: PAYMENT_REQUIRED })
  const client = new MockBroadcastChannel(h3cChannelName(CHALLENGE))
  const acknowledgements = []
  client.onmessage = (event) => acknowledgements.push(event.data)
  client.postMessage({ type: 'h3c-callback', challengeId: CHALLENGE, status: 'signed', proof: 'e30' })
  await waitFor(() => bridge.getSnapshot().state === 'proof-verifying')
  now = NOW + H3C_TTL_SECONDS
  finishVerification({
    payer: vector.payer,
    publicKey: vector.publicKey,
    paymentRequiredSha256: PAYMENT_REQUIRED_SHA256
  })
  await waitFor(() => bridge.getSnapshot().state === 'expired')
  await new Promise((resolve) => setTimeout(resolve, 1))
  assert.deepEqual(acknowledgements[0], {
    type: 'h3c-ack', challengeId: CHALLENGE, accepted: false, verified: false
  })
  assert.throws(() => bridge.readResult(), /expired/u)
  client.close()
  bridge.dispose()
})

test('rejected callback returns authorization_rejected and performed false', async () => {
  const { bridge } = createAutoBridge()
  await bridge.startHandoff({ paymentRequired: PAYMENT_REQUIRED })
  const { acknowledgements } = await sendCallback(bridge, { type: 'h3c-callback', challengeId: CHALLENGE, status: 'rejected' })
  assert.deepEqual(bridge.readResult(), {
    status: 'authorization_rejected', gate: 'H3C', challengeId: CHALLENGE,
    authorization: { signed: false, verified: false },
    payment: { performed: false },
    transaction: { created: false, broadcasted: false }
  })
  assert.deepEqual(acknowledgements[0], { type: 'h3c-ack', challengeId: CHALLENGE, accepted: true, verified: false })
  bridge.dispose()
})

test('signed callback returns authorization_verified only after real crypto verification', async () => {
  const { bridge, trace } = createAutoBridge()
  await bridge.startHandoff({ paymentRequired: PAYMENT_REQUIRED })
  const { acknowledgements } = await sendCallback(bridge, {
    type: 'h3c-callback', challengeId: CHALLENGE, status: 'signed', proof: encodeCanonicalBase64Url(signedVectorProof)
  })
  const result = bridge.readResult()
  assert.equal(result.status, 'authorization_verified')
  assert.equal(result.authorization.signed, true)
  assert.equal(result.authorization.verified, true)
  assert.equal(result.authorization.payer, vector.payer)
  assert.equal(result.payment.performed, false)
  assert.equal(result.transaction.created, false)
  assert.equal(result.transaction.broadcasted, false)
  assert.equal(result.resource.unlocked, false)
  assert.deepEqual(acknowledgements[0], { type: 'h3c-ack', challengeId: CHALLENGE, accepted: true, verified: true })
  assert.ok(trace.includes('Tonalli Authorization Proof cryptographically verified'))
  bridge.dispose()
})

test('invalid signed callback is ACKed accepted false and exposes no result', async () => {
  const { bridge } = createAutoBridge()
  await bridge.startHandoff({ paymentRequired: PAYMENT_REQUIRED })
  const changed = clone(signedVectorProof)
  changed.amount = '10001'
  const { acknowledgements } = await sendCallback(bridge, {
    type: 'h3c-callback', challengeId: CHALLENGE, status: 'signed', proof: encodeCanonicalBase64Url(changed)
  })
  assert.equal(bridge.getSnapshot().state, 'failed')
  assert.deepEqual(acknowledgements[0], { type: 'h3c-ack', challengeId: CHALLENGE, accepted: false, verified: false })
  assert.throws(() => bridge.readResult(), /failed closed/u)
  bridge.dispose()
})

test('double callback settles once and stale decision cannot change the result', async () => {
  const { bridge } = createAutoBridge()
  await bridge.startHandoff({ paymentRequired: PAYMENT_REQUIRED })
  const client = new MockBroadcastChannel(h3cChannelName(CHALLENGE))
  const acknowledgements = []
  client.onmessage = (event) => acknowledgements.push(event.data)
  const message = { type: 'h3c-callback', challengeId: CHALLENGE, status: 'rejected' }
  client.postMessage(message)
  client.postMessage(message)
  await waitFor(() => bridge.getSnapshot().state === 'rejected')
  await new Promise((resolve) => setTimeout(resolve, 1))
  assert.equal(bridge.readResult().status, 'authorization_rejected')
  assert.equal(bridge.getSnapshot().callbackConsumed, true)
  assert.ok(acknowledgements.some((ack) => ack.accepted === true))
  assert.ok(acknowledgements.some((ack) => ack.accepted === false))
  client.close()
  bridge.dispose()
})

test('valid but wrong callback challenge is ignored', async () => {
  const { bridge } = createAutoBridge()
  await bridge.startHandoff({ paymentRequired: PAYMENT_REQUIRED })
  const client = new MockBroadcastChannel(h3cChannelName(CHALLENGE))
  const wrongChallenge = encodeBase64UrlBytes(new Uint8Array(32).fill(1))
  const acknowledgements = []
  client.onmessage = (event) => acknowledgements.push(event.data)
  client.postMessage({ type: 'h3c-callback', challengeId: wrongChallenge, status: 'rejected' })
  await new Promise((resolve) => setTimeout(resolve, 5))
  assert.equal(bridge.getSnapshot().state, 'awaiting-tonalli')
  assert.deepEqual(acknowledgements, [])
  client.close()
  bridge.dispose()
})

test('page reload semantics provide no rendezvous to a fresh bridge', () => {
  const fresh = createH3CBridge({ BroadcastChannelImplementation: MockBroadcastChannel })
  assert.throws(() => fresh.readResult(), /No ephemeral H3C authorization session/u)
})

test('malformed callback fails closed before proof verification', async () => {
  let verificationCalls = 0
  const { bridge } = createAutoBridge({
    verifyProof: async () => {
      verificationCalls += 1
      throw new Error('must not run')
    }
  })
  await bridge.startHandoff({ paymentRequired: PAYMENT_REQUIRED })
  const client = new MockBroadcastChannel(h3cChannelName(CHALLENGE))
  const acknowledgements = []
  client.onmessage = (event) => acknowledgements.push(event.data)
  client.postMessage({ type: 'h3c-callback', challengeId: CHALLENGE, status: 'signed', proof: 'e30', extra: true })
  await waitFor(() => bridge.getSnapshot().state === 'failed')
  await new Promise((resolve) => setTimeout(resolve, 1))
  assert.equal(verificationCalls, 0)
  assert.equal(bridge.getSnapshot().callbackConsumed, true)
  assert.deepEqual(acknowledgements[0], {
    type: 'h3c-ack', challengeId: CHALLENGE, accepted: false, verified: false
  })
  assert.throws(() => bridge.readResult(), /failed closed/u)
  client.close()
  bridge.dispose()
})

test('production H3C runtime has one protected-resource fetch and no retry', async () => {
  const source = await readFile(`${WEBMCP_ROOT}webmcp.js`, 'utf8')
  assert.equal((source.match(/\bfetch\s*\(/gu) ?? []).length, 1)
  assert.equal(source.includes('retry'), false)
})

test('H3A reject returns before any Tonalli handoff', async () => {
  const source = await readFile(`${WEBMCP_ROOT}webmcp.js`, 'utf8')
  const rejectHandler = source.slice(
    source.indexOf('function handleReject'),
    source.indexOf('function handleApprove')
  )
  assert.ok(rejectHandler.includes("settle('resolve', 'rejected')"))
  assert.equal(rejectHandler.includes('beginApprovedHandoff'), false)
  assert.equal(rejectHandler.includes('h3cBridge.startHandoff'), false)
  assert.ok(source.includes("status: 'payment_rejected'"))
  assert.ok(source.includes('approved: false'))
})

test('Approve click starts handoff before its approval promise settles', async () => {
  const source = await readFile(`${WEBMCP_ROOT}webmcp.js`, 'utf8')
  const handler = source.slice(
    source.indexOf('function handleApprove'),
    source.indexOf('function handleAbort')
  )
  assert.ok(handler.indexOf('beginApprovedHandoff()') < handler.indexOf("settle('resolve', 'approved')"))
  assert.ok(source.includes('handoff did not start from the approval gesture'))
})

test('malformed PaymentRequired validation precedes approval UI rendering', async () => {
  const source = await readFile(`${WEBMCP_ROOT}webmcp.js`, 'utf8')
  assert.ok(
    source.indexOf('const acceptance = validatePaymentRequired(paymentRequired)') <
    source.indexOf('const decision = await requestHumanApproval')
  )
})

test('H3C first-tool result is authorization_pending, never final payment_approved', async () => {
  const source = await readFile(`${WEBMCP_ROOT}h3c-bridge.js`, 'utf8')
  assert.ok(source.includes("status: 'authorization_pending'"))
  assert.equal(source.includes("status: 'payment_approved'"), false)
})

test('H3A approval controls retain single-settle, stale-binding and abort guards', async () => {
  const source = await readFile(`${WEBMCP_ROOT}webmcp.js`, 'utf8')
  assert.ok(source.includes('if (settled) return'))
  assert.ok(source.includes('pendingApproval.requirement !== paymentRequired'))
  assert.ok(source.includes("signal?.addEventListener('abort'"))
  assert.ok(source.includes('ui.rejectButton.disabled = true'))
  assert.ok(source.includes('ui.approveButton.disabled = true'))
})

test('only the result tool retains readOnlyHint', async () => {
  const source = await readFile(`${WEBMCP_ROOT}webmcp.js`, 'utf8')
  assert.equal((source.match(/readOnlyHint/gu) ?? []).length, 1)
  assert.ok(source.indexOf('readOnlyHint') > source.indexOf('name: RESULT_TOOL_NAME'))
})

test('callback bootstrap clears URL data before loading the verifier graph', async () => {
  const bootstrap = await readFile(`${WEBMCP_ROOT}webmcp-bootstrap.js`, 'utf8')
  const page = await readFile(`${WEBMCP_ROOT}index.html`, 'utf8')
  assert.equal(/^\s*import\s/mu.test(bootstrap), false)
  assert.ok(bootstrap.indexOf('history.replaceState') < bootstrap.indexOf("import('./webmcp.js')"))
  assert.ok(bootstrap.includes("location.hash !== '' || location.search !== ''"))
  assert.ok(bootstrap.includes('No result was processed.'))
  assert.ok(page.includes('src="./webmcp-bootstrap.js"'))
  assert.equal(page.includes('src="./webmcp.js"'), false)
})

test('same-origin handoff requires parent acceptance before Tonalli navigation', async () => {
  const handoff = await readFile(`${WEBMCP_ROOT}h3c-handoff.js`, 'utf8')
  const bridge = await readFile(`${WEBMCP_ROOT}h3c-bridge.js`, 'utf8')
  assert.ok(handoff.includes("message.type === 'h3c-handoff-accepted'"))
  assert.ok(handoff.indexOf('isAcceptedHandoff') < handoff.indexOf('location.replace'))
  assert.ok(handoff.includes('No active x402eCash H3C session accepted this handoff'))
  assert.ok(bridge.includes("type: 'h3c-handoff-accepted'"))
})

test('H3C runtime contains no persistent browser storage', async () => {
  const files = ['h3c-contract.js', 'h3c-bridge.js', 'h3c-verify.js', 'h3c-handoff.js', 'webmcp-bootstrap.js', 'webmcp.js']
  const source = (await Promise.all(files.map((file) => readFile(`${WEBMCP_ROOT}${file}`, 'utf8')))).join('\n')
  for (const forbidden of ['localStorage', 'sessionStorage', 'indexedDB', 'document.cookie']) {
    assert.equal(source.includes(forbidden), false, forbidden)
  }
})

test('H3C verification modules perform no network call', async () => {
  const files = ['h3c-contract.js', 'h3c-bridge.js', 'h3c-verify.js', 'h3c-handoff.js']
  const source = (await Promise.all(files.map((file) => readFile(`${WEBMCP_ROOT}${file}`, 'utf8')))).join('\n')
  assert.equal(/\bfetch\s*\(/u.test(source), false)
  assert.equal(source.includes('XMLHttpRequest'), false)
})

test('vendored verifier exposes no network loader or JavaScript signing wrapper', async () => {
  const source = await readFile(`${WEBMCP_ROOT}vendor/ecash-lib-4.5.2-verifier.js`, 'utf8')
  for (const forbidden of [
    'fetch(', 'XMLHttpRequest', 'signMsg', 'signRecoverable', 'ecdsaSign',
    'schnorrSign', 'privateKey', 'seckey', 'mnemonic'
  ]) {
    assert.equal(source.includes(forbidden), false, forbidden)
  }
  assert.ok(source.includes('recoverEcashMessagePublicKey'))
  assert.ok(source.includes('deriveEcashP2pkhAddress'))
  assert.ok(source.includes('decodeEcashAddress'))
})

test('vendored verifier public module surface is verification-only', async () => {
  const verifier = await import(new URL('../vendor/ecash-lib-4.5.2-verifier.js', HERE))
  assert.deepEqual(Object.keys(verifier).sort(), [
    'decodeEcashAddress',
    'deriveEcashP2pkhAddress',
    'recoverEcashMessagePublicKey'
  ])
})

test('H3C constructs no payment signature header or protected-resource retry', async () => {
  const webmcp = await readFile(`${WEBMCP_ROOT}webmcp.js`, 'utf8')
  const bridge = await readFile(`${WEBMCP_ROOT}h3c-bridge.js`, 'utf8')
  assert.equal(webmcp.includes("'PAYMENT-SIGNATURE':"), false)
  assert.equal(webmcp.includes('setRequestHeader'), false)
  assert.equal(bridge.includes('fetch('), false)
})

test('WebMCP uses document.modelContext and never navigator.modelContext', async () => {
  const source = await readFile(`${WEBMCP_ROOT}webmcp.js`, 'utf8')
  assert.ok(source.includes('document.modelContext.registerTool'))
  assert.equal(source.includes('navigator.modelContext'), false)
})

let passed = 0
for (const { name, run } of tests) {
  try {
    await run()
    passed += 1
    process.stdout.write(`ok ${passed} - ${name}\n`)
  } catch (error) {
    process.stderr.write(`not ok ${passed + 1} - ${name}\n`)
    throw error
  } finally {
    MockBroadcastChannel.reset()
  }
}

process.stdout.write(`H3C deterministic harness: ${passed}/${tests.length} PASS\n`)
