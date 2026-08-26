import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import {
  H3B_MAX_PROOF_BASE64URL_LENGTH,
  H3C_CALLBACK_ACK_TIMEOUT_MS,
  H3C_HANDOFF_ANNOUNCEMENT_INTERVAL_MS,
  H3C_HANDOFF_PATH,
  H3C_HANDOFF_TIMEOUT_MS,
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
import { runHandoff } from '../h3c-handoff.js'
import { buildH3BAuthorizationMessage, verifySignedH3BProof } from '../h3c-verify.js'
import { createResourceToolExecutor } from '../webmcp.js'

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

const FIRST_APPROVAL_REQUIRED = Object.freeze({
  status: 'approval_required',
  gate: 'H3A',
  httpStatus: 402,
  message: 'The live 100 XEC requirement was validated and is awaiting a human decision. No payment was performed.',
  approval: Object.freeze({ required: true, decided: false, required_amount: '100 XEC' }),
  payment: Object.freeze({ performed: false })
})

const RESULT_APPROVAL_REQUIRED = Object.freeze({
  status: 'approval_required',
  gate: 'H3A',
  approval: Object.freeze({ required: true, decided: false, required_amount: '100 XEC' }),
  payment: Object.freeze({ performed: false })
})

const HUMAN_REJECTED = Object.freeze({
  status: 'authorization_rejected',
  gate: 'H3A',
  authorization: Object.freeze({ signed: false, verified: false }),
  payment: Object.freeze({ performed: false }),
  transaction: Object.freeze({ created: false, broadcasted: false })
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
  const add = (callback, delay, repeat) => {
    const id = nextId
    nextId += 1
    tasks.set(id, { callback, delay, repeat, cleared: false })
    return id
  }
  return {
    set (callback, delay) {
      return add(callback, delay, false)
    },
    setInterval (callback, delay) {
      return add(callback, delay, true)
    },
    clear (id) {
      const task = tasks.get(id)
      if (task) task.cleared = true
    },
    runDelay (delay) {
      for (const [id, task] of [...tasks]) {
        if (task.cleared || task.delay !== delay) continue
        if (!task.repeat) task.cleared = true
        tasks.set(id, task)
        task.callback()
      }
    },
    pending () {
      return [...tasks.values()].filter((task) => !task.cleared).length
    }
  }
}

const flushMicrotasks = async () => {
  await Promise.resolve()
  await Promise.resolve()
}

const createHandoffChildHarness = ({
  nowMilliseconds = () => NOW * 1_000,
  onOpened = () => {}
} = {}) => {
  MockBroadcastChannel.reset()
  const scheduler = createManualScheduler()
  const created = createH3BRequest({
    paymentRequired: PAYMENT_REQUIRED,
    nowSeconds: NOW,
    cryptoImplementation: deterministicCrypto
  })
  const status = { textContent: '' }
  const detail = { textContent: '' }
  const location = {
    hash: `#request=${created.encodedRequest}`,
    search: '',
    pathname: H3C_HANDOFF_PATH,
    replaced: [],
    replace (url) {
      this.replaced.push(url)
    }
  }
  const history = {
    state: null,
    replaceState (_state, _title, path) {
      assert.equal(path, H3C_HANDOFF_PATH)
      location.hash = ''
      location.search = ''
    }
  }
  const document = {
    body: { dataset: {} },
    querySelector (selector) {
      if (selector === '[data-handoff-status]') return status
      if (selector === '[data-handoff-detail]') return detail
      return null
    }
  }
  const listeners = new Map()
  const window = {
    opener: {},
    addEventListener (type, handler) {
      listeners.set(type, handler)
    },
    removeEventListener (type, handler) {
      if (listeners.get(type) === handler) listeners.delete(type)
    }
  }
  const announcements = []
  const scrubbedBeforeAnnouncements = []
  const parent = new MockBroadcastChannel(h3cChannelName(created.request.challengeId))
  parent.onmessage = (event) => {
    if (event.data?.type !== 'h3c-handoff-opened') return
    announcements.push(event.data)
    scrubbedBeforeAnnouncements.push(location.hash === '' && location.search === '')
    onOpened({ message: event.data, parent, announcements })
  }
  const controller = runHandoff({
    documentImplementation: document,
    historyImplementation: history,
    locationImplementation: location,
    windowImplementation: window,
    BroadcastChannelImplementation: MockBroadcastChannel,
    nowMilliseconds,
    setTimeoutImplementation: scheduler.set,
    clearTimeoutImplementation: scheduler.clear,
    setIntervalImplementation: scheduler.setInterval,
    clearIntervalImplementation: scheduler.clear
  })

  return {
    announcements,
    controller,
    created,
    detail,
    dispatchPageHide: () => listeners.get('pagehide')?.(),
    document,
    location,
    parent,
    scheduler,
    scrubbedBeforeAnnouncements,
    status,
    window
  }
}

const autoHandshakeOpen = (openedUrls, nowSeconds = () => NOW) => (url) => {
  openedUrls.push(url)
  const hash = new URL(url, 'https://x402.ecash.mx').hash
  const request = parseH3BRequestTransport({ hash, search: '', nowSeconds: nowSeconds() }).request
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
  const nowSeconds = overrides.nowSeconds ?? (() => NOW)
  const bridge = createH3CBridge({
    BroadcastChannelImplementation: MockBroadcastChannel,
    openWindow: autoHandshakeOpen(openedUrls, nowSeconds),
    cryptoImplementation: deterministicCrypto,
    nowSeconds,
    handoffTimeoutMs: 100,
    addTraceEvent: (message) => trace.push(message),
    ...overrides
  })
  return { bridge, openedUrls, trace }
}

const createApproval = (bridge, paymentRequired = PAYMENT_REQUIRED) => (
  bridge.createApprovalSession({ paymentRequired })
)

const startApprovedHandoff = (bridge, paymentRequired = PAYMENT_REQUIRED) => {
  const approval = createApproval(bridge, paymentRequired)
  return bridge.startHandoff(approval.binding)
}

const encodePaymentRequiredHeader = (paymentRequired = PAYMENT_REQUIRED) => (
  Buffer.from(JSON.stringify(paymentRequired), 'utf8').toString('base64')
)

const paymentRequiredResponse = (paymentRequired = PAYMENT_REQUIRED) => ({
  status: 402,
  headers: {
    get (name) {
      return name.toUpperCase() === 'PAYMENT-REQUIRED'
        ? encodePaymentRequiredHeader(paymentRequired)
        : null
    }
  }
})

const deferred = () => {
  let resolve
  let reject
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise
    reject = rejectPromise
  })
  return { promise, resolve, reject }
}

const createResourceHarness = ({ bridgeOverrides = {}, fetchImplementation } = {}) => {
  const { bridge, openedUrls, trace } = createAutoBridge(bridgeOverrides)
  const rendered = []
  const fetches = []
  const execute = createResourceToolExecutor({
    bridge,
    fetchImplementation: async (url, options) => {
      fetches.push({ url, options })
      return fetchImplementation
        ? fetchImplementation(url, options)
        : paymentRequiredResponse()
    },
    renderApproval: (renderedApproval) => {
      const mounted = { ...renderedApproval, cleaned: false }
      rendered.push(mounted)
      return {
        cleanup () { mounted.cleaned = true }
      }
    },
    traceEvent: (message) => trace.push(message)
  })
  return { bridge, execute, fetches, openedUrls, rendered, trace }
}

class FakeUiNode {
  constructor () {
    this.dataset = {}
    this.hidden = false
    this.textContent = ''
    this.disabled = false
    this.attributes = new Map()
  }

  setAttribute (name, value) {
    this.attributes.set(name, String(value))
  }
}

class FakeUiButton extends FakeUiNode {
  constructor () {
    super()
    this.listeners = new Set()
  }

  addEventListener (type, listener) {
    if (type === 'click') this.listeners.add(listener)
  }

  removeEventListener (type, listener) {
    if (type === 'click') this.listeners.delete(listener)
  }

  click () {
    if (this.disabled) return false
    for (const listener of [...this.listeners]) listener({ type: 'click', currentTarget: this })
    return true
  }
}

const createProductionUiEnvironment = () => {
  const registeredTools = new Map()
  const cards = []
  const trace = []
  const openedUrls = []
  const fetches = []
  const approvalRegion = new FakeUiNode()
  approvalRegion.hidden = true
  const approvalMount = new FakeUiNode()
  approvalMount.children = []
  approvalMount.replaceChildren = (...children) => { approvalMount.children = children }
  const rendezvousRegion = new FakeUiNode()
  const rendezvousState = new FakeUiNode()
  const rendezvousChallenge = new FakeUiNode()
  const rendezvousExpiry = new FakeUiNode()
  const traceLog = new FakeUiNode()
  traceLog.querySelector = () => null
  traceLog.append = (item) => trace.push(item.textContent)

  const approvalTemplate = {
    content: {
      cloneNode () {
        const nodes = new Map([
          ['[data-approval-card]', new FakeUiNode()],
          ['[data-approval-amount]', new FakeUiNode()],
          ['[data-approval-network]', new FakeUiNode()],
          ['[data-approval-asset]', new FakeUiNode()],
          ['[data-approval-destination]', new FakeUiNode()],
          ['[data-approval-experimental]', new FakeUiNode()],
          ['[data-approval-reject]', new FakeUiButton()],
          ['[data-approval-approve]', new FakeUiButton()],
          ['[data-approval-status]', new FakeUiNode()]
        ])
        const fragment = { querySelector: (selector) => nodes.get(selector) ?? null }
        const card = {
          fragment,
          card: nodes.get('[data-approval-card]'),
          rejectButton: nodes.get('[data-approval-reject]'),
          approveButton: nodes.get('[data-approval-approve]'),
          status: nodes.get('[data-approval-status]')
        }
        card.card.focus = () => { card.card.focused = true }
        cards.push(card)
        return fragment
      }
    }
  }

  const selectors = new Map([
    ['[data-trace-log]', traceLog],
    ['[data-webmcp-state]', new FakeUiNode()],
    ['[data-webmcp-status]', new FakeUiNode()],
    ['[data-webmcp-detail]', new FakeUiNode()],
    ['[data-approval-region]', approvalRegion],
    ['[data-approval-mount]', approvalMount],
    ['[data-approval-template]', approvalTemplate],
    ['[data-rendezvous-region]', rendezvousRegion],
    ['[data-rendezvous-state]', rendezvousState],
    ['[data-rendezvous-challenge]', rendezvousChallenge],
    ['[data-rendezvous-expiry]', rendezvousExpiry]
  ])

  const document = {
    modelContext: {
      async registerTool (tool) { registeredTools.set(tool.name, tool) }
    },
    querySelector: (selector) => selectors.get(selector) ?? null,
    createElement: () => new FakeUiNode()
  }
  const fetchImplementation = async (url, options) => {
    fetches.push({ url, options })
    return paymentRequiredResponse()
  }
  const openWindow = autoHandshakeOpen(openedUrls, () => Math.floor(Date.now() / 1_000))

  return {
    document,
    fetchImplementation,
    openWindow,
    registeredTools,
    cards,
    trace,
    openedUrls,
    fetches,
    approvalMount
  }
}

const replaceGlobal = (name, value) => {
  const descriptor = Object.getOwnPropertyDescriptor(globalThis, name)
  Object.defineProperty(globalThis, name, { configurable: true, writable: true, value })
  return () => {
    if (descriptor) Object.defineProperty(globalThis, name, descriptor)
    else delete globalThis[name]
  }
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
  const result = await startApprovedHandoff(bridge)
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
  const handoff = startApprovedHandoff(bridge)
  startReturned = true
  assert.equal(openedSynchronously, true)
  await handoff
  child.close()
  bridge.dispose()
})

test('noopener-style null window handle is accepted only with a valid handoff ACK', async () => {
  const { bridge } = createAutoBridge()
  await assert.doesNotReject(startApprovedHandoff(bridge))
  assert.equal(bridge.getSnapshot().state, 'awaiting-tonalli')
  bridge.dispose()
})

test('result tool view is pending while Tonalli has not returned', async () => {
  const { bridge } = createAutoBridge()
  await startApprovedHandoff(bridge)
  assert.deepEqual(bridge.readResult(), {
    status: 'authorization_pending', gate: 'H3C', challengeId: CHALLENGE,
    authorization: { wallet: 'Tonalli', signed: false, verified: false, pending: true },
    payment: { performed: false },
    transaction: { created: false, broadcasted: false }
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
  const first = startApprovedHandoff(bridge)
  await waitFor(() => Boolean(handoffChild))
  await expectFailure(() => startApprovedHandoff(bridge), /already pending/u)
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
  await expectFailure(() => startApprovedHandoff(bridge), /did not acknowledge/u)
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
  await expectFailure(() => startApprovedHandoff(bridge), /could not open/u)
  assert.equal(bridge.getSnapshot().state, 'failed')
  bridge.dispose()
})

test('H3C-R2 A: child announces immediately after fragment cleanup and existing success is unchanged', async () => {
  assert.equal(H3C_HANDOFF_TIMEOUT_MS, 15_000)
  assert.equal(H3C_HANDOFF_ANNOUNCEMENT_INTERVAL_MS, 400)
  assert.equal(H3C_TTL_SECONDS, 240)
  const child = createHandoffChildHarness({
    onOpened: ({ message, parent }) => parent.postMessage({
      type: 'h3c-handoff-accepted',
      challengeId: message.challengeId
    })
  })
  await flushMicrotasks()
  assert.deepEqual(child.announcements, [{
    type: 'h3c-handoff-opened',
    challengeId: child.created.request.challengeId
  }])
  assert.deepEqual(child.scrubbedBeforeAnnouncements, [true])
  assert.deepEqual(child.location.replaced, [tonalliH3BUrl(child.created.encodedRequest)])
  assert.equal(child.window.opener, null)
  assert.equal(child.document.body.dataset.handoffState, 'opening')
  assert.equal(child.scheduler.pending(), 0)
  child.parent.close()
})

test('H3C-R2 B: child startup after eight seconds succeeds inside the new handshake window', async () => {
  MockBroadcastChannel.reset()
  const scheduler = createManualScheduler()
  let child = null
  let openCount = 0
  const bridge = createH3CBridge({
    BroadcastChannelImplementation: MockBroadcastChannel,
    openWindow: (url) => {
      openCount += 1
      const request = parseH3BRequestTransport({
        hash: new URL(url, 'https://x402.ecash.mx').hash,
        search: '',
        nowSeconds: NOW
      }).request
      scheduler.set(() => {
        child = new MockBroadcastChannel(h3cChannelName(request.challengeId))
        child.postMessage({ type: 'h3c-handoff-opened', challengeId: request.challengeId })
      }, 8_000)
      return null
    },
    cryptoImplementation: deterministicCrypto,
    nowSeconds: () => NOW,
    setTimeoutImplementation: scheduler.set,
    clearTimeoutImplementation: scheduler.clear
  })
  const handoff = startApprovedHandoff(bridge)
  assert.equal(bridge.getSnapshot().state, 'handoff-opening')
  assert.equal(child, null)
  scheduler.runDelay(8_000)
  const result = await handoff
  assert.equal(result.status, 'authorization_pending')
  assert.equal(bridge.getSnapshot().state, 'awaiting-tonalli')
  assert.equal(bridge.getSnapshot().expiresAt - bridge.getSnapshot().issuedAt, 240)
  assert.equal(openCount, 1)
  child.close()
  bridge.dispose()
})

test('H3C-R2 C: repeated valid child announcements settle the parent exactly once', async () => {
  MockBroadcastChannel.reset()
  let child
  let randomCalls = 0
  let openCount = 0
  const acceptedMessages = []
  const cryptoImplementation = {
    subtle: deterministicCrypto.subtle,
    getRandomValues (bytes) {
      randomCalls += 1
      return deterministicCrypto.getRandomValues(bytes)
    }
  }
  const bridge = createH3CBridge({
    BroadcastChannelImplementation: MockBroadcastChannel,
    openWindow: (url) => {
      openCount += 1
      const request = parseH3BRequestTransport({
        hash: new URL(url, 'https://x402.ecash.mx').hash,
        search: '',
        nowSeconds: NOW
      }).request
      child = new MockBroadcastChannel(h3cChannelName(request.challengeId))
      child.onmessage = (event) => {
        if (event.data.type === 'h3c-handoff-accepted') acceptedMessages.push(event.data)
      }
      queueMicrotask(() => {
        for (let count = 0; count < 4; count += 1) {
          child.postMessage({ type: 'h3c-handoff-opened', challengeId: request.challengeId })
        }
      })
      return null
    },
    cryptoImplementation,
    nowSeconds: () => NOW,
    handoffTimeoutMs: H3C_HANDOFF_TIMEOUT_MS
  })
  await startApprovedHandoff(bridge)
  await flushMicrotasks()
  const snapshot = bridge.getSnapshot()
  assert.equal(acceptedMessages.length, 1)
  assert.equal(randomCalls, 1)
  assert.equal(openCount, 1)
  assert.equal(snapshot.challengeId, CHALLENGE)
  assert.equal(snapshot.expiresAt, NOW + H3C_TTL_SECONDS)
  child.close()
  bridge.dispose()
})

test('H3C-R2 D: child repeats until acceptance and navigates exactly once', async () => {
  const child = createHandoffChildHarness({
    onOpened: ({ message, parent, announcements }) => {
      if (announcements.length === 3) {
        parent.postMessage({
          type: 'h3c-handoff-accepted',
          challengeId: message.challengeId
        })
      }
    }
  })
  await flushMicrotasks()
  assert.equal(child.announcements.length, 1)
  child.scheduler.runDelay(H3C_HANDOFF_ANNOUNCEMENT_INTERVAL_MS)
  await flushMicrotasks()
  child.scheduler.runDelay(H3C_HANDOFF_ANNOUNCEMENT_INTERVAL_MS)
  await flushMicrotasks()
  assert.equal(child.announcements.length, 3)
  assert.ok(child.announcements.every((message) => (
    message.type === 'h3c-handoff-opened' &&
    message.challengeId === child.created.request.challengeId
  )))
  assert.deepEqual(child.location.replaced, [tonalliH3BUrl(child.created.encodedRequest)])
  assert.equal(child.scheduler.pending(), 0)
  child.scheduler.runDelay(H3C_HANDOFF_ANNOUNCEMENT_INTERVAL_MS)
  child.parent.postMessage({
    type: 'h3c-handoff-accepted',
    challengeId: child.created.request.challengeId
  })
  await flushMicrotasks()
  assert.equal(child.announcements.length, 3)
  assert.equal(child.location.replaced.length, 1)
  child.parent.close()
})

test('H3C-R2 E: no child acknowledgement for the full new timeout fails closed', async () => {
  MockBroadcastChannel.reset()
  const scheduler = createManualScheduler()
  const bridge = createH3CBridge({
    BroadcastChannelImplementation: MockBroadcastChannel,
    openWindow: () => ({}),
    cryptoImplementation: deterministicCrypto,
    nowSeconds: () => NOW,
    setTimeoutImplementation: scheduler.set,
    clearTimeoutImplementation: scheduler.clear
  })
  const handoff = startApprovedHandoff(bridge)
  const failure = assert.rejects(handoff, /did not acknowledge/u)
  scheduler.runDelay(H3C_HANDOFF_TIMEOUT_MS - 1)
  assert.equal(bridge.getSnapshot().state, 'handoff-opening')
  scheduler.runDelay(H3C_HANDOFF_TIMEOUT_MS)
  await failure
  assert.equal(bridge.getSnapshot().state, 'failed')
  bridge.dispose()

  const child = createHandoffChildHarness()
  await flushMicrotasks()
  child.scheduler.runDelay(H3C_HANDOFF_ANNOUNCEMENT_INTERVAL_MS)
  await flushMicrotasks()
  assert.equal(child.announcements.length, 2)
  child.scheduler.runDelay(H3C_HANDOFF_TIMEOUT_MS)
  assert.equal(child.document.body.dataset.handoffState, 'failed')
  assert.equal(child.location.replaced.length, 0)
  assert.equal(child.scheduler.pending(), 0)
  child.parent.close()
})

test('H3C-R2 F: wrong-challenge announcements are ignored', async () => {
  MockBroadcastChannel.reset()
  let child
  const acceptedMessages = []
  const bridge = createH3CBridge({
    BroadcastChannelImplementation: MockBroadcastChannel,
    openWindow: (url) => {
      const request = parseH3BRequestTransport({
        hash: new URL(url, 'https://x402.ecash.mx').hash,
        search: '',
        nowSeconds: NOW
      }).request
      child = new MockBroadcastChannel(h3cChannelName(request.challengeId))
      child.onmessage = (event) => acceptedMessages.push(event.data)
      return null
    },
    cryptoImplementation: deterministicCrypto,
    nowSeconds: () => NOW,
    handoffTimeoutMs: H3C_HANDOFF_TIMEOUT_MS
  })
  const handoff = startApprovedHandoff(bridge)
  child.postMessage({ type: 'h3c-handoff-opened', challengeId: `B${CHALLENGE.slice(1)}` })
  await flushMicrotasks()
  assert.equal(bridge.getSnapshot().state, 'handoff-opening')
  assert.equal(acceptedMessages.length, 0)
  child.postMessage({ type: 'h3c-handoff-opened', challengeId: CHALLENGE })
  await handoff
  await flushMicrotasks()
  assert.equal(acceptedMessages.filter((message) => message.type === 'h3c-handoff-accepted').length, 1)
  child.close()
  bridge.dispose()
})

test('H3C-R2 G: duplicate announcements after success cannot reopen or mutate the rendezvous', async () => {
  MockBroadcastChannel.reset()
  let child
  let openCount = 0
  const acceptedMessages = []
  const bridge = createH3CBridge({
    BroadcastChannelImplementation: MockBroadcastChannel,
    openWindow: (url) => {
      openCount += 1
      const request = parseH3BRequestTransport({
        hash: new URL(url, 'https://x402.ecash.mx').hash,
        search: '',
        nowSeconds: NOW
      }).request
      child = new MockBroadcastChannel(h3cChannelName(request.challengeId))
      child.onmessage = (event) => acceptedMessages.push(event.data)
      queueMicrotask(() => child.postMessage({
        type: 'h3c-handoff-opened',
        challengeId: request.challengeId
      }))
      return null
    },
    cryptoImplementation: deterministicCrypto,
    nowSeconds: () => NOW,
    handoffTimeoutMs: H3C_HANDOFF_TIMEOUT_MS
  })
  await startApprovedHandoff(bridge)
  await flushMicrotasks()
  const before = bridge.getSnapshot()
  for (let count = 0; count < 3; count += 1) {
    child.postMessage({ type: 'h3c-handoff-opened', challengeId: CHALLENGE })
  }
  await flushMicrotasks()
  assert.deepEqual(bridge.getSnapshot(), before)
  assert.equal(openCount, 1)
  assert.equal(acceptedMessages.filter((message) => message.type === 'h3c-handoff-accepted').length, 1)
  child.close()
  bridge.dispose()
})

test('H3C-R2 H: acknowledgement after parent failure is ignored', async () => {
  MockBroadcastChannel.reset()
  const scheduler = createManualScheduler()
  let child
  const acceptedMessages = []
  const bridge = createH3CBridge({
    BroadcastChannelImplementation: MockBroadcastChannel,
    openWindow: (url) => {
      const request = parseH3BRequestTransport({
        hash: new URL(url, 'https://x402.ecash.mx').hash,
        search: '',
        nowSeconds: NOW
      }).request
      child = new MockBroadcastChannel(h3cChannelName(request.challengeId))
      child.onmessage = (event) => acceptedMessages.push(event.data)
      return null
    },
    cryptoImplementation: deterministicCrypto,
    nowSeconds: () => NOW,
    setTimeoutImplementation: scheduler.set,
    clearTimeoutImplementation: scheduler.clear
  })
  const handoff = startApprovedHandoff(bridge)
  const failure = assert.rejects(handoff, /did not acknowledge/u)
  scheduler.runDelay(H3C_HANDOFF_TIMEOUT_MS)
  await failure
  const failed = bridge.getSnapshot()
  child.postMessage({ type: 'h3c-handoff-opened', challengeId: CHALLENGE })
  await flushMicrotasks()
  assert.deepEqual(bridge.getSnapshot(), failed)
  assert.equal(acceptedMessages.length, 0)
  child.close()
  bridge.dispose()
})

test('H3C-R2 I: authorization expiry wins before handshake success and prevents child navigation', async () => {
  MockBroadcastChannel.reset()
  const scheduler = createManualScheduler()
  let now = NOW
  let child
  const acceptedMessages = []
  const bridge = createH3CBridge({
    BroadcastChannelImplementation: MockBroadcastChannel,
    openWindow: (url) => {
      const request = parseH3BRequestTransport({
        hash: new URL(url, 'https://x402.ecash.mx').hash,
        search: '',
        nowSeconds: NOW
      }).request
      child = new MockBroadcastChannel(h3cChannelName(request.challengeId))
      child.onmessage = (event) => acceptedMessages.push(event.data)
      return null
    },
    cryptoImplementation: deterministicCrypto,
    nowSeconds: () => now,
    setTimeoutImplementation: scheduler.set,
    clearTimeoutImplementation: scheduler.clear
  })
  const handoff = startApprovedHandoff(bridge)
  const failure = assert.rejects(handoff, /expired before handoff acknowledgement/u)
  now = NOW + H3C_TTL_SECONDS
  scheduler.runDelay(H3C_HANDOFF_TIMEOUT_MS)
  await failure
  assert.equal(bridge.getSnapshot().state, 'expired')
  child.postMessage({ type: 'h3c-handoff-opened', challengeId: CHALLENGE })
  await flushMicrotasks()
  assert.equal(acceptedMessages.length, 0)
  child.close()
  bridge.dispose()

  let childNow = NOW * 1_000
  const expiredChild = createHandoffChildHarness({ nowMilliseconds: () => childNow })
  await flushMicrotasks()
  childNow = (NOW + H3C_TTL_SECONDS) * 1_000
  expiredChild.parent.postMessage({
    type: 'h3c-handoff-accepted',
    challengeId: expiredChild.created.request.challengeId
  })
  await flushMicrotasks()
  assert.equal(expiredChild.location.replaced.length, 0)
  assert.equal(expiredChild.document.body.dataset.handoffState, 'failed')
  expiredChild.parent.close()
})

test('H3C-R2 J: null window handle plus a valid child acknowledgement succeeds', async () => {
  const { bridge, openedUrls } = createAutoBridge({ handoffTimeoutMs: H3C_HANDOFF_TIMEOUT_MS })
  const result = await startApprovedHandoff(bridge)
  assert.equal(result.status, 'authorization_pending')
  assert.equal(bridge.getSnapshot().state, 'awaiting-tonalli')
  assert.equal(openedUrls.length, 1)
  bridge.dispose()
})

test('H3C-R2 K: null window handle without a child acknowledgement fails closed', async () => {
  MockBroadcastChannel.reset()
  const scheduler = createManualScheduler()
  const bridge = createH3CBridge({
    BroadcastChannelImplementation: MockBroadcastChannel,
    openWindow: () => null,
    cryptoImplementation: deterministicCrypto,
    nowSeconds: () => NOW,
    setTimeoutImplementation: scheduler.set,
    clearTimeoutImplementation: scheduler.clear,
    handoffTimeoutMs: 5
  })
  const handoff = startApprovedHandoff(bridge)
  const failure = assert.rejects(handoff, /did not acknowledge/u)
  scheduler.runDelay(5)
  await failure
  assert.equal(bridge.getSnapshot().state, 'failed')
  bridge.dispose()
})

test('H3C-R2 L: a throwing window.open fails closed immediately', async () => {
  MockBroadcastChannel.reset()
  const scheduler = createManualScheduler()
  let openAttempts = 0
  const bridge = createH3CBridge({
    BroadcastChannelImplementation: MockBroadcastChannel,
    openWindow: () => {
      openAttempts += 1
      throw new Error('blocked')
    },
    cryptoImplementation: deterministicCrypto,
    nowSeconds: () => NOW,
    setTimeoutImplementation: scheduler.set,
    clearTimeoutImplementation: scheduler.clear
  })
  await expectFailure(() => startApprovedHandoff(bridge), /could not open/u)
  assert.equal(bridge.getSnapshot().state, 'failed')
  assert.equal(openAttempts, 1)
  assert.equal(scheduler.pending(), 0)
  bridge.dispose()
})

test('H3C-R2 child ignores wrong acceptance and pagehide stops every announcement', async () => {
  const child = createHandoffChildHarness()
  await flushMicrotasks()
  child.parent.postMessage({
    type: 'h3c-handoff-accepted',
    challengeId: child.created.request.challengeId,
    unexpected: true
  })
  await flushMicrotasks()
  assert.equal(child.location.replaced.length, 0)
  child.parent.postMessage({
    type: 'h3c-handoff-accepted',
    challengeId: `B${child.created.request.challengeId.slice(1)}`
  })
  await flushMicrotasks()
  assert.equal(child.location.replaced.length, 0)
  child.scheduler.runDelay(H3C_HANDOFF_ANNOUNCEMENT_INTERVAL_MS)
  await flushMicrotasks()
  assert.equal(child.announcements.length, 2)
  child.dispatchPageHide()
  assert.equal(child.scheduler.pending(), 0)
  child.scheduler.runDelay(H3C_HANDOFF_ANNOUNCEMENT_INTERVAL_MS)
  await flushMicrotasks()
  assert.equal(child.announcements.length, 2)
  assert.equal(child.location.replaced.length, 0)
  child.parent.close()
})

test('H3C-R2 M: repeated handoff announcements perform no additional protected-resource fetch', async () => {
  const { bridge, execute, fetches, rendered } = createResourceHarness()
  await execute({})
  await bridge.startHandoff(rendered[0].binding)
  bridge.readResult()
  assert.equal(fetches.length, 1)
  const source = await readFile(`${WEBMCP_ROOT}webmcp.js`, 'utf8')
  const executor = source.slice(
    source.indexOf('export const createResourceToolExecutor'),
    source.indexOf('const executeResourceTool =')
  )
  assert.equal((executor.match(/fetchImplementation\s*\(/gu) ?? []).length, 1)
  bridge.dispose()
})

test('H3C-R2 N: robust handoff retains zero persistent browser storage', async () => {
  const files = ['h3c-contract.js', 'h3c-bridge.js', 'h3c-handoff.js', 'webmcp.js']
  const source = (await Promise.all(files.map((file) => readFile(`${WEBMCP_ROOT}${file}`, 'utf8')))).join('\n')
  for (const forbidden of ['localStorage', 'sessionStorage', 'indexedDB', 'document.cookie']) {
    assert.equal(source.includes(forbidden), false, forbidden)
  }
})

test('H3C-R2 O: robust handoff constructs no PAYMENT-SIGNATURE', async () => {
  const files = ['h3c-contract.js', 'h3c-bridge.js', 'h3c-handoff.js', 'webmcp.js']
  const source = (await Promise.all(files.map((file) => readFile(`${WEBMCP_ROOT}${file}`, 'utf8')))).join('\n')
  assert.equal(/["']PAYMENT-SIGNATURE["']\s*:/u.test(source), false)
  assert.equal(/\.set\(\s*["']PAYMENT-SIGNATURE["']/u.test(source), false)
  assert.equal(/setRequestHeader\(\s*["']PAYMENT-SIGNATURE["']/u.test(source), false)
})

test('H3C-R2 P: robust handoff contains no transaction or UTXO builder', async () => {
  const files = ['h3c-contract.js', 'h3c-bridge.js', 'h3c-handoff.js', 'h3c-verify.js', 'webmcp.js']
  const source = (await Promise.all(files.map((file) => readFile(`${WEBMCP_ROOT}${file}`, 'utf8')))).join('\n')
  for (const forbidden of [
    'TxBuilder', 'TransactionBuilder', 'buildTransaction', 'createTransaction',
    'signTransaction', 'selectUtxo', 'selectUtxos'
  ]) {
    assert.equal(source.includes(forbidden), false, forbidden)
  }
})

test('H3C-R2 Q: robust handoff contains no Chronik or blockchain broadcast', async () => {
  const files = ['h3c-contract.js', 'h3c-bridge.js', 'h3c-handoff.js', 'h3c-verify.js', 'webmcp.js']
  const source = (await Promise.all(files.map((file) => readFile(`${WEBMCP_ROOT}${file}`, 'utf8')))).join('\n')
  assert.equal(/chronik/iu.test(source), false)
  for (const forbidden of [/broadcastTx\s*\(/u, /sendRawTransaction\s*\(/u, /submitTx\s*\(/u]) {
    assert.equal(forbidden.test(source), false, forbidden.source)
  }
})

test('BroadcastChannel support is mandatory', async () => {
  const bridge = createH3CBridge({
    BroadcastChannelImplementation: null,
    cryptoImplementation: deterministicCrypto,
    nowSeconds: () => NOW
  })
  await expectFailure(() => startApprovedHandoff(bridge), /BroadcastChannel is unavailable/u)
})

test('an unrelated completed-tool AbortSignal cannot cancel page-owned approval', async () => {
  const controller = new AbortController()
  const { bridge, openedUrls } = createAutoBridge()
  const approval = createApproval(bridge)
  controller.abort()
  assert.equal(bridge.readResult().status, 'approval_required')
  await bridge.startHandoff(approval.binding)
  assert.equal(bridge.getSnapshot().state, 'awaiting-tonalli')
  assert.equal(openedUrls.length, 1)
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
  await startApprovedHandoff(bridge)
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
  await startApprovedHandoff(bridge)
  now = NOW + H3C_TTL_SECONDS
  assert.throws(() => bridge.readResult(), /expired/u)
  assert.equal(bridge.getSnapshot().state, 'expired')
  bridge.dispose()
})

test('live-state checks release a throttled expired rendezvous', async () => {
  let now = NOW
  const { bridge } = createAutoBridge({ nowSeconds: () => now })
  await startApprovedHandoff(bridge)
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
    () => startApprovedHandoff(bridge),
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
  await startApprovedHandoff(bridge)
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
  await startApprovedHandoff(bridge)
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
  await startApprovedHandoff(bridge)
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
  await startApprovedHandoff(bridge)
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
  await startApprovedHandoff(bridge)
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
  await startApprovedHandoff(bridge)
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
  await startApprovedHandoff(bridge)
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
  assert.throws(() => fresh.readResult(), /No ephemeral H3A\/H3C authorization session/u)
})

test('malformed callback fails closed before proof verification', async () => {
  let verificationCalls = 0
  const { bridge } = createAutoBridge({
    verifyProof: async () => {
      verificationCalls += 1
      throw new Error('must not run')
    }
  })
  await startApprovedHandoff(bridge)
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

test('resource tool returns exact approval_required before any human decision', async () => {
  const { bridge, execute, fetches, openedUrls, rendered } = createResourceHarness()
  const result = await execute({})
  assert.deepEqual(result, FIRST_APPROVAL_REQUIRED)
  assert.deepEqual(bridge.readResult(), RESULT_APPROVAL_REQUIRED)
  assert.equal(fetches.length, 1)
  assert.equal(fetches[0].url, 'https://api.x402.ecash.mx/v1/resource/demo')
  assert.deepEqual(fetches[0].options, { cache: 'no-store', redirect: 'error' })
  assert.equal(rendered.length, 1)
  assert.equal(openedUrls.length, 0)
  assert.equal(bridge.getSnapshot().state, 'approval-required')
  assert.equal(bridge.getSnapshot().challengeId, null)
  assert.equal(bridge.getSnapshot().expiresAt, null)
  bridge.dispose()
})

test('arbitrarily long delay after tool return preserves approval and starts a fresh 240-second H3C clock', async () => {
  let now = NOW
  const { bridge, execute, openedUrls, rendered } = createResourceHarness({
    bridgeOverrides: { nowSeconds: () => now }
  })
  await execute({})
  const before = bridge.getSnapshot()
  assert.equal(before.createdAt, NOW)
  now += 31_536_000
  assert.equal(bridge.hasLiveSession(), true)
  assert.equal(bridge.getSnapshot().generation, before.generation)
  assert.equal(bridge.getSnapshot().createdAt, before.createdAt)
  const handoff = bridge.startHandoff(rendered[0].binding)
  assert.equal(openedUrls.length, 1)
  const request = parseH3BRequestTransport({
    hash: new URL(openedUrls[0], 'https://x402.ecash.mx').hash,
    search: '',
    nowSeconds: now
  }).request
  assert.equal(request.issuedAt, now)
  assert.equal(request.expiresAt, now + H3C_TTL_SECONDS)
  await handoff
  assert.equal(bridge.getSnapshot().state, 'awaiting-tonalli')
  bridge.dispose()
})

test('human Reject after resource-tool return is page-owned and opens no handoff', async () => {
  const { bridge, execute, fetches, openedUrls, rendered, trace } = createResourceHarness()
  await execute({})
  const result = bridge.rejectApproval(rendered[0].binding)
  assert.deepEqual(result, HUMAN_REJECTED)
  assert.deepEqual(bridge.readResult(), HUMAN_REJECTED)
  assert.equal(fetches.length, 1)
  assert.equal(openedUrls.length, 0)
  assert.ok(trace.includes('Human decision: REJECTED'))
  assert.ok(trace.includes('STOP - Payment not authorized'))
  await expectFailure(() => bridge.startHandoff(rendered[0].binding), /no longer matches/u)
  bridge.dispose()
})

test('human Approve after resource-tool return opens synchronously and later verifies', async () => {
  MockBroadcastChannel.reset()
  let clickReturned = false
  let openedSynchronously = false
  let child
  const { bridge, execute, rendered } = createResourceHarness({
    bridgeOverrides: {
      openWindow: (url) => {
        openedSynchronously = !clickReturned
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
      }
    }
  })
  await execute({})
  const handoff = bridge.startHandoff(rendered[0].binding)
  clickReturned = true
  assert.equal(openedSynchronously, true)
  assert.equal(bridge.readResult().status, 'authorization_pending')
  await handoff
  assert.equal(bridge.readResult().authorization.pending, true)
  await sendCallback(bridge, {
    type: 'h3c-callback',
    challengeId: CHALLENGE,
    status: 'signed',
    proof: encodeCanonicalBase64Url(signedVectorProof)
  })
  assert.equal(bridge.readResult().status, 'authorization_verified')
  child.close()
  bridge.dispose()
})

test('aborting the original tool signal after return does not cancel approval or handoff', async () => {
  const controller = new AbortController()
  const { bridge, execute, openedUrls, rendered } = createResourceHarness()
  assert.deepEqual(await execute({}, { signal: controller.signal }), FIRST_APPROVAL_REQUIRED)
  controller.abort()
  assert.deepEqual(bridge.readResult(), RESULT_APPROVAL_REQUIRED)
  await bridge.startHandoff(rendered[0].binding)
  assert.equal(openedUrls.length, 1)
  assert.equal(bridge.getSnapshot().state, 'awaiting-tonalli')
  bridge.dispose()
})

test('abort before resource-tool return creates no approval session and permits retry', async () => {
  const firstFetch = deferred()
  let fetchCall = 0
  const controller = new AbortController()
  const { bridge, execute, fetches, rendered } = createResourceHarness({
    fetchImplementation: () => {
      fetchCall += 1
      return fetchCall === 1 ? firstFetch.promise : paymentRequiredResponse()
    }
  })
  const first = execute({}, { signal: controller.signal })
  controller.abort()
  firstFetch.resolve(paymentRequiredResponse())
  await assert.rejects(first, (error) => error?.name === 'AbortError')
  assert.equal(fetches[0].options.signal, controller.signal)
  assert.equal(bridge.getSnapshot().state, 'idle')
  assert.equal(rendered.length, 0)
  assert.deepEqual(await execute({}), FIRST_APPROVAL_REQUIRED)
  assert.equal(rendered.length, 1)
  bridge.dispose()
})

test('concurrent resource invocation fails before a second fetch', async () => {
  const firstFetch = deferred()
  const { bridge, execute, fetches } = createResourceHarness({
    fetchImplementation: () => firstFetch.promise
  })
  const first = execute({})
  await waitFor(() => fetches.length === 1)
  await expectFailure(() => execute({}), /already active/u)
  assert.equal(fetches.length, 1)
  firstFetch.resolve(paymentRequiredResponse())
  await first
  bridge.dispose()
})

test('live approval session blocks replacement before any additional fetch', async () => {
  const { bridge, execute, fetches } = createResourceHarness()
  await execute({})
  await expectFailure(() => execute({}), /already pending/u)
  assert.equal(fetches.length, 1)
  assert.equal(bridge.getSnapshot().state, 'approval-required')
  bridge.dispose()
})

test('resource tool is blocked during handoff-opening, awaiting-tonalli, and proof-verifying', async () => {
  const verification = deferred()
  let handoffChild
  const { bridge, execute, fetches, rendered } = createResourceHarness({
    bridgeOverrides: {
      openWindow: (url) => {
        const request = parseH3BRequestTransport({
          hash: new URL(url, 'https://x402.ecash.mx').hash,
          search: '',
          nowSeconds: NOW
        }).request
        handoffChild = new MockBroadcastChannel(h3cChannelName(request.challengeId))
        return null
      },
      verifyProof: () => verification.promise
    }
  })
  await execute({})
  const handoff = bridge.startHandoff(rendered[0].binding)
  await waitFor(() => bridge.getSnapshot().state === 'handoff-opening')
  await expectFailure(() => execute({}), /already pending/u)
  assert.equal(fetches.length, 1)

  handoffChild.postMessage({ type: 'h3c-handoff-opened', challengeId: CHALLENGE })
  await handoff
  await expectFailure(() => execute({}), /already pending/u)
  assert.equal(fetches.length, 1)

  const callback = new MockBroadcastChannel(h3cChannelName(CHALLENGE))
  callback.postMessage({ type: 'h3c-callback', challengeId: CHALLENGE, status: 'signed', proof: 'e30' })
  await waitFor(() => bridge.getSnapshot().state === 'proof-verifying')
  await expectFailure(() => execute({}), /already pending/u)
  assert.equal(fetches.length, 1)
  verification.resolve({
    payer: vector.payer,
    publicKey: vector.publicKey,
    paymentRequiredSha256: PAYMENT_REQUIRED_SHA256
  })
  await waitFor(() => bridge.getSnapshot().state === 'verified')
  callback.close()
  handoffChild.close()
  bridge.dispose()
})

test('malformed PaymentRequired never creates or renders approval state', async () => {
  const malformed = clone(PAYMENT_REQUIRED)
  malformed.accepts[0].amount = '10001'
  const { bridge, execute, fetches, rendered } = createResourceHarness({
    fetchImplementation: () => paymentRequiredResponse(malformed)
  })
  await expectFailure(() => execute({}), /amount must equal 10000/u)
  assert.equal(fetches.length, 1)
  assert.equal(rendered.length, 0)
  assert.equal(bridge.getSnapshot().state, 'idle')
  bridge.dispose()
})

for (const [name, response] of [
  ['non-402 response', { status: 200, headers: { get: () => null } }],
  ['missing PAYMENT-REQUIRED header', { status: 402, headers: { get: () => null } }],
  ['malformed Base64 header', { status: 402, headers: { get: () => '***' } }],
  ['invalid UTF-8 header', { status: 402, headers: { get: () => Buffer.from([0xff]).toString('base64') } }],
  ['invalid JSON header', { status: 402, headers: { get: () => Buffer.from('not-json').toString('base64') } }]
]) {
  test(`${name} fails before approval state is rendered`, async () => {
    const { bridge, execute, fetches, rendered } = createResourceHarness({
      fetchImplementation: () => response
    })
    await expectFailure(() => execute({}))
    assert.equal(fetches.length, 1)
    assert.equal(rendered.length, 0)
    assert.equal(bridge.getSnapshot().state, 'idle')
    bridge.dispose()
  })
}

test('terminal H3A rejection resets only after a newly validated 402', async () => {
  const { bridge, execute, fetches, rendered, trace } = createResourceHarness()
  await execute({})
  const firstBinding = rendered[0].binding
  const firstGeneration = bridge.getSnapshot().generation
  bridge.rejectApproval(firstBinding)
  await execute({})
  assert.equal(fetches.length, 2)
  assert.equal(rendered.length, 2)
  assert.equal(bridge.getSnapshot().state, 'approval-required')
  assert.equal(bridge.getSnapshot().generation, firstGeneration + 1)
  assert.equal(bridge.getSnapshot().challengeId, null)
  assert.ok(trace.includes('Previous terminal authorization session reset for a new validated resource request'))
  assert.throws(() => bridge.validateApproval(firstBinding), /no longer matches/u)
  bridge.dispose()
})

test('rejected, verified, failed, and expired sessions all use the explicit terminal reset policy', async () => {
  const cases = [
    {
      name: 'rejected',
      setup: async (bridge, binding) => { bridge.rejectApproval(binding) }
    },
    {
      name: 'verified',
      setup: async (bridge, binding) => {
        await bridge.startHandoff(binding)
        await sendCallback(bridge, {
          type: 'h3c-callback',
          challengeId: CHALLENGE,
          status: 'signed',
          proof: encodeCanonicalBase64Url(signedVectorProof)
        })
      }
    },
    {
      name: 'failed',
      setup: async (bridge, binding) => {
        bridge.failApprovalSession(binding, new Error('deterministic failure'))
      }
    },
    {
      name: 'expired',
      setup: async (bridge, binding, advanceClock) => {
        await bridge.startHandoff(binding)
        advanceClock()
        assert.equal(bridge.hasLiveSession(), false)
      }
    }
  ]

  for (const scenario of cases) {
    let now = NOW
    const { bridge, execute, fetches, rendered, trace } = createResourceHarness({
      bridgeOverrides: { nowSeconds: () => now }
    })
    await execute({})
    const first = rendered[0]
    const firstGeneration = first.binding.generation
    await scenario.setup(bridge, first.binding, () => { now += H3C_TTL_SECONDS })
    assert.equal(bridge.getSnapshot().state, scenario.name)
    await execute({})
    assert.equal(fetches.length, 2)
    assert.equal(rendered.length, 2)
    assert.equal(rendered[1].binding.generation, firstGeneration + 1)
    assert.equal(bridge.getSnapshot().state, 'approval-required')
    assert.equal(bridge.getSnapshot().challengeId, null)
    assert.ok(trace.includes('Previous terminal authorization session reset for a new validated resource request'))
    assert.throws(() => bridge.validateApproval(first.binding), /no longer matches/u)
    bridge.dispose()
  }
})

test('failed replacement validation preserves the previous terminal result', async () => {
  let fetchCall = 0
  const malformed = clone(PAYMENT_REQUIRED)
  malformed.resource.url = 'https://example.com/resource'
  const { bridge, execute, rendered } = createResourceHarness({
    fetchImplementation: () => {
      fetchCall += 1
      return paymentRequiredResponse(fetchCall === 1 ? PAYMENT_REQUIRED : malformed)
    }
  })
  await execute({})
  bridge.rejectApproval(rendered[0].binding)
  const terminal = bridge.readResult()
  await expectFailure(() => execute({}), /resource.url/u)
  assert.deepEqual(bridge.readResult(), terminal)
  assert.equal(bridge.getSnapshot().state, 'rejected')
  bridge.dispose()
})

test('stale fingerprint and double approval attempts fail closed without a second popup', async () => {
  const mutableRequirement = clone(PAYMENT_REQUIRED)
  const { bridge, openedUrls } = createAutoBridge()
  const approval = createApproval(bridge, mutableRequirement)
  mutableRequirement.accepts[0].amount = '10001'
  assert.throws(() => bridge.validateApproval(approval.binding), /no longer matches/u)
  assert.throws(
    () => bridge.failApprovalSession({
      ...approval.binding,
      paymentRequiredFingerprint: 'forged-fingerprint'
    }, new Error('forged failure')),
    /no longer current/u
  )
  assert.equal(bridge.getSnapshot().state, 'approval-required')
  bridge.failApprovalSession(approval.binding, new Error('fingerprint changed'))
  assert.equal(bridge.getSnapshot().state, 'failed')
  assert.equal(openedUrls.length, 0)

  const next = createApproval(bridge)
  const firstHandoff = bridge.startHandoff(next.binding)
  await expectFailure(() => bridge.startHandoff(next.binding), /no longer matches/u)
  await firstHandoff
  assert.equal(openedUrls.length, 1)
  bridge.dispose()
})

test('registered production tools handle real Reject and Approve button clicks after returning', async () => {
  MockBroadcastChannel.reset()
  const ui = createProductionUiEnvironment()
  const restore = [
    replaceGlobal('document', ui.document),
    replaceGlobal('window', { open: ui.openWindow, close: () => {} }),
    replaceGlobal('fetch', ui.fetchImplementation),
    replaceGlobal('BroadcastChannel', MockBroadcastChannel)
  ]
  try {
    const production = await import(new URL('../webmcp.js?production-ui-integration=1', import.meta.url))
    production.initializeWebMcp()
    await waitFor(() => ui.registeredTools.size === 2)
    const resourceTool = ui.registeredTools.get('get_paid_xec_resource')
    const resultTool = ui.registeredTools.get('get_x402_authorization_result')
    assert.ok(resourceTool)
    assert.ok(resultTool)

    assert.deepEqual(await resourceTool.execute({}), FIRST_APPROVAL_REQUIRED)
    assert.equal(ui.cards.length, 1)
    const rejectedCard = ui.cards[0]
    assert.equal(rejectedCard.rejectButton.click(), true)
    assert.deepEqual(resultTool.execute({}), HUMAN_REJECTED)
    assert.equal(rejectedCard.rejectButton.disabled, true)
    assert.equal(rejectedCard.approveButton.disabled, true)
    assert.equal(rejectedCard.approveButton.click(), false)
    assert.equal(ui.openedUrls.length, 0)

    assert.deepEqual(await resourceTool.execute({}), FIRST_APPROVAL_REQUIRED)
    assert.equal(ui.cards.length, 2)
    assert.equal(ui.approvalMount.children.length, 1)
    const approvedCard = ui.cards[1]
    const traceBeforeApproval = ui.trace.length
    assert.equal(approvedCard.approveButton.click(), true)
    assert.equal(ui.openedUrls.length, 1, 'window.open must run synchronously inside the button click')
    assert.equal(approvedCard.rejectButton.disabled, true)
    assert.equal(approvedCard.approveButton.disabled, true)
    assert.equal(approvedCard.approveButton.click(), false)
    await waitFor(() => ui.trace.some((entry) => entry.includes('Tonalli authorization handoff opened')))

    const pending = resultTool.execute({})
    assert.equal(pending.status, 'authorization_pending')
    assert.equal(pending.gate, 'H3C')
    assert.equal(typeof pending.challengeId, 'string')
    const approvalTrace = ui.trace.findIndex((entry, index) => (
      index >= traceBeforeApproval && entry.includes('Human decision: APPROVED')
    ))
    const challengeTrace = ui.trace.findIndex((entry, index) => (
      index >= traceBeforeApproval && entry.includes('H3B challenge created')
    ))
    assert.ok(approvalTrace >= traceBeforeApproval)
    assert.ok(challengeTrace > approvalTrace)

    const callback = new MockBroadcastChannel(h3cChannelName(pending.challengeId))
    callback.postMessage({
      type: 'h3c-callback',
      challengeId: pending.challengeId,
      status: 'rejected'
    })
    await waitFor(() => {
      try { return resultTool.execute({}).status === 'authorization_rejected' } catch { return false }
    })
    assert.match(approvedCard.status.textContent, /Tonalli authorization request rejected/u)
    assert.equal(ui.fetches.length, 2, 'human decisions must not retry the protected resource')
    callback.close()
    await new Promise((resolve) => setTimeout(resolve, 1))
  } finally {
    for (const restoreGlobal of restore.reverse()) restoreGlobal()
    MockBroadcastChannel.reset()
  }
})

test('production click handler validates, disables, and starts H3C without awaiting', async () => {
  const source = await readFile(`${WEBMCP_ROOT}webmcp.js`, 'utf8')
  const handler = source.slice(
    source.indexOf('function handleApprove'),
    source.indexOf('try {\n    ui.rejectButton.addEventListener')
  )
  assert.ok(handler.indexOf('h3cBridge.validateApproval(binding)') < handler.indexOf('lockControls()'))
  assert.ok(handler.indexOf('lockControls()') < handler.indexOf("addTraceEvent('Human decision: APPROVED')"))
  assert.ok(handler.indexOf("addTraceEvent('Human decision: APPROVED')") < handler.indexOf('h3cBridge.startHandoff(binding)'))
  assert.equal(handler.includes('await '), false)
  assert.ok(source.includes('ui.rejectButton.disabled = true'))
  assert.ok(source.includes('ui.approveButton.disabled = true'))
  assert.ok(source.includes("addTraceEvent('Human approval required')"))
  assert.equal(source.includes("signal?.addEventListener('abort'"), false)
})

test('resource tool contains one fetch path and never awaits the human decision', async () => {
  const source = await readFile(`${WEBMCP_ROOT}webmcp.js`, 'utf8')
  const executor = source.slice(
    source.indexOf('export const createResourceToolExecutor'),
    source.indexOf('const executeResourceTool =')
  )
  assert.equal((executor.match(/fetchImplementation\s*\(/gu) ?? []).length, 1)
  assert.equal(executor.includes('requestHumanApproval'), false)
  assert.equal(executor.includes('await handoff'), false)
  assert.equal(source.includes('retry'), false)
})

test('H3C-R1 page copy and approval card describe the decoupled state truthfully', async () => {
  const page = await readFile(`${WEBMCP_ROOT}index.html`, 'utf8')
  for (const expected of [
    'returns <code>approval_required</code> immediately',
    'The human can decide afterward.',
    'The resource tool has already returned.',
    'get_x402_authorization_result',
    '100 XEC',
    'Approve 100 XEC',
    'Reject'
  ]) {
    assert.ok(page.includes(expected), expected)
  }
  const runtime = await readFile(`${WEBMCP_ROOT}webmcp.js`, 'utf8')
  for (const field of [
    'acceptance.extra.displayAmount',
    'acceptance.network',
    'acceptance.asset',
    'acceptance.payTo',
    'acceptance.extra.experimental'
  ]) {
    assert.ok(runtime.includes(field), field)
  }
  assert.equal(page.includes('the tool opens an authorization-only Tonalli handoff and returns'), false)
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
  assert.ok(handoff.indexOf('isAcceptedHandoff') < handoff.indexOf('locationImplementation.replace'))
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
