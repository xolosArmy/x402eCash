import { Core } from '@walletconnect/core'
import { SignClient } from '@walletconnect/sign-client'

export const H3WC_CHAIN = 'ecash:1'
export const H3WC_METHODS = Object.freeze([
  'ecash_getAccountIdentity',
  'ecash_signMessage'
])
export const H3WC_EVENTS = Object.freeze([])
export const H3WC_STORAGE_PREFIX = 'tonalli-h3wc-v1'
export const H3WC_REQUESTER_ORIGIN = 'https://x402.ecash.mx'
export const H3WC_WALLET_ORIGIN = 'https://app.tonalli.cash'
export const H3WC_PROFILE = 'x402-h3b-authorization-v1'
export const H3WC_GRANT_VERSION = 1
export const H3WC_SIGNING_NOT_ENABLED = 'H3WC_SIGNING_NOT_ENABLED'
export const H3WC_DEFAULT_ENABLED = false

export const H3WC_REQUIRED_NAMESPACES = Object.freeze({
  ecash: Object.freeze({
    chains: Object.freeze([H3WC_CHAIN]),
    methods: H3WC_METHODS,
    events: H3WC_EVENTS
  })
})

const isRecord = (value) => (
  typeof value === 'object' && value !== null && !Array.isArray(value)
)

const sorted = (values) => [...values].sort()

const exactArray = (value, expected, label) => {
  if (!Array.isArray(value) || !value.every((item) => typeof item === 'string')) {
    throw new Error(`H3WC ${label} is invalid`)
  }
  if (new Set(value).size !== value.length) throw new Error(`H3WC ${label} contains duplicates`)
  const actual = sorted(value)
  const wanted = sorted(expected)
  if (actual.length !== wanted.length || actual.some((item, index) => item !== wanted[index])) {
    throw new Error(`H3WC ${label} does not equal the frozen grant`)
  }
  return Object.freeze([...value])
}

const canonicalOrigin = (value) => {
  if (typeof value !== 'string' || value.trim() === '') throw new Error('H3WC peer origin is missing')
  let url
  try { url = new URL(value) } catch { throw new Error('H3WC peer origin is malformed') }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
    throw new Error('H3WC peer origin is not an exact HTTPS origin')
  }
  if (url.pathname !== '/' || url.port) throw new Error('H3WC peer origin contains a path or port')
  return url.origin
}

const canonicalAccount = (value) => {
  if (typeof value !== 'string' || !/^ecash:1:[qp][a-z0-9]+$/u.test(value)) {
    throw new Error('H3WC session account is not a canonical ecash:1 CAIP-10 account')
  }
  return value
}

const canonicalIdentity = (value) => {
  if (!isRecord(value) || Object.keys(value).length !== 2 || !('address' in value) || !('publicKey' in value)) {
    throw new Error('H3WC identity has unexpected fields')
  }
  if (typeof value.address !== 'string' || !/^ecash:[qp][a-z0-9]+$/u.test(value.address)) {
    throw new Error('H3WC identity address is invalid')
  }
  if (typeof value.publicKey !== 'string' || !/^(?:02|03)[0-9a-f]{64}$/u.test(value.publicKey)) {
    throw new Error('H3WC identity publicKey is not lowercase compressed secp256k1')
  }
  return Object.freeze({ address: value.address, publicKey: value.publicKey })
}

const sessionAccountForIdentity = (identity) => {
  const [, payload] = identity.address.split(':')
  return `ecash:1:${payload}`
}

const readPeerOrigin = (session) => {
  const metadata = session?.peer?.metadata
  if (!isRecord(metadata)) throw new Error('H3WC session peer metadata is missing')
  return canonicalOrigin(metadata.url)
}

/**
 * Qualifies only the effective approved/restored session.  Proposal fields
 * are intentionally absent: SDK proposal normalization is not authority.
 */
export const qualifyH3wcSession = (session, {
  nowSeconds = Math.floor(Date.now() / 1000),
  expectedWalletOrigin = H3WC_WALLET_ORIGIN
} = {}) => {
  if (!isRecord(session) || typeof session.topic !== 'string' || session.topic.length === 0) {
    throw new Error('H3WC session topic is invalid')
  }
  if (!Number.isSafeInteger(session.expiry) || session.expiry <= nowSeconds) {
    throw new Error('H3WC session is expired or has an invalid expiry')
  }
  if (session.acknowledged !== true) throw new Error('H3WC session is not acknowledged')
  if (!isRecord(session.namespaces) || Object.keys(session.namespaces).length !== 1 || !('ecash' in session.namespaces)) {
    throw new Error('H3WC session contains an unexpected namespace')
  }
  const namespace = session.namespaces.ecash
  if (!isRecord(namespace)) throw new Error('H3WC ecash namespace is invalid')
  const namespaceKeys = Object.keys(namespace).sort()
  if (namespaceKeys.join(',') !== 'accounts,chains,events,methods') {
    throw new Error('H3WC namespace contains unknown authority fields')
  }
  exactArray(namespace.chains, [H3WC_CHAIN], 'chains')
  exactArray(namespace.methods, H3WC_METHODS, 'methods')
  exactArray(namespace.events, H3WC_EVENTS, 'events')
  if (!Array.isArray(namespace.accounts) || namespace.accounts.length !== 1) {
    throw new Error('H3WC session must bind exactly one account')
  }
  const account = canonicalAccount(namespace.accounts[0])
  const peerOrigin = readPeerOrigin(session)
  const expectedOrigin = canonicalOrigin(expectedWalletOrigin)
  if (peerOrigin !== expectedOrigin) throw new Error('H3WC session peer origin does not match Tonalli')
  return Object.freeze({
    topic: session.topic,
    account,
    peerOrigin,
    expiresAt: session.expiry,
    grantVersion: H3WC_GRANT_VERSION,
    profile: H3WC_PROFILE
  })
}

const assertProjectId = (value) => {
  if (typeof value !== 'string' || value.trim() === '') throw new Error('H3WC project ID is required')
  return value.trim()
}

const assertMessage = (value) => {
  if (typeof value !== 'string' || value.length === 0 || value.length > 64 * 1024) {
    throw new Error('H3WC authorization message is invalid')
  }
  return value
}

const identityRequest = Object.freeze({ method: 'ecash_getAccountIdentity', params: {} })

class TonalliConnectClient {
  constructor(signClient, core, options) {
    this.signClient = signClient
    this.core = core
    this.options = options
    this.session = null
    this.qualification = null
  }

  qualify(session) {
    const result = qualifyH3wcSession(session, {
      nowSeconds: this.options.nowSeconds(),
      expectedWalletOrigin: this.options.walletOrigin
    })
    this.session = session
    this.qualification = result
    return result
  }

  async connect({ onUri } = {}) {
    const { uri, approval } = await this.signClient.connect({
      requiredNamespaces: H3WC_REQUIRED_NAMESPACES
    })
    if (uri) {
      if (typeof onUri === 'function') onUri(uri)
      else this.lastUri = uri
    }
    if (typeof approval !== 'function') throw new Error('H3WC session approval is unavailable')
    const session = await approval()
    this.qualify(session)
    return Object.freeze({ session, qualification: this.qualification, uri: uri ?? null })
  }

  async restore() {
    const sessions = this.signClient.session.getAll()
    const qualified = sessions.map((session) => {
      const qualification = qualifyH3wcSession(session, {
        nowSeconds: this.options.nowSeconds(),
        expectedWalletOrigin: this.options.walletOrigin
      })
      return Object.freeze({ session, qualification })
    })
    if (qualified.length === 1) {
      this.session = qualified[0].session
      this.qualification = qualified[0].qualification
    } else {
      this.session = null
      this.qualification = null
    }
    return Object.freeze(qualified)
  }

  requireSession() {
    if (!this.session || !this.qualification) throw new Error('H3WC has no qualified session')
    // Recompute from the current SDK object before every request; the cached
    // result is informational and never authority.
    const current = this.signClient.session.get(this.session.topic)
    this.qualify(current)
    return current
  }

  async getAccountIdentity() {
    const session = this.requireSession()
    const value = await session.request({ chainId: H3WC_CHAIN, request: identityRequest })
    const identity = canonicalIdentity(value)
    if (sessionAccountForIdentity(identity) !== this.qualification.account) {
      throw new Error('H3WC identity does not bind to the qualified session account')
    }
    return identity
  }

  async requestH3BAuthorization({ message } = {}) {
    const session = this.requireSession()
    const authorizationMessage = assertMessage(message)
    return session.request({
      chainId: H3WC_CHAIN,
      request: { method: 'ecash_signMessage', params: { message: authorizationMessage } }
    })
  }

  async disconnect() {
    if (!this.session) return
    const topic = this.session.topic
    await this.signClient.disconnect({
      topic,
      reason: { code: 6000, message: 'H3WC client disconnected' }
    })
    this.session = null
    this.qualification = null
  }

  getState() {
    return Object.freeze({
      enabled: true,
      storagePrefix: this.options.storagePrefix,
      topic: this.qualification?.topic ?? null,
      account: this.qualification?.account ?? null,
      expiresAt: this.qualification?.expiresAt ?? null,
      qualification: this.qualification ? 'QUALIFIED' : 'NONE',
      lastUri: this.lastUri ?? null
    })
  }
}

export const createTonalliConnectClient = async ({
  projectId,
  metadata = {},
  storagePrefix = H3WC_STORAGE_PREFIX,
  requesterOrigin = H3WC_REQUESTER_ORIGIN,
  walletOrigin = H3WC_WALLET_ORIGIN,
  nowSeconds = () => Math.floor(Date.now() / 1000)
} = {}) => {
  const normalizedProjectId = assertProjectId(projectId)
  if (typeof nowSeconds !== 'function') throw new Error('H3WC clock is invalid')
  if (storagePrefix !== H3WC_STORAGE_PREFIX) throw new Error('H3WC storage prefix is fixed and cannot be changed')
  const normalizedRequesterOrigin = canonicalOrigin(requesterOrigin)
  const metadataOrigin = canonicalOrigin(metadata.url ?? normalizedRequesterOrigin)
  if (metadataOrigin !== normalizedRequesterOrigin) throw new Error('H3WC requester origin is not exact')
  const core = new Core({ projectId: normalizedProjectId, customStoragePrefix: storagePrefix })
  const signClient = await SignClient.init({
    core,
    metadata: {
      name: metadata.name ?? 'x402eCash H3WC',
      description: metadata.description ?? 'x402eCash authorization transport',
      url: metadataOrigin,
      icons: Array.isArray(metadata.icons) ? metadata.icons : []
    }
  })
  return new TonalliConnectClient(signClient, core, {
    storagePrefix,
    walletOrigin: canonicalOrigin(walletOrigin),
    nowSeconds
  })
}

export const __testing = Object.freeze({ canonicalIdentity, canonicalAccount, canonicalOrigin })
