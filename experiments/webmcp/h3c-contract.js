export const SOURCE_ORIGIN = 'https://x402.ecash.mx'
export const RETURN_URL = 'https://x402.ecash.mx/experiments/webmcp/'
export const LIVE_RESOURCE_URL = 'https://api.x402.ecash.mx/v1/resource/demo'
export const TONALLI_ORIGIN = 'https://app.tonalli.cash'
export const TONALLI_H3B_PATH = '/connect/x402-authorize'
export const H3C_HANDOFF_PATH = '/experiments/webmcp/h3c-handoff.html'
export const EXPECTED_PAYMENT_ERROR = 'PAYMENT-SIGNATURE header is required'
export const EXPECTED_PAY_TO = 'ecash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyquz9y96w'
export const H3C_TTL_SECONDS = 240
export const H3C_HANDOFF_TIMEOUT_MS = 3_000
export const H3C_CALLBACK_ACK_TIMEOUT_MS = H3C_TTL_SECONDS * 1_000
export const H3B_MAX_REQUEST_BASE64URL_LENGTH = 16_384
export const H3B_MAX_PROOF_BASE64URL_LENGTH = 32_768

const PAYMENT_REQUIRED_KEYS = ['x402Version', 'error', 'resource', 'accepts', 'extensions']
const RESOURCE_KEYS = ['url', 'description', 'mimeType', 'serviceName']
const ACCEPTANCE_KEYS = ['scheme', 'network', 'amount', 'asset', 'payTo', 'maxTimeoutSeconds', 'extra']
const EXTRA_KEYS = ['displayAmount', 'experimental', 'gate']
const H3B_REQUEST_KEYS = [
  'type',
  'version',
  'targetGate',
  'sourceOrigin',
  'returnUrl',
  'challengeId',
  'issuedAt',
  'expiresAt',
  'paymentRequired',
  'approval'
]
const H3A_APPROVAL_KEYS = ['status', 'gate', 'approved', 'performed']

export const isRecord = (value) => (
  typeof value === 'object' && value !== null && !Array.isArray(value)
)

const fail = (message) => {
  throw new Error(message)
}

export const requireExactKeys = (value, expected, context) => {
  if (!isRecord(value)) fail(`${context} must be an object`)
  const actual = Object.keys(value).sort()
  const wanted = [...expected].sort()
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    fail(`${context} contains missing or unknown fields`)
  }
}

const requireLiteral = (value, expected, message) => {
  if (value !== expected) fail(message)
  return expected
}

export const canonicalizeJson = (value) => {
  if (value === null) return 'null'
  if (typeof value === 'string' || typeof value === 'boolean') return JSON.stringify(value)
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('H3C canonical JSON contains a non-finite number')
    return Object.is(value, -0) ? '0' : JSON.stringify(value)
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJson(item)).join(',')}]`
  }
  if (isRecord(value)) {
    return `{${Object.keys(value).sort().map((key) => (
      `${JSON.stringify(key)}:${canonicalizeJson(value[key])}`
    )).join(',')}}`
  }
  return fail('H3C canonical JSON contains a non-JSON value')
}

export const encodeBase64UrlBytes = (bytes) => {
  if (!(bytes instanceof Uint8Array)) fail('Base64URL input must be bytes')
  let binary = ''
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/u, '')
}

export const decodeCanonicalBase64Url = (value, maximumLength = Number.MAX_SAFE_INTEGER) => {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > maximumLength ||
    value.length % 4 === 1 ||
    !/^[A-Za-z0-9_-]+$/u.test(value)
  ) {
    fail('Invalid canonical Base64URL')
  }

  const base64 = value.replace(/-/g, '+').replace(/_/g, '/')
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4)
  let binary
  try {
    binary = atob(padded)
  } catch {
    return fail('Invalid canonical Base64URL')
  }

  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0))
  if (encodeBase64UrlBytes(bytes) !== value) fail('Invalid canonical Base64URL')
  return bytes
}

export const encodeCanonicalBase64Url = (value) => (
  encodeBase64UrlBytes(new TextEncoder().encode(canonicalizeJson(value)))
)

export const decodeCanonicalJsonBase64Url = (value, maximumLength) => {
  let json
  try {
    json = new TextDecoder('utf-8', { fatal: true }).decode(
      decodeCanonicalBase64Url(value, maximumLength)
    )
  } catch {
    return fail('Base64URL payload is not valid UTF-8')
  }

  let parsed
  try {
    parsed = JSON.parse(json)
  } catch {
    return fail('Base64URL payload is not valid JSON')
  }

  if (canonicalizeJson(parsed) !== json) fail('Base64URL JSON payload is not canonical')
  return parsed
}

const decodeCanonicalBase64 = (value) => {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)
  ) {
    fail('PAYMENT-REQUIRED header is not valid Base64')
  }

  let binary
  try {
    binary = atob(value)
  } catch {
    return fail('PAYMENT-REQUIRED header is not valid Base64')
  }
  if (btoa(binary) !== value) fail('PAYMENT-REQUIRED header is not canonical Base64')
  return Uint8Array.from(binary, (character) => character.charCodeAt(0))
}

export const decodePaymentRequiredHeader = (encodedHeader) => {
  let decoded
  try {
    decoded = new TextDecoder('utf-8', { fatal: true }).decode(
      decodeCanonicalBase64(encodedHeader)
    )
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('PAYMENT-REQUIRED')) throw error
    return fail('PAYMENT-REQUIRED header is not valid UTF-8')
  }

  try {
    return JSON.parse(decoded)
  } catch {
    return fail('PAYMENT-REQUIRED header does not contain valid JSON')
  }
}

export const validatePaymentRequired = (paymentRequired) => {
  requireExactKeys(paymentRequired, PAYMENT_REQUIRED_KEYS, 'PAYMENT-REQUIRED')
  requireLiteral(paymentRequired.x402Version, 2, 'PAYMENT-REQUIRED x402Version must equal 2')
  requireLiteral(paymentRequired.error, EXPECTED_PAYMENT_ERROR, 'PAYMENT-REQUIRED error does not match Gate H2A')

  const resource = paymentRequired.resource
  requireExactKeys(resource, RESOURCE_KEYS, 'PAYMENT-REQUIRED resource')
  requireLiteral(resource.url, LIVE_RESOURCE_URL, 'PAYMENT-REQUIRED resource.url does not match the canonical resource')
  requireLiteral(resource.description, 'x402eCash WebMCP Challenge demo resource', 'PAYMENT-REQUIRED resource.description does not match')
  requireLiteral(resource.mimeType, 'application/json', 'PAYMENT-REQUIRED resource.mimeType must be application/json')
  requireLiteral(resource.serviceName, 'x402eCash', 'PAYMENT-REQUIRED resource.serviceName must be x402eCash')

  if (!Array.isArray(paymentRequired.accepts) || paymentRequired.accepts.length !== 1) {
    fail('PAYMENT-REQUIRED accepts must contain exactly one entry')
  }
  const acceptance = paymentRequired.accepts[0]
  requireExactKeys(acceptance, ACCEPTANCE_KEYS, 'PAYMENT-REQUIRED accepts[0]')
  requireLiteral(acceptance.scheme, 'xec-prepaid-utxo', 'PAYMENT-REQUIRED scheme must be xec-prepaid-utxo')
  requireLiteral(acceptance.network, 'xec:mainnet', 'PAYMENT-REQUIRED network must be xec:mainnet')
  requireLiteral(acceptance.amount, '10000', 'PAYMENT-REQUIRED amount must equal 10000')
  requireLiteral(acceptance.asset, 'XEC', 'PAYMENT-REQUIRED asset must be XEC')
  requireLiteral(acceptance.payTo, EXPECTED_PAY_TO, 'PAYMENT-REQUIRED payTo does not match the deterministic fixture')
  requireLiteral(acceptance.maxTimeoutSeconds, 60, 'PAYMENT-REQUIRED maxTimeoutSeconds must equal 60')

  const extra = acceptance.extra
  requireExactKeys(extra, EXTRA_KEYS, 'PAYMENT-REQUIRED accepts[0].extra')
  requireLiteral(extra.displayAmount, '100 XEC', 'PAYMENT-REQUIRED displayAmount must equal 100 XEC')
  requireLiteral(extra.experimental, true, 'PAYMENT-REQUIRED experimental must equal true')
  requireLiteral(extra.gate, 'H2A', 'PAYMENT-REQUIRED gate must equal H2A')

  requireExactKeys(paymentRequired.extensions, [], 'PAYMENT-REQUIRED extensions')
  return acceptance
}

const requireChallengeId = (challengeId) => {
  if (typeof challengeId !== 'string' || challengeId.length !== 43) {
    fail('H3C challengeId must be a canonical 32-byte Base64URL value')
  }
  if (decodeCanonicalBase64Url(challengeId, 43).byteLength !== 32) {
    fail('H3C challengeId must contain exactly 32 bytes')
  }
  return challengeId
}

export const generateChallengeId = (cryptoImplementation = globalThis.crypto) => {
  if (!cryptoImplementation || typeof cryptoImplementation.getRandomValues !== 'function') {
    fail('Secure random challenge generation is unavailable')
  }
  const bytes = new Uint8Array(32)
  cryptoImplementation.getRandomValues(bytes)
  const challengeId = encodeBase64UrlBytes(bytes)
  return requireChallengeId(challengeId)
}

export const sha256CanonicalJson = async (value, cryptoImplementation = globalThis.crypto) => {
  if (!cryptoImplementation?.subtle || typeof cryptoImplementation.subtle.digest !== 'function') {
    fail('Web Crypto SHA-256 is unavailable')
  }
  const digest = await cryptoImplementation.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(canonicalizeJson(value))
  )
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, '0')).join('')
}

export const createH3BRequest = ({
  paymentRequired,
  nowSeconds = Math.floor(Date.now() / 1000),
  cryptoImplementation = globalThis.crypto
}) => {
  validatePaymentRequired(paymentRequired)
  if (!Number.isSafeInteger(nowSeconds)) fail('H3C issuedAt must be a safe integer')
  const expiresAt = nowSeconds + H3C_TTL_SECONDS
  if (!Number.isSafeInteger(expiresAt)) fail('H3C expiresAt must be a safe integer')

  const request = {
    type: 'x402ecash-h3b-request',
    version: 1,
    targetGate: 'H3B',
    sourceOrigin: SOURCE_ORIGIN,
    returnUrl: RETURN_URL,
    challengeId: generateChallengeId(cryptoImplementation),
    issuedAt: nowSeconds,
    expiresAt,
    paymentRequired,
    approval: {
      status: 'payment_approved',
      gate: 'H3A',
      approved: true,
      performed: false
    }
  }
  requireExactKeys(request, H3B_REQUEST_KEYS, 'H3B request')
  const canonicalRequest = canonicalizeJson(request)
  const encodedRequest = encodeBase64UrlBytes(new TextEncoder().encode(canonicalRequest))
  if (encodedRequest.length > H3B_MAX_REQUEST_BASE64URL_LENGTH) {
    fail('Canonical H3B request exceeds the Tonalli transport limit')
  }

  return {
    request,
    canonicalRequest,
    encodedRequest
  }
}

export const validateH3BRequest = (request, nowSeconds = Math.floor(Date.now() / 1000)) => {
  requireExactKeys(request, H3B_REQUEST_KEYS, 'H3B request')
  requireLiteral(request.type, 'x402ecash-h3b-request', 'H3B request type is invalid')
  requireLiteral(request.version, 1, 'H3B request version is invalid')
  requireLiteral(request.targetGate, 'H3B', 'H3B targetGate is invalid')
  requireLiteral(request.sourceOrigin, SOURCE_ORIGIN, 'H3B sourceOrigin is invalid')
  requireLiteral(request.returnUrl, RETURN_URL, 'H3B returnUrl is invalid')
  requireChallengeId(request.challengeId)
  if (!Number.isSafeInteger(request.issuedAt) || !Number.isSafeInteger(request.expiresAt)) {
    fail('H3B request timestamps must be safe integers')
  }
  if (
    !Number.isSafeInteger(nowSeconds) ||
    request.expiresAt <= request.issuedAt ||
    request.expiresAt - request.issuedAt !== H3C_TTL_SECONDS ||
    request.expiresAt <= nowSeconds ||
    request.issuedAt > nowSeconds + 60 ||
    nowSeconds - request.issuedAt > 300
  ) {
    fail('H3B request is expired or has an invalid lifetime')
  }
  validatePaymentRequired(request.paymentRequired)
  requireExactKeys(request.approval, H3A_APPROVAL_KEYS, 'H3B approval')
  requireLiteral(request.approval.status, 'payment_approved', 'H3B approval status is invalid')
  requireLiteral(request.approval.gate, 'H3A', 'H3B approval gate is invalid')
  requireLiteral(request.approval.approved, true, 'H3B approval must be true')
  requireLiteral(request.approval.performed, false, 'H3B approval performed must be false')
  return request
}

export const parseH3BRequestTransport = ({ hash, search, nowSeconds }) => {
  if (search !== '') fail('H3B handoff does not accept query parameters')
  const match = /^#request=([A-Za-z0-9_-]+)$/u.exec(hash)
  if (!match) fail('H3B handoff fragment is invalid')
  const request = decodeCanonicalJsonBase64Url(match[1], H3B_MAX_REQUEST_BASE64URL_LENGTH)
  validateH3BRequest(request, nowSeconds)
  return { request, encodedRequest: match[1] }
}

export const isH3BCallbackAttempt = ({ hash, search }) => (
  /(?:^#|[&#])(?:h3bStatus|challengeId|proof)=/u.test(hash) ||
  /(?:^\?|[&])(?:h3bStatus|challengeId|proof)=/u.test(search)
)

export const parseH3BCallback = ({ hash, search }) => {
  if (search !== '') fail('H3B callback query parameters are not allowed')

  const signed = /^#h3bStatus=signed&challengeId=([A-Za-z0-9_-]+)&proof=([A-Za-z0-9_-]+)$/u.exec(hash)
  if (signed) {
    const challengeId = requireChallengeId(signed[1])
    if (signed[2].length > H3B_MAX_PROOF_BASE64URL_LENGTH) fail('H3B proof exceeds the maximum length')
    decodeCanonicalBase64Url(signed[2], H3B_MAX_PROOF_BASE64URL_LENGTH)
    return Object.freeze({ status: 'signed', challengeId, proof: signed[2] })
  }

  const rejected = /^#h3bStatus=rejected&challengeId=([A-Za-z0-9_-]+)$/u.exec(hash)
  if (rejected) {
    return Object.freeze({ status: 'rejected', challengeId: requireChallengeId(rejected[1]) })
  }

  return fail('H3B callback fragment is invalid')
}

export const recoverH3BCallbackChallenge = ({ hash, search }) => {
  const values = []
  for (const [value, marker] of [[hash, '#'], [search, '?']]) {
    if (typeof value !== 'string' || !value.startsWith(marker)) continue
    for (const field of value.slice(1).split('&')) {
      const match = /^challengeId=([A-Za-z0-9_-]+)$/u.exec(field)
      if (match) values.push(match[1])
    }
  }
  if (values.length === 0 || values.some((value) => value !== values[0])) {
    fail('H3B callback has no unambiguous challengeId')
  }
  return requireChallengeId(values[0])
}

export const decodeCanonicalH3BProof = (encodedProof) => {
  const proof = decodeCanonicalJsonBase64Url(encodedProof, H3B_MAX_PROOF_BASE64URL_LENGTH)
  if (!isRecord(proof)) fail('H3B proof must be an object')
  return proof
}

export const h3cChannelName = (challengeId) => `x402-h3c:${requireChallengeId(challengeId)}`

export const tonalliH3BUrl = (encodedRequest) => {
  decodeCanonicalBase64Url(encodedRequest, H3B_MAX_REQUEST_BASE64URL_LENGTH)
  return `${TONALLI_ORIGIN}${TONALLI_H3B_PATH}#request=${encodedRequest}`
}
