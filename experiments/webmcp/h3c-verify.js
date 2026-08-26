import {
  EXPECTED_PAY_TO,
  LIVE_RESOURCE_URL,
  SOURCE_ORIGIN,
  canonicalizeJson,
  decodeCanonicalBase64Url,
  decodeCanonicalH3BProof,
  requireExactKeys,
  sha256CanonicalJson
} from './h3c-contract.js'
import {
  decodeEcashAddress,
  deriveEcashP2pkhAddress,
  recoverEcashMessagePublicKey
} from './vendor/ecash-lib-4.5.2-verifier.js'

export const H3B_AUTHORIZATION_PREFIX = 'TONALLI_X402_H3B_AUTHORIZATION_PROOF_V1'

export const H3B_UNSIGNED_PROOF_KEYS = Object.freeze([
  'type',
  'version',
  'gate',
  'mode',
  'challengeId',
  'sourceOrigin',
  'resourceUrl',
  'paymentRequiredSha256',
  'x402Version',
  'scheme',
  'network',
  'asset',
  'amount',
  'displayAmount',
  'payTo',
  'payer',
  'publicKey',
  'issuedAt',
  'expiresAt',
  'paymentPerformed',
  'transactionCreated',
  'broadcasted'
])

export const H3B_SIGNED_PROOF_KEYS = Object.freeze([
  ...H3B_UNSIGNED_PROOF_KEYS,
  'authorizationMessage',
  'authorizationSignature'
])

const AUTHORIZATION_SIGNATURE_KEYS = Object.freeze(['type', 'publicKey', 'signature'])

const fail = (message) => {
  throw new Error(`H3C proof verification failed: ${message}`)
}

const requireLiteral = (value, expected, field) => {
  if (value !== expected) fail(`${field} mismatch`)
}

const requireSafeIntegerMatch = (value, expected, field) => {
  if (!Number.isSafeInteger(value) || value !== expected) fail(`${field} mismatch`)
}

const isCompressedPublicKey = (value) => /^(02|03)[0-9a-f]{64}$/u.test(value)

const decodeCanonicalMessageSignature = (signature) => {
  if (
    typeof signature !== 'string' ||
    signature.length !== 88 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(signature)
  ) {
    fail('authorizationSignature.signature is not canonical Base64')
  }

  let binary
  try {
    binary = atob(signature)
  } catch {
    return fail('authorizationSignature.signature is not canonical Base64')
  }
  if (btoa(binary) !== signature) fail('authorizationSignature.signature is not canonical Base64')

  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0))
  if (bytes.byteLength !== 65 || bytes[0] < 31 || bytes[0] > 34) {
    fail('authorizationSignature.signature is not a compressed recoverable eCash signature')
  }
  return bytes
}

export const buildH3BAuthorizationMessage = (unsignedProof) => (
  `${H3B_AUTHORIZATION_PREFIX}\n${canonicalizeJson(unsignedProof)}`
)

const unsignedProofFrom = (proof) => {
  const unsignedProof = {}
  for (const key of H3B_UNSIGNED_PROOF_KEYS) unsignedProof[key] = proof[key]
  requireExactKeys(unsignedProof, H3B_UNSIGNED_PROOF_KEYS, 'H3B unsigned proof')
  return unsignedProof
}

const validateSignedProofSchema = (proof, rendezvous) => {
  requireExactKeys(proof, H3B_SIGNED_PROOF_KEYS, 'H3B signed proof')
  requireLiteral(proof.type, 'tonalli-x402-authorization-proof', 'type')
  requireLiteral(proof.version, 1, 'version')
  requireLiteral(proof.gate, 'H3B', 'gate')
  requireLiteral(proof.mode, 'authorization-dry-run', 'mode')
  requireLiteral(proof.challengeId, rendezvous.challengeId, 'challengeId')
  decodeCanonicalBase64Url(proof.challengeId, 43)
  requireLiteral(proof.sourceOrigin, SOURCE_ORIGIN, 'sourceOrigin')
  requireLiteral(proof.resourceUrl, LIVE_RESOURCE_URL, 'resourceUrl')
  if (!/^[0-9a-f]{64}$/u.test(proof.paymentRequiredSha256)) {
    fail('paymentRequiredSha256 is not lowercase SHA-256 hex')
  }
  requireLiteral(proof.x402Version, 2, 'x402Version')
  requireLiteral(proof.scheme, 'xec-prepaid-utxo', 'scheme')
  requireLiteral(proof.network, 'xec:mainnet', 'network')
  requireLiteral(proof.asset, 'XEC', 'asset')
  requireLiteral(proof.amount, '10000', 'amount')
  requireLiteral(proof.displayAmount, '100 XEC', 'displayAmount')
  requireLiteral(proof.payTo, EXPECTED_PAY_TO, 'payTo')

  if (
    typeof proof.payer !== 'string' ||
    proof.payer !== proof.payer.trim() ||
    proof.payer.length > 128
  ) {
    fail('payer is invalid')
  }
  if (!isCompressedPublicKey(proof.publicKey)) fail('publicKey is not canonical compressed secp256k1 hex')
  requireSafeIntegerMatch(proof.issuedAt, rendezvous.issuedAt, 'issuedAt')
  requireSafeIntegerMatch(proof.expiresAt, rendezvous.expiresAt, 'expiresAt')
  requireLiteral(proof.paymentPerformed, false, 'paymentPerformed')
  requireLiteral(proof.transactionCreated, false, 'transactionCreated')
  requireLiteral(proof.broadcasted, false, 'broadcasted')

  if (typeof proof.authorizationMessage !== 'string' || proof.authorizationMessage.length === 0) {
    fail('authorizationMessage is empty')
  }
  requireExactKeys(
    proof.authorizationSignature,
    AUTHORIZATION_SIGNATURE_KEYS,
    'authorizationSignature'
  )
  requireLiteral(
    proof.authorizationSignature.type,
    'tonalli-message-signature',
    'authorizationSignature.type'
  )
  requireLiteral(
    proof.authorizationSignature.publicKey,
    proof.publicKey,
    'authorizationSignature.publicKey'
  )
  return proof
}

const verifySignatureAndPayer = (proof) => {
  const signatureBytes = decodeCanonicalMessageSignature(proof.authorizationSignature.signature)
  let recoveredPublicKey
  try {
    recoveredPublicKey = recoverEcashMessagePublicKey(
      proof.authorizationMessage,
      signatureBytes
    )
  } catch {
    return fail('recoverable secp256k1 signature is invalid')
  }

  const recoveredPublicKeyHex = recoveredPublicKey.hex
  if (recoveredPublicKeyHex !== proof.publicKey) {
    fail('signature does not recover the declared publicKey')
  }

  let decodedPayer
  try {
    decodedPayer = decodeEcashAddress(proof.payer)
  } catch {
    return fail('payer is not a valid eCash CashAddr')
  }
  if (decodedPayer.prefix !== 'ecash' || decodedPayer.type !== 'p2pkh') {
    fail('payer must be an ecash P2PKH address')
  }

  const derivedPayer = deriveEcashP2pkhAddress(recoveredPublicKey.bytes)
  if (derivedPayer !== proof.payer) fail('payer does not derive from the recovered publicKey')
  return { recoveredPublicKeyHex, derivedPayer }
}

export const verifySignedH3BProof = async ({
  encodedProof,
  rendezvous,
  cryptoImplementation = globalThis.crypto,
  nowSeconds = Math.floor(Date.now() / 1000)
}) => {
  if (
    !rendezvous ||
    typeof rendezvous !== 'object' ||
    !Number.isSafeInteger(nowSeconds) ||
    nowSeconds >= rendezvous.expiresAt
  ) {
    fail('authorization request is unavailable or expired')
  }

  const proof = validateSignedProofSchema(decodeCanonicalH3BProof(encodedProof), rendezvous)
  const paymentRequiredSha256 = await sha256CanonicalJson(
    rendezvous.paymentRequired,
    cryptoImplementation
  )
  if (
    paymentRequiredSha256 !== rendezvous.paymentRequiredSha256 ||
    paymentRequiredSha256 !== proof.paymentRequiredSha256
  ) {
    fail('paymentRequiredSha256 does not bind the original live requirement')
  }

  const unsignedProof = unsignedProofFrom(proof)
  const authorizationMessage = buildH3BAuthorizationMessage(unsignedProof)
  if (authorizationMessage !== proof.authorizationMessage) {
    fail('authorizationMessage does not match the canonical unsigned proof')
  }

  const binding = verifySignatureAndPayer(proof)
  return Object.freeze({
    proof,
    publicKey: binding.recoveredPublicKeyHex,
    payer: binding.derivedPayer,
    paymentRequiredSha256
  })
}
