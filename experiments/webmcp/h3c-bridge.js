import {
  H3C_HANDOFF_PATH,
  H3C_HANDOFF_TIMEOUT_MS,
  canonicalizeJson,
  createH3BRequest,
  h3cChannelName,
  isRecord,
  requireExactKeys,
  sha256CanonicalJson,
  validatePaymentRequired
} from './h3c-contract.js'
import { verifySignedH3BProof } from './h3c-verify.js'

export const H3C_STATES = Object.freeze([
  'idle',
  'approval-required',
  'handoff-opening',
  'awaiting-tonalli',
  'proof-verifying',
  'verified',
  'rejected',
  'failed',
  'expired'
])

const LIVE_STATES = new Set(['approval-required', 'handoff-opening', 'awaiting-tonalli', 'proof-verifying'])
const RENDEZVOUS_LIVE_STATES = new Set(['handoff-opening', 'awaiting-tonalli', 'proof-verifying'])
const HANDOFF_OPENED_KEYS = Object.freeze(['type', 'challengeId'])
const SIGNED_CALLBACK_KEYS = Object.freeze(['type', 'challengeId', 'status', 'proof'])
const REJECTED_CALLBACK_KEYS = Object.freeze(['type', 'challengeId', 'status'])
const APPROVAL_BINDING_KEYS = Object.freeze(['generation', 'paymentRequiredFingerprint'])

const errorMessage = (error) => {
  if (error instanceof Error && error.message) return error.message
  if (typeof error === 'string' && error) return error
  return 'Unknown H3C error'
}

const exactMessage = (message, keys) => {
  if (!isRecord(message)) return false
  try {
    requireExactKeys(message, keys, 'H3C channel message')
    return true
  } catch {
    return false
  }
}

const firstToolApprovalRequiredResult = () => Object.freeze({
  status: 'approval_required',
  gate: 'H3A',
  httpStatus: 402,
  message: 'The live 100 XEC requirement was validated and is awaiting a human decision. No payment was performed.',
  approval: Object.freeze({
    required: true,
    decided: false,
    required_amount: '100 XEC'
  }),
  payment: Object.freeze({ performed: false })
})

const resultToolApprovalRequiredResult = () => Object.freeze({
  status: 'approval_required',
  gate: 'H3A',
  approval: Object.freeze({
    required: true,
    decided: false,
    required_amount: '100 XEC'
  }),
  payment: Object.freeze({ performed: false })
})

const resultToolPendingResult = (rendezvous) => Object.freeze({
  status: 'authorization_pending',
  gate: 'H3C',
  challengeId: rendezvous.challengeId,
  authorization: Object.freeze({
    wallet: 'Tonalli',
    signed: false,
    verified: false,
    pending: true
  }),
  payment: Object.freeze({ performed: false }),
  transaction: Object.freeze({ created: false, broadcasted: false })
})

const humanRejectedResult = () => Object.freeze({
  status: 'authorization_rejected',
  gate: 'H3A',
  authorization: Object.freeze({ signed: false, verified: false }),
  payment: Object.freeze({ performed: false }),
  transaction: Object.freeze({ created: false, broadcasted: false })
})

const rejectedResult = (rendezvous) => Object.freeze({
  status: 'authorization_rejected',
  gate: 'H3C',
  challengeId: rendezvous.challengeId,
  authorization: Object.freeze({ signed: false, verified: false }),
  payment: Object.freeze({ performed: false }),
  transaction: Object.freeze({ created: false, broadcasted: false })
})

const verifiedResult = (rendezvous, verification) => Object.freeze({
  status: 'authorization_verified',
  gate: 'H3C',
  challengeId: rendezvous.challengeId,
  authorization: Object.freeze({
    wallet: 'Tonalli',
    signed: true,
    verified: true,
    mode: 'authorization-dry-run',
    payer: verification.payer,
    publicKey: verification.publicKey,
    paymentRequiredSha256: verification.paymentRequiredSha256
  }),
  payment: Object.freeze({ performed: false }),
  transaction: Object.freeze({ created: false, broadcasted: false }),
  resource: Object.freeze({ unlocked: false })
})

export const createH3CBridge = ({
  BroadcastChannelImplementation = globalThis.BroadcastChannel,
  openWindow = (url) => globalThis.window?.open(url, '_blank', 'noopener,noreferrer'),
  cryptoImplementation = globalThis.crypto,
  nowSeconds = () => Math.floor(Date.now() / 1000),
  setTimeoutImplementation = globalThis.setTimeout.bind(globalThis),
  clearTimeoutImplementation = globalThis.clearTimeout.bind(globalThis),
  handoffTimeoutMs = H3C_HANDOFF_TIMEOUT_MS,
  handoffPath = H3C_HANDOFF_PATH,
  verifyProof = verifySignedH3BProof,
  addTraceEvent = () => {},
  onStateChange = () => {}
} = {}) => {
  let rendezvous = null
  let starting = false
  let nextGeneration = 1

  const notifyState = () => {
    try { onStateChange(api.getSnapshot()) } catch {}
  }

  const transition = (current, state) => {
    if (!H3C_STATES.includes(state)) throw new Error('H3C internal state corruption')
    if (rendezvous !== current) throw new Error('H3C rendezvous is no longer current')
    current.state = state
    notifyState()
  }

  const clearExpiry = (current) => {
    if (current.expiryTimer !== null) {
      clearTimeoutImplementation(current.expiryTimer)
      current.expiryTimer = null
    }
  }

  const closeChannel = (current) => {
    if (!current.channel) return
    try { current.channel.close() } catch {}
    current.channel = null
  }

  const closeChannelAfterAck = (current) => {
    setTimeoutImplementation(() => {
      if (rendezvous === current) closeChannel(current)
    }, 0)
  }

  const approvalBinding = (current) => Object.freeze({
    generation: current.generation,
    paymentRequiredFingerprint: current.paymentRequiredFingerprint
  })

  const requireCurrentApproval = (binding) => {
    requireExactKeys(binding, APPROVAL_BINDING_KEYS, 'H3A approval binding')
    if (
      !rendezvous ||
      rendezvous.state !== 'approval-required' ||
      rendezvous.generation !== binding.generation ||
      rendezvous.paymentRequiredFingerprint !== binding.paymentRequiredFingerprint ||
      canonicalizeJson(rendezvous.paymentRequired) !== rendezvous.paymentRequiredFingerprint
    ) {
      throw new Error('Gate H3A approval state no longer matches the validated payment requirement')
    }
    return rendezvous
  }

  const failCurrent = (current, error, trace = true) => {
    if (rendezvous !== current) return
    current.error = errorMessage(error)
    current.state = 'failed'
    clearExpiry(current)
    closeChannel(current)
    if (trace) addTraceEvent(`H3C failed closed: ${current.error}`, 'error')
    notifyState()
  }

  const postAck = (current, accepted, verified) => {
    if (!current.channel) return
    try {
      current.channel.postMessage({
        type: 'h3c-ack',
        challengeId: current.challengeId,
        accepted,
        verified
      })
    } catch {}
  }

  const acknowledgeHandoff = (current) => {
    if (!current.channel) throw new Error('H3C handoff channel is unavailable')
    try {
      current.channel.postMessage({
        type: 'h3c-handoff-accepted',
        challengeId: current.challengeId
      })
    } catch {
      throw new Error('H3C could not acknowledge the same-origin handoff')
    }
  }

  const expireCurrent = (current, acknowledge = false) => {
    if (rendezvous !== current || !RENDEZVOUS_LIVE_STATES.has(current.state)) return
    current.callbackConsumed = true
    current.state = 'expired'
    current.error = 'H3C authorization request expired'
    clearExpiry(current)
    addTraceEvent('H3C authorization request expired', 'error')
    if (acknowledge) {
      postAck(current, false, false)
      closeChannelAfterAck(current)
    } else {
      closeChannel(current)
    }
    notifyState()
  }

  const finalizeRejected = (current) => {
    if (rendezvous !== current) return
    current.result = rejectedResult(current)
    transition(current, 'rejected')
    clearExpiry(current)
    addTraceEvent('Tonalli authorization request rejected')
    addTraceEvent('STOP - Nothing signed and no payment performed')
    postAck(current, true, false)
    closeChannelAfterAck(current)
  }

  const finalizeSigned = async (current, encodedProof) => {
    addTraceEvent('Tonalli Authorization Proof received')
    try {
      const verification = await verifyProof({
        encodedProof,
        rendezvous: current,
        cryptoImplementation,
        nowSeconds: nowSeconds()
      })
      if (rendezvous !== current || current.state === 'expired') return
      if (nowSeconds() >= current.expiresAt) {
        expireCurrent(current, true)
        return
      }
      if (current.state !== 'proof-verifying') {
        throw new Error('H3C rendezvous changed during proof verification')
      }
      current.result = verifiedResult(current, verification)
      transition(current, 'verified')
      clearExpiry(current)
      addTraceEvent('Tonalli Authorization Proof cryptographically verified', 'success')
      addTraceEvent('Payment requirement binding verified', 'success')
      addTraceEvent('Payment performed: false')
      addTraceEvent('Transaction created: false')
      addTraceEvent('Broadcasted: false')
      addTraceEvent('STOP - Authorization proof complete; payment execution not implemented')
      postAck(current, true, true)
      closeChannelAfterAck(current)
    } catch (error) {
      if (rendezvous !== current || current.state === 'expired') return
      current.error = errorMessage(error)
      current.state = 'failed'
      clearExpiry(current)
      addTraceEvent(`Tonalli authorization proof rejected: ${current.error}`, 'error')
      postAck(current, false, false)
      notifyState()
      closeChannelAfterAck(current)
    }
  }

  const receiveCallback = (current, message) => {
    if (rendezvous !== current || !isRecord(message)) return
    if (message.type !== 'h3c-callback' || message.challengeId !== current.challengeId) return

    const receivedAt = nowSeconds()
    if (current.state !== 'awaiting-tonalli' || current.callbackConsumed) {
      postAck(current, false, false)
      return
    }
    if (receivedAt >= current.expiresAt) {
      expireCurrent(current, true)
      return
    }

    const keys = message.status === 'signed' ? SIGNED_CALLBACK_KEYS : REJECTED_CALLBACK_KEYS
    if (
      (message.status !== 'signed' && message.status !== 'rejected') ||
      !exactMessage(message, keys)
    ) {
      if (
        current.state === 'awaiting-tonalli' &&
        !current.callbackConsumed
      ) {
        current.callbackConsumed = true
        current.error = 'Tonalli callback message is malformed'
        current.state = 'failed'
        clearExpiry(current)
        addTraceEvent(`Tonalli authorization callback rejected: ${current.error}`, 'error')
        postAck(current, false, false)
        notifyState()
        closeChannelAfterAck(current)
        return
      }
      postAck(current, false, false)
      return
    }

    current.callbackConsumed = true
    transition(current, 'proof-verifying')
    if (message.status === 'rejected') {
      finalizeRejected(current)
      return
    }
    void finalizeSigned(current, message.proof)
  }

  const receiveChannelMessage = (current, message) => {
    if (rendezvous !== current || !isRecord(message)) return
    if (
      current.state === 'handoff-opening' &&
      exactMessage(message, HANDOFF_OPENED_KEYS) &&
      message.type === 'h3c-handoff-opened' &&
      message.challengeId === current.challengeId
    ) {
      current.handshakeResolve?.()
      return
    }
    receiveCallback(current, message)
  }

  const scheduleExpiry = (current) => {
    const delayMilliseconds = Math.max(0, (current.expiresAt - nowSeconds()) * 1_000)
    current.expiryTimer = setTimeoutImplementation(() => {
      expireCurrent(current)
    }, delayMilliseconds)
  }

  const replaceTerminalRendezvous = () => {
    if (!rendezvous) return false
    if (LIVE_STATES.has(rendezvous.state) || starting) {
      throw new Error('A Gate H3A/H3C session is already pending.')
    }
    clearExpiry(rendezvous)
    closeChannel(rendezvous)
    rendezvous = null
    notifyState()
    addTraceEvent('Previous terminal authorization session reset for a new validated resource request')
    return true
  }

  const createApprovalSession = ({ paymentRequired } = {}) => {
    validatePaymentRequired(paymentRequired)
    if (starting || (rendezvous && LIVE_STATES.has(rendezvous.state))) {
      throw new Error('A Gate H3A/H3C session is already pending.')
    }
    const createdAt = nowSeconds()
    if (!Number.isSafeInteger(createdAt)) {
      throw new Error('Gate H3A approval createdAt must be a safe integer')
    }
    const paymentRequiredFingerprint = canonicalizeJson(paymentRequired)
    replaceTerminalRendezvous()
    const current = {
      generation: nextGeneration,
      createdAt,
      paymentRequired,
      paymentRequiredFingerprint,
      challengeId: null,
      issuedAt: null,
      expiresAt: null,
      canonicalRequest: null,
      encodedRequest: null,
      paymentRequiredSha256: null,
      state: 'approval-required',
      callbackConsumed: false,
      channel: null,
      expiryTimer: null,
      handshakeResolve: null,
      result: null,
      error: null
    }
    nextGeneration += 1
    rendezvous = current
    notifyState()
    return Object.freeze({
      binding: approvalBinding(current),
      result: firstToolApprovalRequiredResult()
    })
  }

  const validateApproval = (binding) => {
    const current = requireCurrentApproval(binding)
    return Object.freeze({
      generation: current.generation,
      createdAt: current.createdAt,
      paymentRequiredFingerprint: current.paymentRequiredFingerprint,
      state: current.state
    })
  }

  const rejectApproval = (binding) => {
    const current = requireCurrentApproval(binding)
    current.result = humanRejectedResult()
    transition(current, 'rejected')
    addTraceEvent('Human decision: REJECTED')
    addTraceEvent('STOP - Payment not authorized')
    return current.result
  }

  const failApprovalSession = (binding, error) => {
    requireExactKeys(binding, APPROVAL_BINDING_KEYS, 'H3A approval binding')
    if (
      !rendezvous ||
      rendezvous.state !== 'approval-required' ||
      rendezvous.generation !== binding.generation ||
      rendezvous.paymentRequiredFingerprint !== binding.paymentRequiredFingerprint
    ) {
      throw new Error('Gate H3A approval session is no longer current')
    }
    const current = rendezvous
    failCurrent(current, error)
  }

  const startHandoff = async (binding) => {
    const approval = requireCurrentApproval(binding)
    if (starting) throw new Error('An H3C authorization rendezvous is already pending.')
    starting = true
    let current = approval
    try {
      if (typeof BroadcastChannelImplementation !== 'function') {
        throw new Error('BroadcastChannel is unavailable; H3C cannot start safely.')
      }
      if (!cryptoImplementation?.subtle || typeof cryptoImplementation.subtle.digest !== 'function') {
        throw new Error('Web Crypto SHA-256 is unavailable; H3C cannot start safely.')
      }
      const created = createH3BRequest({
        paymentRequired: current.paymentRequired,
        nowSeconds: nowSeconds(),
        cryptoImplementation
      })

      let channel
      try {
        channel = new BroadcastChannelImplementation(h3cChannelName(created.request.challengeId))
      } catch {
        throw new Error('BroadcastChannel initialization failed; H3C stopped safely.')
      }

      current.challengeId = created.request.challengeId
      current.issuedAt = created.request.issuedAt
      current.expiresAt = created.request.expiresAt
      current.canonicalRequest = created.canonicalRequest
      current.encodedRequest = created.encodedRequest
      current.paymentRequiredSha256 = null
      current.callbackConsumed = false
      current.channel = channel
      current.expiryTimer = null
      current.handshakeResolve = null
      current.result = null
      current.error = null
      transition(current, 'handoff-opening')
      channel.onmessage = (event) => receiveChannelMessage(current, event.data)
      scheduleExpiry(current)
      addTraceEvent('H3B challenge created')

      const handoffAcknowledgement = new Promise((resolve, reject) => {
        let settled = false
        const timeout = setTimeoutImplementation(() => {
          settle(reject, new Error('Tonalli authorization handoff did not acknowledge opening.'))
        }, handoffTimeoutMs)

        const cleanup = () => {
          clearTimeoutImplementation(timeout)
          current.handshakeResolve = null
        }
        const settle = (handler, value) => {
          if (settled) return
          settled = true
          cleanup()
          handler(value)
        }

        current.handshakeResolve = () => {
          if (settled || rendezvous !== current || current.state !== 'handoff-opening') return
          settle(resolve)
        }
        try {
          openWindow(`${handoffPath}#request=${created.encodedRequest}`)
        } catch (error) {
          settle(reject, new Error(`Tonalli authorization handoff could not open: ${errorMessage(error)}`))
          return
        }
      })

      const paymentRequiredSha256Promise = sha256CanonicalJson(
        current.paymentRequired,
        cryptoImplementation
      )
      const [, paymentRequiredSha256] = await Promise.all([
        handoffAcknowledgement,
        paymentRequiredSha256Promise
      ])
      if (nowSeconds() >= current.expiresAt) {
        expireCurrent(current)
        throw new Error('H3C authorization request expired before handoff acknowledgement')
      }
      current.paymentRequiredSha256 = paymentRequiredSha256
      if (rendezvous !== current || current.state !== 'handoff-opening') {
        throw new Error('H3C rendezvous changed while binding the payment requirement')
      }
      transition(current, 'awaiting-tonalli')
      acknowledgeHandoff(current)

      addTraceEvent('Tonalli authorization handoff opened', 'success')
      addTraceEvent('STOP - Awaiting Tonalli authorization proof')
      return resultToolPendingResult(current)
    } catch (error) {
      if (current && current.state !== 'expired') failCurrent(current, error)
      throw error
    } finally {
      starting = false
    }
  }

  const readResult = () => {
    if (!rendezvous) throw new Error('No ephemeral H3A/H3C authorization session exists.')
    if (
      RENDEZVOUS_LIVE_STATES.has(rendezvous.state) &&
      nowSeconds() >= rendezvous.expiresAt
    ) {
      expireCurrent(rendezvous)
    }
    if (rendezvous.state === 'approval-required') {
      return resultToolApprovalRequiredResult()
    }
    if (rendezvous.state === 'verified' || rendezvous.state === 'rejected') {
      if (!rendezvous.result) throw new Error('H3C terminal state is missing its result.')
      return rendezvous.result
    }
    if (RENDEZVOUS_LIVE_STATES.has(rendezvous.state)) return resultToolPendingResult(rendezvous)
    if (rendezvous.state === 'expired') throw new Error('The H3C authorization session expired.')
    throw new Error(`The H3C authorization session failed closed: ${rendezvous.error ?? 'unknown error'}`)
  }

  const hasLiveSession = () => {
    if (
      rendezvous &&
      RENDEZVOUS_LIVE_STATES.has(rendezvous.state) &&
      nowSeconds() >= rendezvous.expiresAt
    ) {
      expireCurrent(rendezvous)
    }
    return starting || Boolean(rendezvous && LIVE_STATES.has(rendezvous.state))
  }

  const api = Object.freeze({
    createApprovalSession,
    validateApproval,
    rejectApproval,
    failApprovalSession,
    startHandoff,
    readResult,
    hasLiveSession,
    hasLiveRendezvous: () => {
      if (
        rendezvous &&
        RENDEZVOUS_LIVE_STATES.has(rendezvous.state) &&
        nowSeconds() >= rendezvous.expiresAt
      ) {
        expireCurrent(rendezvous)
      }
      return starting || Boolean(rendezvous && RENDEZVOUS_LIVE_STATES.has(rendezvous.state))
    },
    getSnapshot: () => Object.freeze({
      state: starting && !rendezvous ? 'handoff-opening' : (rendezvous?.state ?? 'idle'),
      generation: rendezvous?.generation ?? null,
      createdAt: rendezvous?.createdAt ?? null,
      paymentRequiredFingerprint: rendezvous?.paymentRequiredFingerprint ?? null,
      challengeId: rendezvous?.challengeId ?? null,
      issuedAt: rendezvous?.issuedAt ?? null,
      expiresAt: rendezvous?.expiresAt ?? null,
      callbackConsumed: rendezvous?.callbackConsumed ?? false,
      error: rendezvous?.error ?? null
    }),
    dispose: () => {
      if (!rendezvous) return
      clearExpiry(rendezvous)
      closeChannel(rendezvous)
      rendezvous = null
      starting = false
      notifyState()
    }
  })

  return api
}
