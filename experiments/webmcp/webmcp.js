import {
  H3C_CALLBACK_ACK_TIMEOUT_MS,
  LIVE_RESOURCE_URL,
  canonicalizeJson,
  decodePaymentRequiredHeader,
  h3cChannelName,
  isRecord,
  parseH3BCallback,
  recoverH3BCallbackChallenge,
  requireExactKeys,
  validatePaymentRequired
} from './h3c-contract.js'
import { createH3CBridge } from './h3c-bridge.js'

const RESOURCE_TOOL_NAME = 'get_paid_xec_resource'
const RESULT_TOOL_NAME = 'get_x402_authorization_result'
const RESOURCE_TOOL_DESCRIPTION = 'Validate the live experimental 100 XEC HTTP 402 requirement, ask for human approval, and initiate the Tonalli H3B authorization-only handoff. No payment is performed.'
const RESULT_TOOL_DESCRIPTION = 'Read the current ephemeral Gate H3C authorization state. This tool never initiates signing or payment.'

const traceLog = document.querySelector('[data-trace-log]')
const capabilityState = document.querySelector('[data-webmcp-state]')
const capabilityStatus = document.querySelector('[data-webmcp-status]')
const capabilityDetail = document.querySelector('[data-webmcp-detail]')
const approvalRegion = document.querySelector('[data-approval-region]')
const approvalMount = document.querySelector('[data-approval-mount]')
const approvalTemplate = document.querySelector('[data-approval-template]')
const rendezvousRegion = document.querySelector('[data-rendezvous-region]')
const rendezvousState = document.querySelector('[data-rendezvous-state]')
const rendezvousChallenge = document.querySelector('[data-rendezvous-challenge]')
const rendezvousExpiry = document.querySelector('[data-rendezvous-expiry]')
const callbackRegion = document.querySelector('[data-callback-region]')
const callbackTitle = document.querySelector('[data-callback-title]')
const callbackDetail = document.querySelector('[data-callback-detail]')
const callbackClose = document.querySelector('[data-callback-close]')

let activeExecution = null
let pendingApproval = null

const localTimestamp = () => {
  const now = new Date()
  return [now.getHours(), now.getMinutes(), now.getSeconds()]
    .map((part) => String(part).padStart(2, '0'))
    .join(':')
}

const addTraceEvent = (message, kind = 'info') => {
  if (!traceLog) return
  traceLog.querySelector('[data-trace-placeholder]')?.remove()
  const item = document.createElement('li')
  item.dataset.kind = kind
  item.textContent = `[${localTimestamp()}] ${message}`
  traceLog.append(item)
}

const setCapabilityState = (state, status, detail) => {
  capabilityState?.setAttribute('data-webmcp-state', state)
  if (capabilityStatus) capabilityStatus.textContent = status
  if (capabilityDetail) capabilityDetail.textContent = detail
}

const errorMessage = (error) => {
  if (error instanceof Error && error.message) return error.message
  if (typeof error === 'string' && error) return error
  return 'Unknown error'
}

const requireEmptyInput = (input) => {
  if (input === undefined) return
  if (!isRecord(input) || Object.keys(input).length !== 0) {
    throw new Error('This WebMCP tool accepts only an empty object.')
  }
}

const requireValidAbortSignal = (signal) => {
  if (signal === undefined || signal === null) return
  if (
    typeof signal.aborted !== 'boolean' ||
    typeof signal.addEventListener !== 'function' ||
    typeof signal.removeEventListener !== 'function'
  ) {
    throw new Error('Gate H3C received an invalid AbortSignal')
  }
}

const createAbortError = () => {
  const error = new Error('Human approval cancelled because the tool execution was aborted')
  error.name = 'AbortError'
  return error
}

const requireApprovalSurface = () => {
  if (
    !approvalRegion ||
    !approvalMount ||
    typeof approvalMount.replaceChildren !== 'function' ||
    !approvalTemplate?.content ||
    typeof approvalTemplate.content.cloneNode !== 'function'
  ) {
    throw new Error('Gate H3A approval UI is unavailable')
  }
}

const resetApprovalSurface = () => {
  requireApprovalSurface()
  approvalRegion.hidden = true
  approvalMount.replaceChildren()
}

const createApprovalCard = (acceptance) => {
  requireApprovalSurface()
  const fragment = approvalTemplate.content.cloneNode(true)
  const card = fragment.querySelector('[data-approval-card]')
  const amount = fragment.querySelector('[data-approval-amount]')
  const network = fragment.querySelector('[data-approval-network]')
  const asset = fragment.querySelector('[data-approval-asset]')
  const destination = fragment.querySelector('[data-approval-destination]')
  const experimental = fragment.querySelector('[data-approval-experimental]')
  const rejectButton = fragment.querySelector('[data-approval-reject]')
  const approveButton = fragment.querySelector('[data-approval-approve]')
  const status = fragment.querySelector('[data-approval-status]')

  if (
    !card ||
    !amount ||
    !network ||
    !asset ||
    !destination ||
    !experimental ||
    !rejectButton ||
    !approveButton ||
    !status ||
    typeof card.focus !== 'function' ||
    typeof rejectButton.addEventListener !== 'function' ||
    typeof rejectButton.removeEventListener !== 'function' ||
    typeof approveButton.addEventListener !== 'function' ||
    typeof approveButton.removeEventListener !== 'function'
  ) {
    throw new Error('Gate H3A approval UI is incomplete')
  }

  amount.textContent = acceptance.extra.displayAmount
  network.textContent = acceptance.network
  asset.textContent = acceptance.asset
  destination.textContent = acceptance.payTo
  experimental.textContent = acceptance.extra.experimental ? 'Yes' : 'No'
  approveButton.textContent = `Approve ${acceptance.extra.displayAmount}`
  return { fragment, card, rejectButton, approveButton, status }
}

const requestHumanApproval = (
  paymentRequired,
  acceptance,
  signal,
  executionToken,
  beginApprovedHandoff
) => {
  if (pendingApproval !== null) throw new Error('An approval decision is already pending.')
  const requirementFingerprint = canonicalizeJson(paymentRequired)
  const ui = createApprovalCard(acceptance)

  approvalMount.replaceChildren(ui.fragment)
  approvalRegion.hidden = false
  ui.card.focus()

  return new Promise((resolve, reject) => {
    let settled = false

    const cleanup = () => {
      try { ui.rejectButton.removeEventListener('click', handleReject) } catch {}
      try { ui.approveButton.removeEventListener('click', handleApprove) } catch {}
      try { signal?.removeEventListener('abort', handleAbort) } catch {}
      ui.rejectButton.disabled = true
      ui.approveButton.disabled = true
      if (pendingApproval?.token === executionToken) pendingApproval = null
    }

    const settle = (outcome, value) => {
      if (settled) return
      settled = true
      cleanup()
      if (outcome === 'resolve') {
        ui.card.dataset.approvalState = value
        ui.status.textContent = value === 'approved'
          ? 'Approval recorded. Opening the authorization-only Tonalli handoff; no payment is being sent.'
          : 'Request rejected. No payment was authorized.'
        resolve(value)
        return
      }
      ui.card.dataset.approvalState = 'cancelled'
      ui.status.textContent = errorMessage(value)
      approvalRegion.hidden = true
      approvalMount.replaceChildren()
      reject(value)
    }

    const validateCurrentRequest = () => {
      if (
        pendingApproval?.token !== executionToken ||
        pendingApproval.requirement !== paymentRequired ||
        pendingApproval.fingerprint !== requirementFingerprint ||
        canonicalizeJson(paymentRequired) !== requirementFingerprint
      ) {
        settle('reject', new Error('Gate H3A approval state no longer matches the validated payment requirement'))
        return false
      }
      return true
    }

    function handleReject () {
      if (settled || !validateCurrentRequest()) return
      settle('resolve', 'rejected')
    }

    function handleApprove () {
      if (settled || !validateCurrentRequest()) return
      try {
        beginApprovedHandoff()
      } catch (error) {
        settle('reject', error)
        return
      }
      settle('resolve', 'approved')
    }

    function handleAbort () {
      if (settled) return
      addTraceEvent('Human approval cancelled: execution aborted', 'error')
      settle('reject', createAbortError())
    }

    pendingApproval = {
      token: executionToken,
      requirement: paymentRequired,
      fingerprint: requirementFingerprint
    }

    try {
      ui.rejectButton.addEventListener('click', handleReject)
      ui.approveButton.addEventListener('click', handleApprove)
      signal?.addEventListener('abort', handleAbort, { once: true })
    } catch (error) {
      settle('reject', new Error(`Gate H3A approval setup failed: ${errorMessage(error)}`))
      return
    }

    if (signal?.aborted) {
      handleAbort()
      return
    }
    addTraceEvent('Human approval required')
  })
}

const updateRendezvousUi = (snapshot) => {
  if (!rendezvousRegion || !rendezvousState || !rendezvousChallenge || !rendezvousExpiry) return
  rendezvousRegion.hidden = snapshot.state === 'idle'
  rendezvousRegion.dataset.rendezvousState = snapshot.state
  rendezvousState.textContent = snapshot.state
  rendezvousChallenge.textContent = snapshot.challengeId ?? 'Not created'
  rendezvousExpiry.textContent = snapshot.expiresAt === null
    ? 'Not scheduled'
    : new Date(snapshot.expiresAt * 1_000).toLocaleTimeString()
}

const h3cBridge = createH3CBridge({ addTraceEvent, onStateChange: updateRendezvousUi })

const executeResourceTool = async (input, options = {}) => {
  requireEmptyInput(input)
  addTraceEvent(`WebMCP tool invoked: ${RESOURCE_TOOL_NAME}`)

  if (pendingApproval !== null) {
    const error = new Error('An approval decision is already pending.')
    addTraceEvent(`Tool execution failed: ${error.message}`, 'error')
    throw error
  }
  if (activeExecution !== null) {
    const error = new Error('A Gate H3C tool invocation is already active.')
    addTraceEvent(`Tool execution failed: ${error.message}`, 'error')
    throw error
  }
  if (h3cBridge.hasLiveRendezvous()) {
    const error = new Error('An H3C authorization rendezvous is already pending.')
    addTraceEvent(`Tool execution failed: ${error.message}`, 'error')
    throw error
  }

  const executionToken = Symbol('gate-h3c-execution')
  activeExecution = executionToken
  try {
    resetApprovalSurface()
    requireValidAbortSignal(options.signal)

    const fetchOptions = { cache: 'no-store', redirect: 'error' }
    if (options.signal) fetchOptions.signal = options.signal
    const response = await fetch(LIVE_RESOURCE_URL, fetchOptions)
    if (response.status !== 402) {
      throw new Error(`Expected HTTP 402 Payment Required; received HTTP ${response.status}`)
    }
    addTraceEvent('← HTTP 402 Payment Required', 'success')

    const encodedHeader = response.headers.get('PAYMENT-REQUIRED')
    if (!encodedHeader) throw new Error('PAYMENT-REQUIRED response header is missing')
    const paymentRequired = decodePaymentRequiredHeader(encodedHeader)
    const acceptance = validatePaymentRequired(paymentRequired)
    addTraceEvent('PAYMENT-REQUIRED header decoded & validated', 'success')
    addTraceEvent(`Price: ${acceptance.extra.displayAmount}`, 'success')

    let handoffPromise = null
    const decision = await requestHumanApproval(
      paymentRequired,
      acceptance,
      options.signal,
      executionToken,
      () => {
        addTraceEvent('Human decision: APPROVED')
        handoffPromise = h3cBridge.startHandoff({ paymentRequired, signal: options.signal })
      }
    )

    if (decision === 'rejected') {
      addTraceEvent('Human decision: REJECTED')
      addTraceEvent('STOP - Payment not authorized')
      return {
        status: 'payment_rejected',
        gate: 'H3A',
        httpStatus: 402,
        message: 'The human rejected the experimental 100 XEC payment request. No payment was performed.',
        approval: {
          required_amount: acceptance.extra.displayAmount,
          approved: false
        },
        payment: { performed: false }
      }
    }
    if (decision !== 'approved') throw new Error('Gate H3A produced an invalid approval decision')
    if (!handoffPromise) throw new Error('Gate H3C handoff did not start from the approval gesture')
    return await handoffPromise
  } catch (error) {
    addTraceEvent(`Tool execution failed: ${errorMessage(error)}`, 'error')
    throw error
  } finally {
    if (activeExecution === executionToken) activeExecution = null
  }
}

const executeResultTool = (input) => {
  requireEmptyInput(input)
  addTraceEvent(`WebMCP tool invoked: ${RESULT_TOOL_NAME}`)
  try {
    return h3cBridge.readResult()
  } catch (error) {
    addTraceEvent(`Authorization result unavailable: ${errorMessage(error)}`, 'error')
    throw error
  }
}

const emptyInputSchema = Object.freeze({
  type: 'object',
  properties: {},
  additionalProperties: false
})

const registerH3CTools = async () => {
  try {
    if (!document.modelContext || typeof document.modelContext.registerTool !== 'function') {
      setCapabilityState(
        'unavailable',
        'WebMCP unavailable in this browser.',
        'No tool was registered. Open this page in a WebMCP-aware browser to run Gate H3C.'
      )
      addTraceEvent('WebMCP unavailable in this browser.', 'unavailable')
      return
    }

    await document.modelContext.registerTool({
      name: RESULT_TOOL_NAME,
      description: RESULT_TOOL_DESCRIPTION,
      inputSchema: emptyInputSchema,
      annotations: { readOnlyHint: true },
      execute: executeResultTool
    })
    await document.modelContext.registerTool({
      name: RESOURCE_TOOL_NAME,
      description: RESOURCE_TOOL_DESCRIPTION,
      inputSchema: emptyInputSchema,
      execute: executeResourceTool
    })

    setCapabilityState(
      'ready',
      'Two WebMCP tools registered.',
      'Gate H3C can initiate an authorization-only handoff and later read its ephemeral verified result.'
    )
    addTraceEvent(`WebMCP tool registered: ${RESOURCE_TOOL_NAME}`, 'success')
    addTraceEvent(`WebMCP tool registered: ${RESULT_TOOL_NAME}`, 'success')
  } catch (error) {
    setCapabilityState(
      'error',
      'WebMCP tool registration failed.',
      'No complete H3C registration is being claimed. Review the trace for details.'
    )
    addTraceEvent(`WebMCP tool registration failed: ${errorMessage(error)}`, 'error')
  }
}

const setCallbackUi = (title, detail, state) => {
  document.body.dataset.callbackMode = 'true'
  if (callbackRegion) callbackRegion.hidden = false
  if (callbackTitle) callbackTitle.textContent = title
  if (callbackDetail) callbackDetail.textContent = detail
  callbackRegion?.setAttribute('data-callback-state', state)
}

const validAck = (message, callback) => {
  if (!isRecord(message)) return false
  try {
    requireExactKeys(message, ['type', 'challengeId', 'accepted', 'verified'], 'H3C callback ACK')
  } catch {
    return false
  }
  if (
    message.type !== 'h3c-ack' ||
    message.challengeId !== callback.challengeId ||
    typeof message.accepted !== 'boolean' ||
    typeof message.verified !== 'boolean'
  ) return false
  if (!message.accepted && message.verified) return false
  if (callback.status === 'invalid') return !message.accepted && !message.verified
  if (message.accepted && callback.status === 'signed' && !message.verified) return false
  if (message.accepted && callback.status === 'rejected' && message.verified) return false
  return true
}

const runCallbackMode = (capture) => {
  if (!callbackRegion || !callbackTitle || !callbackDetail) {
    document.body.textContent = 'No active H3C session accepted this callback.'
    return
  }
  setCallbackUi(
    'Returning Tonalli authorization result…',
    'Looking for the active, challenge-bound x402eCash session.',
    'delivering'
  )
  callbackClose?.addEventListener('click', () => window.close(), { once: true })

  if (!capture.callback) {
    setCallbackUi(
      'Authorization result was not accepted.',
      'No active H3C session accepted this callback.',
      'failed'
    )
    return
  }
  if (typeof BroadcastChannel !== 'function') {
    setCallbackUi(
      'Authorization result was not accepted.',
      'BroadcastChannel is unavailable. No active H3C session accepted this callback.',
      'failed'
    )
    return
  }

  const callback = capture.callback
  let channel
  let settled = false
  let timeout = null
  const finish = (accepted) => {
    if (settled) return
    settled = true
    if (timeout !== null) clearTimeout(timeout)
    try { channel.close() } catch {}
    if (accepted) {
      setCallbackUi(
        'Authorization result delivered.',
        'Authorization result delivered to active x402eCash session.',
        'delivered'
      )
      return
    }
    setCallbackUi(
      'Authorization result was not accepted.',
      'No active H3C session accepted this callback.',
      'failed'
    )
  }

  try {
    channel = new BroadcastChannel(h3cChannelName(callback.challengeId))
    channel.onmessage = (event) => {
      if (!validAck(event.data, callback)) return
      finish(event.data.accepted)
    }
    timeout = setTimeout(() => finish(false), H3C_CALLBACK_ACK_TIMEOUT_MS)
    channel.postMessage({
      type: 'h3c-callback',
      challengeId: callback.challengeId,
      status: callback.status,
      ...(callback.status === 'signed' ? { proof: callback.proof } : {})
    })
  } catch {
    if (timeout !== null) clearTimeout(timeout)
    try { channel?.close() } catch {}
    setCallbackUi(
      'Authorization result was not accepted.',
      'No active H3C session accepted this callback.',
      'failed'
    )
  }
}

const parseCallbackCapture = (callbackLocation) => {
  if (callbackLocation === null) return null
  requireExactKeys(callbackLocation, ['hash', 'search'], 'H3C callback location')
  let callback = null
  let error = null
  let failureChallenge = null
  try {
    callback = parseH3BCallback(callbackLocation)
  } catch (caught) {
    error = caught
    try {
      failureChallenge = recoverH3BCallbackChallenge(callbackLocation)
    } catch {}
  }
  if (!callback && failureChallenge) {
    callback = Object.freeze({ status: 'invalid', challengeId: failureChallenge })
  }
  return Object.freeze({ callback, error })
}

export const initializeWebMcp = (callbackLocation = null) => {
  const callbackCapture = parseCallbackCapture(callbackLocation)
  if (callbackCapture) runCallbackMode(callbackCapture)
  else void registerH3CTools()
}
