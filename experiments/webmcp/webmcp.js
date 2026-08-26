import {
  H3C_CALLBACK_ACK_TIMEOUT_MS,
  LIVE_RESOURCE_URL,
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
const RESOURCE_TOOL_DESCRIPTION = 'Validate the live experimental 100 XEC HTTP 402 requirement and create an ephemeral page-owned human approval session. The tool returns before the human decides. No payment is performed.'
const RESULT_TOOL_DESCRIPTION = 'Read the current ephemeral Gate H3A/H3C authorization state. This tool never initiates signing or payment.'

const pageDocument = globalThis.document
const traceLog = pageDocument?.querySelector('[data-trace-log]')
const capabilityState = pageDocument?.querySelector('[data-webmcp-state]')
const capabilityStatus = pageDocument?.querySelector('[data-webmcp-status]')
const capabilityDetail = pageDocument?.querySelector('[data-webmcp-detail]')
const approvalRegion = pageDocument?.querySelector('[data-approval-region]')
const approvalMount = pageDocument?.querySelector('[data-approval-mount]')
const approvalTemplate = pageDocument?.querySelector('[data-approval-template]')
const rendezvousRegion = pageDocument?.querySelector('[data-rendezvous-region]')
const rendezvousState = pageDocument?.querySelector('[data-rendezvous-state]')
const rendezvousChallenge = pageDocument?.querySelector('[data-rendezvous-challenge]')
const rendezvousExpiry = pageDocument?.querySelector('[data-rendezvous-expiry]')
const callbackRegion = pageDocument?.querySelector('[data-callback-region]')
const callbackTitle = pageDocument?.querySelector('[data-callback-title]')
const callbackDetail = pageDocument?.querySelector('[data-callback-detail]')
const callbackClose = pageDocument?.querySelector('[data-callback-close]')

let activeApprovalUi = null

const localTimestamp = () => {
  const now = new Date()
  return [now.getHours(), now.getMinutes(), now.getSeconds()]
    .map((part) => String(part).padStart(2, '0'))
    .join(':')
}

const addTraceEvent = (message, kind = 'info') => {
  if (!traceLog || !pageDocument) return
  traceLog.querySelector('[data-trace-placeholder]')?.remove()
  const item = pageDocument.createElement('li')
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
  const error = new Error('Gate H3A resource preparation was aborted before the tool returned')
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
  activeApprovalUi?.cleanup()
  activeApprovalUi = null
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

const updatePageSessionUi = (snapshot) => {
  updateRendezvousUi(snapshot)
  const mounted = activeApprovalUi
  if (!mounted || mounted.binding.generation !== snapshot.generation) return
  if (snapshot.state === 'handoff-opening') {
    mounted.ui.card.dataset.approvalState = 'handoff-opening'
    mounted.ui.status.textContent = 'Approval recorded. Opening the authorization-only Tonalli handoff; no payment is being sent.'
  } else if (snapshot.state === 'awaiting-tonalli') {
    mounted.ui.card.dataset.approvalState = 'awaiting-tonalli'
    mounted.ui.status.textContent = 'Approval recorded. Awaiting the separate Tonalli authorization proof.'
  } else if (snapshot.state === 'verified') {
    mounted.ui.card.dataset.approvalState = 'verified'
    mounted.ui.status.textContent = 'Tonalli authorization proof verified. No payment was performed.'
  } else if (snapshot.state === 'rejected') {
    mounted.ui.card.dataset.approvalState = 'rejected'
    mounted.ui.status.textContent = snapshot.challengeId === null
      ? 'Request rejected. No payment was authorized.'
      : 'Tonalli authorization request rejected. No payment was performed.'
  } else if (snapshot.state === 'failed' || snapshot.state === 'expired') {
    mounted.ui.card.dataset.approvalState = snapshot.state
    mounted.ui.status.textContent = snapshot.state === 'expired'
      ? 'The authorization-only handoff expired. No payment was performed.'
      : 'The authorization-only handoff failed safely. No payment was performed.'
  }
}

const h3cBridge = createH3CBridge({ addTraceEvent, onStateChange: updatePageSessionUi })

const installApprovalSession = ({ acceptance, binding }) => {
  const ui = createApprovalCard(acceptance)
  resetApprovalSurface()
  let decided = false

  const removeListeners = () => {
    try { ui.rejectButton.removeEventListener('click', handleReject) } catch {}
    try { ui.approveButton.removeEventListener('click', handleApprove) } catch {}
  }

  const lockControls = () => {
    removeListeners()
    ui.rejectButton.disabled = true
    ui.approveButton.disabled = true
  }

  const failClosed = (error) => {
    decided = true
    lockControls()
    ui.card.dataset.approvalState = 'failed'
    ui.status.textContent = `Approval stopped safely: ${errorMessage(error)}`
    try { h3cBridge.failApprovalSession(binding, error) } catch {}
  }

  function handleReject () {
    if (decided) return
    try {
      h3cBridge.validateApproval(binding)
      decided = true
      lockControls()
      h3cBridge.rejectApproval(binding)
      ui.card.dataset.approvalState = 'rejected'
      ui.status.textContent = 'Request rejected. No payment was authorized.'
    } catch (error) {
      failClosed(error)
    }
  }

  function handleApprove () {
    if (decided) return
    try {
      h3cBridge.validateApproval(binding)
      decided = true
      lockControls()
      ui.card.dataset.approvalState = 'handoff-opening'
      ui.status.textContent = 'Approval recorded. Opening the authorization-only Tonalli handoff; no payment is being sent.'
      addTraceEvent('Human decision: APPROVED')
      const handoff = h3cBridge.startHandoff(binding)
      void handoff.catch((error) => {
        if (activeApprovalUi?.binding.generation !== binding.generation) return
        ui.card.dataset.approvalState = 'failed'
        ui.status.textContent = `Authorization handoff stopped safely: ${errorMessage(error)}`
      })
    } catch (error) {
      failClosed(error)
    }
  }

  try {
    ui.rejectButton.addEventListener('click', handleReject)
    ui.approveButton.addEventListener('click', handleApprove)
    approvalMount.replaceChildren(ui.fragment)
    approvalRegion.hidden = false
    activeApprovalUi = {
      binding,
      ui,
      cleanup: lockControls
    }
    ui.card.focus()
    addTraceEvent('Human approval required')
    return activeApprovalUi
  } catch (error) {
    failClosed(new Error(`Gate H3A approval setup failed: ${errorMessage(error)}`))
    throw error
  }
}

export const createResourceToolExecutor = ({
  bridge,
  fetchImplementation,
  renderApproval,
  traceEvent = () => {}
}) => {
  if (
    !bridge ||
    typeof bridge.createApprovalSession !== 'function' ||
    typeof bridge.failApprovalSession !== 'function' ||
    typeof bridge.hasLiveSession !== 'function' ||
    typeof fetchImplementation !== 'function' ||
    typeof renderApproval !== 'function' ||
    typeof traceEvent !== 'function'
  ) {
    throw new Error('Gate H3A resource tool dependencies are incomplete')
  }

  let activeExecution = null
  return async (input, options = {}) => {
    requireEmptyInput(input)
    traceEvent(`WebMCP tool invoked: ${RESOURCE_TOOL_NAME}`)

    if (activeExecution !== null) {
      const error = new Error('A Gate H3A resource invocation is already active.')
      traceEvent(`Tool execution failed: ${error.message}`, 'error')
      throw error
    }
    if (bridge.hasLiveSession()) {
      const error = new Error('A human approval or H3C authorization session is already pending.')
      traceEvent(`Tool execution failed: ${error.message}`, 'error')
      throw error
    }

    const executionToken = Symbol('gate-h3a-resource-execution')
    activeExecution = executionToken
    let created = null
    let mounted = null
    try {
      const signal = options?.signal
      requireValidAbortSignal(signal)
      if (signal?.aborted) throw createAbortError()

      const fetchOptions = { cache: 'no-store', redirect: 'error' }
      if (signal) fetchOptions.signal = signal
      const response = await fetchImplementation(LIVE_RESOURCE_URL, fetchOptions)
      if (signal?.aborted) throw createAbortError()
      if (response.status !== 402) {
        throw new Error(`Expected HTTP 402 Payment Required; received HTTP ${response.status}`)
      }
      traceEvent('← HTTP 402 Payment Required', 'success')

      const encodedHeader = response.headers.get('PAYMENT-REQUIRED')
      if (!encodedHeader) throw new Error('PAYMENT-REQUIRED response header is missing')
      const paymentRequired = decodePaymentRequiredHeader(encodedHeader)
      const acceptance = validatePaymentRequired(paymentRequired)
      if (signal?.aborted) throw createAbortError()
      traceEvent('PAYMENT-REQUIRED header decoded & validated', 'success')
      traceEvent(`Price: ${acceptance.extra.displayAmount}`, 'success')

      created = bridge.createApprovalSession({ paymentRequired })
      mounted = renderApproval({ paymentRequired, acceptance, binding: created.binding })
      if (signal?.aborted) {
        const error = createAbortError()
        try { mounted?.cleanup?.() } catch {}
        bridge.failApprovalSession(created.binding, error)
        throw error
      }
      return created.result
    } catch (error) {
      if (created && bridge.getSnapshot?.().state === 'approval-required') {
        try { bridge.failApprovalSession(created.binding, error) } catch {}
      }
      traceEvent(`Tool execution failed: ${errorMessage(error)}`, 'error')
      throw error
    } finally {
      if (activeExecution === executionToken) activeExecution = null
    }
  }
}

const executeResourceTool = createResourceToolExecutor({
  bridge: h3cBridge,
  fetchImplementation: globalThis.fetch.bind(globalThis),
  renderApproval: installApprovalSession,
  traceEvent: addTraceEvent
})

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
      'The resource tool returns after creating page-owned approval state; the read-only result tool reports what happens afterward.'
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
  if (!pageDocument) return
  pageDocument.body.dataset.callbackMode = 'true'
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
    if (pageDocument) pageDocument.body.textContent = 'No active H3C session accepted this callback.'
    return
  }
  setCallbackUi(
    'Returning Tonalli authorization result…',
    'Looking for the active, challenge-bound x402eCash session.',
    'delivering'
  )
  callbackClose?.addEventListener('click', () => globalThis.window?.close(), { once: true })

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
