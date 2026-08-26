const TOOL_NAME = 'get_paid_xec_resource'
const TOOL_DESCRIPTION = 'Request the live x402eCash demo resource, validate its experimental XEC payment requirement, and ask the human to approve or reject proceeding. No signing or payment is performed in Gate H3A.'
const LIVE_RESOURCE_URL = 'https://api.x402.ecash.mx/v1/resource/demo'
const EXPECTED_PAYMENT_ERROR = 'PAYMENT-SIGNATURE header is required'
const EXPECTED_PAY_TO = 'ecash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyquz9y96w'

const traceLog = document.querySelector('[data-trace-log]')
const capabilityState = document.querySelector('[data-webmcp-state]')
const capabilityStatus = document.querySelector('[data-webmcp-status]')
const capabilityDetail = document.querySelector('[data-webmcp-detail]')
const approvalRegion = document.querySelector('[data-approval-region]')
const approvalMount = document.querySelector('[data-approval-mount]')
const approvalTemplate = document.querySelector('[data-approval-template]')

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
  if (
    error !== null &&
    typeof error === 'object' &&
    typeof error.message === 'string' &&
    error.message
  ) return error.message
  if (typeof error === 'string' && error) return error
  return 'Unknown error'
}

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)

const requireInvariant = (condition, message) => {
  if (!condition) throw new Error(`PAYMENT-REQUIRED validation failed: ${message}`)
}

const decodePaymentRequired = (encodedHeader) => {
  if (
    typeof encodedHeader !== 'string' ||
    encodedHeader.length === 0 ||
    encodedHeader.length % 4 !== 0 ||
    !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encodedHeader)
  ) {
    throw new Error('PAYMENT-REQUIRED header is not valid Base64')
  }

  let binary
  try {
    binary = atob(encodedHeader)
  } catch {
    throw new Error('PAYMENT-REQUIRED header is not valid Base64')
  }

  if (btoa(binary) !== encodedHeader) {
    throw new Error('PAYMENT-REQUIRED header is not canonical Base64')
  }

  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0))
  let decoded
  try {
    decoded = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    throw new Error('PAYMENT-REQUIRED header is not valid UTF-8')
  }

  try {
    return JSON.parse(decoded)
  } catch {
    throw new Error('PAYMENT-REQUIRED header does not contain valid JSON')
  }
}

const validatePaymentRequired = (paymentRequired) => {
  requireInvariant(isObject(paymentRequired), 'decoded value must be an object')
  requireInvariant(paymentRequired.x402Version === 2, 'x402Version must equal 2')
  requireInvariant(paymentRequired.error === EXPECTED_PAYMENT_ERROR, 'error message does not match Gate H2A')

  const resource = paymentRequired.resource
  requireInvariant(isObject(resource), 'resource must be an object')
  requireInvariant(resource.url === LIVE_RESOURCE_URL, 'resource.url does not match the canonical resource')
  requireInvariant(resource.description === 'x402eCash WebMCP Challenge demo resource', 'resource.description does not match')
  requireInvariant(resource.mimeType === 'application/json', 'resource.mimeType must be application/json')
  requireInvariant(resource.serviceName === 'x402eCash', 'resource.serviceName must be x402eCash')

  requireInvariant(Array.isArray(paymentRequired.accepts), 'accepts must be an array')
  requireInvariant(paymentRequired.accepts.length === 1, 'accepts must contain exactly one entry')

  const acceptance = paymentRequired.accepts[0]
  requireInvariant(isObject(acceptance), 'accepts[0] must be an object')
  requireInvariant(acceptance.scheme === 'xec-prepaid-utxo', 'scheme must be xec-prepaid-utxo')
  requireInvariant(acceptance.network === 'xec:mainnet', 'network must be xec:mainnet')
  requireInvariant(acceptance.amount === '10000', 'amount must equal 10000')
  requireInvariant(acceptance.asset === 'XEC', 'asset must be XEC')
  requireInvariant(acceptance.payTo === EXPECTED_PAY_TO, 'payTo does not match the deterministic fixture')
  requireInvariant(acceptance.maxTimeoutSeconds === 60, 'maxTimeoutSeconds must equal 60')

  const extra = acceptance.extra
  requireInvariant(isObject(extra), 'accepts[0].extra must be an object')
  requireInvariant(extra.displayAmount === '100 XEC', 'displayAmount must equal 100 XEC')
  requireInvariant(extra.experimental === true, 'experimental must equal true')
  requireInvariant(extra.gate === 'H2A', 'gate must equal H2A')

  requireInvariant(isObject(paymentRequired.extensions), 'extensions must be an object')
  requireInvariant(Object.keys(paymentRequired.extensions).length === 0, 'extensions must contain no enumerable keys')

  return acceptance
}

const requireApprovalSurface = () => {
  if (
    !approvalRegion ||
    !approvalMount ||
    typeof approvalMount.replaceChildren !== 'function' ||
    !approvalTemplate ||
    !approvalTemplate.content ||
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

const requireValidAbortSignal = (signal) => {
  if (signal === undefined || signal === null) return
  if (
    typeof signal.aborted !== 'boolean' ||
    typeof signal.addEventListener !== 'function' ||
    typeof signal.removeEventListener !== 'function'
  ) {
    throw new Error('Gate H3A received an invalid AbortSignal')
  }
}

const createAbortError = () => {
  const error = new Error('Human approval cancelled because the tool execution was aborted')
  error.name = 'AbortError'
  return error
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

  return {
    fragment,
    card,
    rejectButton,
    approveButton,
    status
  }
}

const requestHumanApproval = (paymentRequired, acceptance, signal, executionToken) => {
  if (pendingApproval !== null) {
    throw new Error('An approval decision is already pending.')
  }

  const requirementFingerprint = JSON.stringify(paymentRequired)
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
          ? 'Approval recorded. No signing or payment was performed.'
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
        JSON.stringify(paymentRequired) !== requirementFingerprint
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

const executeGateH3A = async (_input, options = {}) => {
  addTraceEvent(`WebMCP tool invoked: ${TOOL_NAME}`)

  if (pendingApproval !== null) {
    const error = new Error('An approval decision is already pending.')
    addTraceEvent(`Tool execution failed: ${error.message}`, 'error')
    throw error
  }

  if (activeExecution !== null) {
    const error = new Error('A Gate H3A tool invocation is already active.')
    addTraceEvent(`Tool execution failed: ${error.message}`, 'error')
    throw error
  }

  const executionToken = Symbol('gate-h3a-execution')
  activeExecution = executionToken

  try {
    resetApprovalSurface()
    requireValidAbortSignal(options.signal)

    const fetchOptions = {
      cache: 'no-store',
      redirect: 'error'
    }
    if (options.signal) fetchOptions.signal = options.signal

    const response = await fetch(LIVE_RESOURCE_URL, fetchOptions)

    if (response.status !== 402) {
      throw new Error(`Expected HTTP 402 Payment Required; received HTTP ${response.status}`)
    }

    addTraceEvent('← HTTP 402 Payment Required', 'success')

    const encodedHeader = response.headers.get('PAYMENT-REQUIRED')
    if (!encodedHeader) throw new Error('PAYMENT-REQUIRED response header is missing')

    const paymentRequired = decodePaymentRequired(encodedHeader)
    const acceptance = validatePaymentRequired(paymentRequired)

    addTraceEvent('PAYMENT-REQUIRED header decoded & validated', 'success')
    addTraceEvent(`Price: ${acceptance.extra.displayAmount}`, 'success')

    const decision = await requestHumanApproval(
      paymentRequired,
      acceptance,
      options.signal,
      executionToken
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
        payment: {
          performed: false
        }
      }
    }

    if (decision !== 'approved') {
      throw new Error('Gate H3A produced an invalid approval decision')
    }

    addTraceEvent('Human decision: APPROVED')
    addTraceEvent(`Approval recorded: ${acceptance.extra.displayAmount}`)
    addTraceEvent('STOP - Awaiting Tonalli signing integration (Gate H3B)')

    return {
      status: 'payment_approved',
      gate: 'H3A',
      httpStatus: 402,
      message: 'The human approved proceeding toward a 100 XEC payment. No signing or payment was performed.',
      approval: {
        network: acceptance.network,
        asset: acceptance.asset,
        required_amount: acceptance.extra.displayAmount,
        atomic_amount: acceptance.amount,
        payTo: acceptance.payTo,
        approved: true
      },
      payment: {
        performed: false
      },
      nextGate: 'H3B'
    }
  } catch (error) {
    addTraceEvent(`Tool execution failed: ${errorMessage(error)}`, 'error')
    throw error
  } finally {
    if (activeExecution === executionToken) activeExecution = null
  }
}

const registerGateH3ATool = async () => {
  try {
    if (!document.modelContext || typeof document.modelContext.registerTool !== 'function') {
      setCapabilityState(
        'unavailable',
        'WebMCP unavailable in this browser.',
        'No tool was registered. Open this page in a WebMCP-aware browser to run Gate H3A.'
      )
      addTraceEvent('WebMCP unavailable in this browser.', 'unavailable')
      return
    }

    await document.modelContext.registerTool({
      name: TOOL_NAME,
      description: TOOL_DESCRIPTION,
      inputSchema: {
        type: 'object',
        properties: {},
        additionalProperties: false
      },
      annotations: {
        readOnlyHint: true
      },
      execute: executeGateH3A
    })

    setCapabilityState(
      'ready',
      'WebMCP tool registered.',
      'Gate H3A is ready to validate the live requirement and request a human decision.'
    )
    addTraceEvent(`WebMCP tool registered: ${TOOL_NAME}`, 'success')
  } catch (error) {
    setCapabilityState(
      'error',
      'WebMCP tool registration failed.',
      'No successful registration is being claimed. Review the trace for details.'
    )
    addTraceEvent(`WebMCP tool registration failed: ${errorMessage(error)}`, 'error')
  }
}

registerGateH3ATool()
