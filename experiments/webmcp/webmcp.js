const TOOL_NAME = 'get_paid_xec_resource'
const TOOL_DESCRIPTION = 'Request the live x402eCash WebMCP demo resource and report its experimental XEC payment requirement. No payment is performed in Gate H2B.'
const LIVE_RESOURCE_URL = 'https://api.x402.ecash.mx/v1/resource/demo'
const EXPECTED_PAYMENT_ERROR = 'PAYMENT-SIGNATURE header is required'
const EXPECTED_PAY_TO = 'ecash:qqg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyquz9y96w'

const traceLog = document.querySelector('[data-trace-log]')
const capabilityState = document.querySelector('[data-webmcp-state]')
const capabilityStatus = document.querySelector('[data-webmcp-status]')
const capabilityDetail = document.querySelector('[data-webmcp-detail]')

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

const executeGateH2B = async (_input, options = {}) => {
  addTraceEvent(`WebMCP tool invoked: ${TOOL_NAME}`)

  try {
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
    addTraceEvent('STOP - Awaiting wallet integration (Gate H3)')

    return {
      status: 'payment_required',
      gate: 'H2B',
      httpStatus: 402,
      message: 'Resource requires payment. The browser intercepted and validated the live HTTP 402 Payment Required response. No payment was performed.',
      payment: {
        network: acceptance.network,
        asset: acceptance.asset,
        required_amount: acceptance.extra.displayAmount,
        atomic_amount: acceptance.amount,
        payTo: acceptance.payTo,
        experimental: true,
        performed: false
      }
    }
  } catch (error) {
    addTraceEvent(`Tool execution failed: ${errorMessage(error)}`, 'error')
    throw error
  }
}

const registerGateH2BTool = async () => {
  try {
    if (!document.modelContext || typeof document.modelContext.registerTool !== 'function') {
      setCapabilityState(
        'unavailable',
        'WebMCP unavailable in this browser.',
        'No tool was registered. Open this page in a WebMCP-aware browser to run Gate H2B.'
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
      execute: executeGateH2B
    })

    setCapabilityState(
      'ready',
      'WebMCP tool registered.',
      'The read-only Gate H2B tool is ready to inspect the live experimental payment requirement.'
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

registerGateH2BTool()
