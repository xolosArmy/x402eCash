const TOOL_NAME = 'get_paid_xec_resource'
const TOOL_DESCRIPTION = 'Retrieve the Gate H1 mock resource for the future x402 XEC payment flow. No payment is performed in Gate H1.'

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
  if (error instanceof Error && error.message) return error.message
  return 'Unknown error'
}

const validateMockResource = (resource) => (
  resource !== null &&
  typeof resource === 'object' &&
  resource.status === 'unlocked' &&
  resource.payment !== null &&
  typeof resource.payment === 'object' &&
  resource.payment.mode === 'mock' &&
  resource.payment.performed === false
)

const executeGateH1 = async (_input, options = {}) => {
  addTraceEvent(`WebMCP tool invoked: ${TOOL_NAME}`)

  try {
    const fetchOptions = options.signal ? { signal: options.signal } : {}
    const response = await fetch('./mock-resource.json', fetchOptions)

    if (response.ok !== true || response.status !== 200) {
      throw new Error(`Unexpected fixture response: HTTP ${response.status}`)
    }

    const resource = await response.json()
    if (!validateMockResource(resource)) {
      throw new Error('Gate H1 mock resource validation failed')
    }

    addTraceEvent('HTTP 200: Gate H1 mock resource unlocked', 'success')

    return {
      gate: 'H1',
      httpStatus: response.status,
      resource
    }
  } catch (error) {
    addTraceEvent(`Tool execution failed: ${errorMessage(error)}`, 'error')
    throw error
  }
}

const registerGateH1Tool = async () => {
  try {
    if (!document.modelContext || typeof document.modelContext.registerTool !== 'function') {
      setCapabilityState(
        'unavailable',
        'WebMCP unavailable in this browser.',
        'No tool was registered. Open this page in a WebMCP-aware browser to run Gate H1.'
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
      execute: executeGateH1
    })

    setCapabilityState(
      'ready',
      'WebMCP tool registered.',
      'The read-only Gate H1 tool is ready for browser-agent discovery.'
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

registerGateH1Tool()
