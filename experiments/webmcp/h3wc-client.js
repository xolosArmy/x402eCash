const FLAG_NAME = '__X402_H3WC_ENABLED__'
const CONFIG_NAME = '__X402_H3WC_CONFIG__'
export const H3WC_DEFAULT_ENABLED = false

export const isH3wcEnabled = () => H3WC_DEFAULT_ENABLED || globalThis[FLAG_NAME] === true

const readConfig = () => {
  const value = globalThis[CONFIG_NAME]
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new Error('H3WC local QA configuration is missing')
  }
  if (typeof value.projectId !== 'string' || value.projectId.trim() === '') {
    throw new Error('H3WC local QA project ID is missing')
  }
  if (typeof value.requesterOrigin !== 'string' || value.requesterOrigin !== 'https://x402.ecash.mx') {
    throw new Error('H3WC requester origin must be explicitly configured')
  }
  return value
}

const text = (documentImplementation, value) => documentImplementation.createTextNode(String(value))

/**
 * The dormant QA panel is created only after an explicit local flag.  The
 * WebMCP experiment talks to this narrow adapter, never to WalletConnect.
 */
export const mountH3wcQaPanel = async ({ documentImplementation = globalThis.document } = {}) => {
  if (!isH3wcEnabled()) return null
  if (!documentImplementation?.body) throw new Error('H3WC QA document is unavailable')
  const config = readConfig()
  const sdk = await import('./vendor/tonalli-connect-client-v1.mjs')
  if (typeof sdk.createTonalliConnectClient !== 'function') throw new Error('H3WC client artifact is invalid')

  const panel = documentImplementation.createElement('section')
  panel.dataset.h3wcQa = 'enabled'
  panel.setAttribute('aria-label', 'H3WC local QA')
  const title = documentImplementation.createElement('h2')
  title.append(text(documentImplementation, 'H3WC local transport QA'))
  const status = documentImplementation.createElement('output')
  status.setAttribute('aria-live', 'polite')
  status.append(text(documentImplementation, 'Not connected'))
  const uri = documentImplementation.createElement('textarea')
  uri.readOnly = true
  uri.hidden = true
  uri.setAttribute('aria-label', 'WalletConnect pairing URI')
  const controls = documentImplementation.createElement('div')
  const buttons = [
    ['connect', 'Connect'],
    ['restore', 'Restore'],
    ['identity', 'Get account identity'],
    ['authorize', 'Request authorization transport test'],
    ['disconnect', 'Disconnect']
  ]
  let client = null
  const setStatus = (value) => { status.replaceChildren(text(documentImplementation, value)) }
  const ensureClient = async () => {
    if (!client) {
      client = await sdk.createTonalliConnectClient({
        projectId: config.projectId,
        metadata: { name: 'x402eCash H3WC', url: config.requesterOrigin }
      })
    }
    return client
  }
  const action = async (name) => {
    try {
      const active = await ensureClient()
      if (name === 'connect') {
        const result = await active.connect({ onUri: (value) => { uri.hidden = false; uri.value = value } })
        setStatus(`Connected: ${result.qualification.account}`)
      } else if (name === 'restore') {
        const sessions = await active.restore()
        setStatus(`Restored ${sessions.length} exact H3WC session${sessions.length === 1 ? '' : 's'}`)
      } else if (name === 'identity') {
        const identity = await active.getAccountIdentity()
        setStatus(`Identity: ${identity.address} / ${identity.publicKey}`)
      } else if (name === 'authorize') {
        await active.requestH3BAuthorization({ message: 'H3WC transport test (no signature enabled)' })
        setStatus('Unexpected signing success')
      } else {
        await active.disconnect()
        setStatus('Disconnected')
      }
    } catch (error) {
      setStatus(error instanceof Error ? error.message : String(error))
    }
  }
  for (const [name, label] of buttons) {
    const button = documentImplementation.createElement('button')
    button.type = 'button'
    button.dataset.h3wcAction = name
    button.append(text(documentImplementation, label))
    button.addEventListener('click', () => { void action(name) })
    controls.append(button)
  }
  panel.append(title, status, uri, controls)
  documentImplementation.body.append(panel)
  return Object.freeze({ panel, getState: () => client?.getState?.() ?? { qualification: 'NONE' } })
}
