import {
  H3C_HANDOFF_TIMEOUT_MS,
  h3cChannelName,
  isRecord,
  parseH3BRequestTransport,
  requireExactKeys,
  tonalliH3BUrl
} from './h3c-contract.js'

const status = document.querySelector('[data-handoff-status]')
const detail = document.querySelector('[data-handoff-detail]')

const setStatus = (headline, message, state) => {
  if (status) status.textContent = headline
  if (detail) detail.textContent = message
  document.body.dataset.handoffState = state
}

const cleanFragment = () => {
  try {
    history.replaceState(history.state, '', location.pathname)
    return location.hash === '' && location.search === ''
  } catch {
    return false
  }
}

const failClosed = (message) => {
  const cleaned = cleanFragment()
  setStatus(
    'Handoff stopped safely.',
    cleaned ? message : 'The request URL could not be cleared. Tonalli was not opened.',
    'failed'
  )
}

const isAcceptedHandoff = (message, challengeId) => {
  if (!isRecord(message)) return false
  try {
    requireExactKeys(message, ['type', 'challengeId'], 'H3C handoff acceptance')
  } catch {
    return false
  }
  return message.type === 'h3c-handoff-accepted' && message.challengeId === challengeId
}

const runHandoff = () => {
  let transport
  try {
    transport = parseH3BRequestTransport({
      hash: location.hash,
      search: location.search,
      nowSeconds: Math.floor(Date.now() / 1000)
    })
  } catch {
    failClosed('The H3B request is invalid or expired. Tonalli was not opened.')
    return
  }

  if (typeof BroadcastChannel !== 'function') {
    failClosed('BroadcastChannel is unavailable. Tonalli was not opened.')
    return
  }

  let channel
  let settled = false
  let timeout = null
  const stop = (message) => {
    if (settled) return
    settled = true
    if (timeout !== null) clearTimeout(timeout)
    try { channel?.close() } catch {}
    failClosed(message)
  }
  try {
    channel = new BroadcastChannel(h3cChannelName(transport.request.challengeId))
    channel.onmessage = (event) => {
      if (settled || !isAcceptedHandoff(event.data, transport.request.challengeId)) return
      settled = true
      if (timeout !== null) clearTimeout(timeout)
      try { channel.close() } catch {}
      setStatus(
        'Opening Tonalli authorization…',
        'The request fragment has been removed from this page. No payment or transaction was created.',
        'opening'
      )
      try {
        location.replace(tonalliH3BUrl(transport.encodedRequest))
      } catch {
        setStatus('Handoff stopped safely.', 'Tonalli could not be opened.', 'failed')
      }
    }
    channel.postMessage({
      type: 'h3c-handoff-opened',
      challengeId: transport.request.challengeId
    })
  } catch {
    try { channel?.close() } catch {}
    failClosed('The ephemeral H3C rendezvous could not be opened. Tonalli was not opened.')
    return
  }

  if (!cleanFragment()) {
    stop('The request URL could not be cleared. Tonalli was not opened.')
    return
  }
  try { window.opener = null } catch {}
  setStatus(
    'Confirming the x402eCash session…',
    'The request fragment has been removed. Tonalli will open only if the original page accepts this handoff.',
    'checking'
  )
  timeout = setTimeout(() => {
    stop('No active x402eCash H3C session accepted this handoff. Tonalli was not opened.')
  }, H3C_HANDOFF_TIMEOUT_MS)
}

runHandoff()
