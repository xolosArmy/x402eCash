import {
  H3C_HANDOFF_ANNOUNCEMENT_INTERVAL_MS,
  H3C_HANDOFF_TIMEOUT_MS,
  h3cChannelName,
  isRecord,
  parseH3BRequestTransport,
  requireExactKeys,
  tonalliH3BUrl
} from './h3c-contract.js'

const isAcceptedHandoff = (message, challengeId) => {
  if (!isRecord(message)) return false
  try {
    requireExactKeys(message, ['type', 'challengeId'], 'H3C handoff acceptance')
  } catch {
    return false
  }
  return message.type === 'h3c-handoff-accepted' && message.challengeId === challengeId
}

export const runHandoff = ({
  documentImplementation = globalThis.document,
  historyImplementation = globalThis.history,
  locationImplementation = globalThis.location,
  windowImplementation = globalThis.window,
  BroadcastChannelImplementation = globalThis.BroadcastChannel,
  nowMilliseconds = () => Date.now(),
  setTimeoutImplementation = globalThis.setTimeout.bind(globalThis),
  clearTimeoutImplementation = globalThis.clearTimeout.bind(globalThis),
  setIntervalImplementation = globalThis.setInterval.bind(globalThis),
  clearIntervalImplementation = globalThis.clearInterval.bind(globalThis)
} = {}) => {
  const status = documentImplementation.querySelector('[data-handoff-status]')
  const detail = documentImplementation.querySelector('[data-handoff-detail]')

  const setStatus = (headline, message, state) => {
    if (status) status.textContent = headline
    if (detail) detail.textContent = message
    documentImplementation.body.dataset.handoffState = state
  }

  const cleanFragment = () => {
    try {
      historyImplementation.replaceState(
        historyImplementation.state,
        '',
        locationImplementation.pathname
      )
      return locationImplementation.hash === '' && locationImplementation.search === ''
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

  let transport
  try {
    transport = parseH3BRequestTransport({
      hash: locationImplementation.hash,
      search: locationImplementation.search,
      nowSeconds: Math.floor(nowMilliseconds() / 1_000)
    })
  } catch {
    failClosed('The H3B request is invalid or expired. Tonalli was not opened.')
    return null
  }

  if (typeof BroadcastChannelImplementation !== 'function') {
    failClosed('BroadcastChannel is unavailable. Tonalli was not opened.')
    return null
  }

  let channel = null
  let settled = false
  let handshakeTimeout = null
  let announcementInterval = null
  let pageHideHandler = null

  const cleanup = () => {
    if (handshakeTimeout !== null) {
      clearTimeoutImplementation(handshakeTimeout)
      handshakeTimeout = null
    }
    if (announcementInterval !== null) {
      clearIntervalImplementation(announcementInterval)
      announcementInterval = null
    }
    if (pageHideHandler !== null) {
      try { windowImplementation.removeEventListener('pagehide', pageHideHandler) } catch {}
      pageHideHandler = null
    }
    try { channel?.close() } catch {}
    channel = null
  }

  const stop = (message) => {
    if (settled) return
    settled = true
    cleanup()
    failClosed(message)
  }

  const isExpired = () => (
    Math.floor(nowMilliseconds() / 1_000) >= transport.request.expiresAt
  )

  const openedMessage = Object.freeze({
    type: 'h3c-handoff-opened',
    challengeId: transport.request.challengeId
  })

  const announceOpened = () => {
    if (settled) return
    if (isExpired()) {
      stop('The H3C authorization request expired. Tonalli was not opened.')
      return
    }
    try {
      channel.postMessage(openedMessage)
    } catch {
      stop('The ephemeral H3C rendezvous could not be announced. Tonalli was not opened.')
    }
  }

  try {
    channel = new BroadcastChannelImplementation(
      h3cChannelName(transport.request.challengeId)
    )
    channel.onmessage = (event) => {
      if (settled || !isAcceptedHandoff(event.data, transport.request.challengeId)) return
      if (isExpired()) {
        stop('The H3C authorization request expired. Tonalli was not opened.')
        return
      }
      settled = true
      cleanup()
      setStatus(
        'Opening Tonalli authorization…',
        'The request fragment has been removed from this page. No payment or transaction was created.',
        'opening'
      )
      try {
        locationImplementation.replace(tonalliH3BUrl(transport.encodedRequest))
      } catch {
        setStatus('Handoff stopped safely.', 'Tonalli could not be opened.', 'failed')
      }
    }
  } catch {
    cleanup()
    failClosed('The ephemeral H3C rendezvous could not be opened. Tonalli was not opened.')
    return null
  }

  if (!cleanFragment()) {
    stop('The request URL could not be cleared. Tonalli was not opened.')
    return null
  }

  try { windowImplementation.opener = null } catch {}
  setStatus(
    'Confirming the x402eCash session…',
    'The request fragment has been removed. Tonalli will open only if the original page accepts this handoff.',
    'checking'
  )

  pageHideHandler = () => {
    if (settled) return
    settled = true
    cleanup()
  }
  try { windowImplementation.addEventListener('pagehide', pageHideHandler, { once: true }) } catch {}

  announceOpened()
  if (settled) return null

  try {
    announcementInterval = setIntervalImplementation(
      announceOpened,
      H3C_HANDOFF_ANNOUNCEMENT_INTERVAL_MS
    )
    const remainingLifetimeMilliseconds = Math.max(
      0,
      (transport.request.expiresAt * 1_000) - nowMilliseconds()
    )
    handshakeTimeout = setTimeoutImplementation(() => {
      if (isExpired()) {
        stop('The H3C authorization request expired. Tonalli was not opened.')
        return
      }
      stop('No active x402eCash H3C session accepted this handoff. Tonalli was not opened.')
    }, Math.min(H3C_HANDOFF_TIMEOUT_MS, remainingLifetimeMilliseconds))
  } catch {
    stop('The ephemeral H3C rendezvous timers could not be started. Tonalli was not opened.')
    return null
  }

  return Object.freeze({
    dispose: pageHideHandler
  })
}

if (typeof document !== 'undefined' && typeof location !== 'undefined') {
  runHandoff()
}
