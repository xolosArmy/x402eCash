const callbackRegion = document.querySelector('[data-callback-region]')
const callbackTitle = document.querySelector('[data-callback-title]')
const callbackDetail = document.querySelector('[data-callback-detail]')

const isCallbackAttempt = () => (
  /(?:^#|[&#])(?:h3bStatus|challengeId|proof)=/u.test(location.hash) ||
  /(?:^\?|[&])(?:h3bStatus|challengeId|proof)=/u.test(location.search)
)

const showBootstrapFailure = (detail) => {
  document.body.dataset.callbackMode = 'true'
  if (callbackRegion) {
    callbackRegion.hidden = false
    callbackRegion.dataset.callbackState = 'failed'
  }
  if (callbackTitle) callbackTitle.textContent = 'Authorization result was not accepted.'
  if (callbackDetail) callbackDetail.textContent = detail
}

const captureAndCleanCallbackLocation = () => {
  if (!isCallbackAttempt()) return null
  const captured = Object.freeze({ hash: location.hash, search: location.search })
  document.body.dataset.callbackMode = 'true'
  if (callbackRegion) callbackRegion.hidden = false

  try {
    history.replaceState(history.state, '', location.pathname)
  } catch {
    showBootstrapFailure('The callback URL could not be cleared. No result was processed.')
    throw new Error('H3C callback URL cleanup failed')
  }
  if (location.hash !== '' || location.search !== '') {
    showBootstrapFailure('The callback URL could not be cleared. No result was processed.')
    throw new Error('H3C callback URL cleanup did not remove the fragment and query')
  }
  return captured
}

const start = async () => {
  let callbackLocation
  try {
    callbackLocation = captureAndCleanCallbackLocation()
  } catch {
    return
  }

  try {
    const module = await import('./webmcp.js')
    if (typeof module.initializeWebMcp !== 'function') {
      throw new Error('Gate H3C initializer is unavailable')
    }
    module.initializeWebMcp(callbackLocation)
  } catch {
    showBootstrapFailure(
      callbackLocation
        ? 'The callback verifier could not load. No result was processed.'
        : 'Gate H3C could not load in this browser.'
    )
  }
}

void start()
