export type Liveness = { status: 'ok' }

const HEALTH_URL = '/api/v1/health/live'
const HEALTH_TIMEOUT_MS = 5_000

function abortReason(signal: AbortSignal): unknown {
  return signal.reason ?? new DOMException('Request aborted', 'AbortError')
}

export async function getLiveness(signal?: AbortSignal): Promise<Liveness> {
  if (signal?.aborted) {
    throw abortReason(signal)
  }

  const requestController = new AbortController()
  const onCallerAbort = () => requestController.abort(abortReason(signal as AbortSignal))
  signal?.addEventListener('abort', onCallerAbort, { once: true })

  const timeout = setTimeout(() => {
    requestController.abort(new DOMException('Health request timed out', 'TimeoutError'))
  }, HEALTH_TIMEOUT_MS)

  try {
    const response = await fetch(HEALTH_URL, { signal: requestController.signal })
    if (!response.ok) {
      throw new Error(`Health request failed with status ${response.status}`)
    }

    let payload: unknown
    try {
      payload = await response.json()
    } catch {
      throw new Error('Health response was not valid JSON')
    }

    if (
      typeof payload !== 'object' ||
      payload === null ||
      !('status' in payload) ||
      payload.status !== 'ok'
    ) {
      throw new Error('Health response had an unexpected status')
    }

    return { status: 'ok' }
  } finally {
    clearTimeout(timeout)
    signal?.removeEventListener('abort', onCallerAbort)
  }
}
