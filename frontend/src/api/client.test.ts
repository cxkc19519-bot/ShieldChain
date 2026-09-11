import { afterEach, describe, expect, it, vi } from 'vitest'

import { getLiveness } from './client'

const response = (body: unknown, init: ResponseInit = {}) =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
    ...init,
  })

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('getLiveness', () => {
  it('maps the live health response to the exact public result', async () => {
    const fetchMock = vi.fn().mockResolvedValue(response({ status: 'ok', ignored: true }))
    vi.stubGlobal('fetch', fetchMock)

    await expect(getLiveness()).resolves.toEqual({ status: 'ok' })
    expect(fetchMock).toHaveBeenCalledWith(
      '/api/v1/health/live',
      expect.objectContaining({ signal: expect.any(AbortSignal) }),
    )
  })

  it('rejects a non-success HTTP response', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ detail: 'down' }, { status: 503 })))

    await expect(getLiveness()).rejects.toThrow('Health request failed with status 503')
  })

  it('rejects invalid JSON', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response('{', { status: 200 })))

    await expect(getLiveness()).rejects.toThrow('Health response was not valid JSON')
  })

  it('rejects an unexpected health status', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ status: 'degraded' })))

    await expect(getLiveness()).rejects.toThrow('Health response had an unexpected status')
  })

  it('aborts the request after five seconds and releases its timer', async () => {
    vi.useFakeTimers()
    vi.stubGlobal(
      'fetch',
      vi.fn((_input: RequestInfo | URL, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(init.signal?.reason), { once: true })
        }),
      ),
    )

    const request = getLiveness()
    const rejection = expect(request).rejects.toMatchObject({ name: 'TimeoutError' })
    await vi.advanceTimersByTimeAsync(5_000)

    await rejection
    expect(vi.getTimerCount()).toBe(0)
  })

  it('does not start a request for an already-aborted caller signal', async () => {
    const fetchMock = vi.fn()
    vi.stubGlobal('fetch', fetchMock)
    const caller = new AbortController()
    caller.abort(new DOMException('Cancelled', 'AbortError'))

    await expect(getLiveness(caller.signal)).rejects.toMatchObject({ name: 'AbortError' })
    expect(fetchMock).not.toHaveBeenCalled()
  })

  it('honors later caller cancellation and removes its listener and timer', async () => {
    vi.useFakeTimers()
    const caller = new AbortController()
    const addSpy = vi.spyOn(caller.signal, 'addEventListener')
    const removeSpy = vi.spyOn(caller.signal, 'removeEventListener')
    vi.stubGlobal(
      'fetch',
      vi.fn((_input: RequestInfo | URL, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(init.signal?.reason), { once: true })
        }),
      ),
    )

    const request = getLiveness(caller.signal)
    caller.abort(new DOMException('Caller cancelled', 'AbortError'))

    await expect(request).rejects.toMatchObject({ name: 'AbortError' })
    expect(addSpy).toHaveBeenCalledTimes(1)
    expect(removeSpy).toHaveBeenCalledTimes(1)
    expect(removeSpy.mock.calls[0]?.[1]).toBe(addSpy.mock.calls[0]?.[1])
    expect(vi.getTimerCount()).toBe(0)
  })
})
