import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import {
  checkHealth,
  computeAdd,
  OracleOfflineError,
  InvalidCiphertextError,
  OracleInitializingError,
  OracleTimeoutError
} from './apiClient'

/** Build a minimal fetch Response stand-in. */
function mockResponse(opts: { ok: boolean; status: number; body?: unknown; nonJson?: boolean }) {
  return {
    ok: opts.ok,
    status: opts.status,
    json: async () => {
      if (opts.nonJson) throw new SyntaxError('Unexpected token < in JSON')
      return opts.body
    }
  } as unknown as Response
}

const fetchMock = vi.fn()

beforeEach(() => {
  vi.stubGlobal('fetch', fetchMock)
  fetchMock.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.useRealTimers()
})

describe('checkHealth', () => {
  it('returns true when the body reports fhe: true', async () => {
    fetchMock.mockResolvedValue(mockResponse({ ok: true, status: 200, body: { fhe: true } }))
    expect(await checkHealth()).toBe(true)
  })

  it('returns true when the body reports status: "ok"', async () => {
    fetchMock.mockResolvedValue(mockResponse({ ok: true, status: 200, body: { status: 'ok' } }))
    expect(await checkHealth()).toBe(true)
  })

  it('returns false when the body is healthy-shaped but neither flag is set', async () => {
    fetchMock.mockResolvedValue(mockResponse({ ok: true, status: 200, body: { status: 'warn' } }))
    expect(await checkHealth()).toBe(false)
  })

  it('returns false on a non-ok response', async () => {
    fetchMock.mockResolvedValue(mockResponse({ ok: false, status: 503 }))
    expect(await checkHealth()).toBe(false)
  })

  it('returns false when the request rejects (network error)', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
    expect(await checkHealth()).toBe(false)
  })
})

describe('computeAdd', () => {
  const okBody = {
    ctResult: 'cmVzdWx0', // "result"
    operation: 'add',
    plaintextAccessed: false,
    scheme: 'TFHE-rs',
    bootstrapping: 'gate_bootstrapping_per_operation',
    tfheVersion: '1.8'
  }

  it('maps a successful response into a ComputeResult', async () => {
    fetchMock.mockResolvedValue(mockResponse({ ok: true, status: 200, body: okBody }))
    const result = await computeAdd('key', 'ctA', 'ctB')
    expect(result.ctResultBase64).toBe('cmVzdWx0')
    expect(result.operation).toBe('add')
    expect(result.plaintextAccessed).toBe(false)
    expect(result.scheme).toBe('TFHE-rs')
    expect(result.tfheVersion).toBe('1.8')
    const request = fetchMock.mock.calls[0]?.[1] as RequestInit
    expect(JSON.parse(String(request.body))).toEqual({
      serverKey: 'key',
      ctA: 'ctA',
      ctB: 'ctB',
      tfheVersion: '1.8'
    })
    expect(typeof result.responseTimeMs).toBe('number')
  })

  it('coerces a missing plaintextAccessed flag to false', async () => {
    const body = { ctResult: 'x', operation: 'add', tfheVersion: '1.8' }
    fetchMock.mockResolvedValue(mockResponse({ ok: true, status: 200, body }))
    const result = await computeAdd('key', 'ctA', 'ctB')
    expect(result.plaintextAccessed).toBe(false)
    expect(result.scheme).toBe('TFHE-rs') // default applied
  })

  it('throws OracleInitializingError on HTTP 503', async () => {
    fetchMock.mockResolvedValue(
      mockResponse({ ok: false, status: 503, body: { error: 'warming' } })
    )
    await expect(computeAdd('key', 'ctA', 'ctB')).rejects.toBeInstanceOf(OracleInitializingError)
  })

  it('throws InvalidCiphertextError on HTTP 400', async () => {
    fetchMock.mockResolvedValue(mockResponse({ ok: false, status: 400, body: { error: 'bad ct' } }))
    await expect(computeAdd('key', 'ctA', 'ctB')).rejects.toBeInstanceOf(InvalidCiphertextError)
  })

  it('throws OracleOfflineError on other HTTP errors', async () => {
    fetchMock.mockResolvedValue(mockResponse({ ok: false, status: 500, nonJson: true }))
    await expect(computeAdd('key', 'ctA', 'ctB')).rejects.toBeInstanceOf(OracleOfflineError)
  })

  it('throws OracleOfflineError on a malformed success body', async () => {
    fetchMock.mockResolvedValue(mockResponse({ ok: true, status: 200, body: { operation: 'add' } }))
    await expect(computeAdd('key', 'ctA', 'ctB')).rejects.toThrow('Malformed compute response')
  })

  it('rejects a response from a mismatched TFHE runtime', async () => {
    fetchMock.mockResolvedValue(
      mockResponse({
        ok: true,
        status: 200,
        body: { ctResult: 'x', operation: 'add', tfheVersion: '0.8' }
      })
    )
    await expect(computeAdd('key', 'ctA', 'ctB')).rejects.toThrow('Malformed compute response')
  })

  it('maps a network TypeError to OracleOfflineError', async () => {
    fetchMock.mockRejectedValue(new TypeError('Failed to fetch'))
    await expect(computeAdd('key', 'ctA', 'ctB')).rejects.toBeInstanceOf(OracleOfflineError)
  })

  it('maps an aborted request to OracleTimeoutError', async () => {
    fetchMock.mockRejectedValue(new DOMException('aborted', 'AbortError'))
    await expect(computeAdd('key', 'ctA', 'ctB')).rejects.toBeInstanceOf(OracleTimeoutError)
  })

  it('invokes onWake once when the request is slow (>5s)', async () => {
    vi.useFakeTimers()
    let resolveFetch: (r: Response) => void = () => {}
    fetchMock.mockReturnValue(
      new Promise<Response>((resolve) => {
        resolveFetch = resolve
      })
    )

    const onWake = vi.fn()
    const pending = computeAdd('key', 'ctA', 'ctB', onWake)

    await vi.advanceTimersByTimeAsync(5000)
    expect(onWake).toHaveBeenCalledTimes(1)

    resolveFetch(mockResponse({ ok: true, status: 200, body: okBody }))
    await pending
    expect(onWake).toHaveBeenCalledTimes(1) // not re-invoked after completion
  })
})
