import { describe, expect, it } from 'vitest'
import { MAX_BODY_BYTES, ClientError, requireEnum, requireString, requireUuid } from './validation.ts'

const error = (fn: () => unknown) => {
  try { fn(); return null } catch (e) { return e as Error }
}

describe('request validation helpers', () => {
  it('rejects non-UUID values', () => {
    expect(error(() => requireUuid('not-a-uuid', 'incidentId'))).toBeInstanceOf(Error)
    expect(requireUuid('3fa85f64-5717-4562-b3fc-2c963f66afa6', 'incidentId')).toBe('3fa85f64-5717-4562-b3fc-2c963f66afa6')
  })

  it('rejects missing and overly long strings', () => {
    expect(error(() => requireString(undefined, 'target'))).toBeInstanceOf(Error)
    expect(error(() => requireString('', 'target'))).toBeInstanceOf(Error)
    expect(error(() => requireString('x'.repeat(201), 'target', 200))).toBeInstanceOf(Error)
    expect(requireString('short', 'target', 200)).toBe('short')
  })

  it('enforces the allowlist for enums', () => {
    expect(error(() => requireEnum('DROP_TABLE', 'scenario', ['BRUTE_FORCE'] as const))).toBeInstanceOf(Error)
    expect(requireEnum('BRUTE_FORCE', 'scenario', ['BRUTE_FORCE'] as const)).toBe('BRUTE_FORCE')
  })

  it('defines the 32 KB body limit', () => {
    expect(MAX_BODY_BYTES).toBe(32 * 1024)
  })

  it('uses ClientError for HTTP-mapped rejections', () => {
    const e = new ClientError('Too many requests. Please try again later.', 429)
    expect(e.status).toBe(429)
  })
})
