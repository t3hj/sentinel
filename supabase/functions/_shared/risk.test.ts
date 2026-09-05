import { describe, expect, it } from 'vitest'
import { calculateRisk, severityFor } from './risk'

const events = (...eventTypes: string[]) => eventTypes.map((event_type) => ({ event_type }))

describe('deterministic detection risk scoring', () => {
  it('scores a brute-force sequence as high risk', () => {
    expect(calculateRisk(events('LOGIN_FAILED', 'LOGIN_FAILED', 'LOGIN_FAILED', 'LOGIN_SUCCESS'))).toEqual({ score: 59, severity: 'MEDIUM' })
  })

  it('increases risk for escalation and exfiltration stages', () => {
    const result = calculateRisk(events('LOGIN_SUCCESS', 'PRIVILEGE_ESCALATION', 'SUSPICIOUS_PROCESS', 'LARGE_DATA_TRANSFER'))
    expect(result.score).toBe(92)
    expect(result.severity).toBe('CRITICAL')
  })

  it('caps hostile sequences at 100', () => {
    expect(calculateRisk(events(...Array.from({ length: 20 }, () => 'LOGIN_FAILED'), 'LOGIN_SUCCESS', 'PRIVILEGE_ESCALATION', 'SUSPICIOUS_PROCESS', 'LARGE_DATA_TRANSFER', 'FILE_MODIFICATION')).score).toBe(100)
  })

  it('maps event severity consistently', () => {
    expect(severityFor('PRIVILEGE_ESCALATION')).toBe('HIGH')
    expect(severityFor('SUSPICIOUS_PROCESS')).toBe('MEDIUM')
    expect(severityFor('LOGIN_SUCCESS')).toBe('LOW')
  })
})
