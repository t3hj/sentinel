export type RiskEvent = { event_type: string }

export function severityFor(eventType: string) {
  return eventType === 'PRIVILEGE_ESCALATION' || eventType === 'LARGE_DATA_TRANSFER' ? 'HIGH' : eventType === 'SUSPICIOUS_PROCESS' || eventType === 'UNUSUAL_NETWORK_CONNECTION' ? 'MEDIUM' : 'LOW'
}

export function calculateRisk(events: RiskEvent[]) {
  const has = (eventType: string) => events.some((event) => event.event_type === eventType)
  const failedLogins = events.filter((event) => event.event_type === 'LOGIN_FAILED').length
  const score = Math.min(100, 20 + failedLogins * 8 + (has('LOGIN_SUCCESS') ? 15 : 0) + (has('PRIVILEGE_ESCALATION') ? 25 : 0) + (has('SUSPICIOUS_PROCESS') ? 12 : 0) + (has('LARGE_DATA_TRANSFER') ? 20 : 0) + (has('FILE_MODIFICATION') ? 8 : 0))
  const severity = score >= 80 ? 'CRITICAL' : score >= 60 ? 'HIGH' : score >= 35 ? 'MEDIUM' : 'LOW'
  return { score, severity }
}
