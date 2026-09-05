export type AppRole = 'ADMIN' | 'ANALYST' | 'VIEWER'
export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'FALSE_POSITIVE'
export type EventType = 'LOGIN_FAILED' | 'LOGIN_SUCCESS' | 'PRIVILEGE_ESCALATION' | 'SUSPICIOUS_PROCESS' | 'UNUSUAL_NETWORK_CONNECTION' | 'LARGE_DATA_TRANSFER' | 'FILE_MODIFICATION' | 'ACCOUNT_CREATED' | 'ACCOUNT_DISABLED' | 'ENDPOINT_ALERT'
export type RemediationType = 'DISABLE_USER' | 'REVOKE_SESSIONS' | 'BLOCK_IP' | 'ISOLATE_ENDPOINT' | 'MARK_FALSE_POSITIVE'

export type UserProfile = { id: string; email: string; display_name: string; role: AppRole }
export type SecurityEvent = { id: string; timestamp: string; event_type: EventType; source: string; source_ip: string | null; destination_ip: string | null; username: string | null; hostname: string | null; process: string | null; severity: Severity; metadata: Record<string, unknown>; correlation_id: string | null; created_at: string }
export type Incident = { id: string; title: string; description: string; status: IncidentStatus; severity: Severity; risk_score: number; confidence: number; correlation_id: string | null; created_at: string; updated_at: string; resolved_at: string | null }
export type IncidentWithEvents = Incident & { incident_events: { event: SecurityEvent }[]; detection_matches: { id: string; evidence: Record<string, unknown> }[] }
export type RemediationAction = { id: string; incident_id: string; action_type: RemediationType; target: string; reason: string; status: string; requested_by: string; approved_by: string | null; requested_at: string; approved_at: string | null; executed_at: string | null }
export type DashboardData = { incidents: Incident[]; events: SecurityEvent[]; assets: { id: string; hostname: string; asset_type: string; criticality: Severity }[]; eventCount: number }
