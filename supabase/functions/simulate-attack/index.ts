import { createClient } from 'https://esm.sh/@supabase/supabase-js@2'
import { audit, corsHeaders, errorResponse, json, requireContext, requireRole } from '../_shared/auth.ts'
import { calculateRisk, severityFor } from '../_shared/risk.ts'

const scenarios = {
  BRUTE_FORCE: ['LOGIN_FAILED', 'LOGIN_FAILED', 'LOGIN_FAILED', 'LOGIN_FAILED', 'LOGIN_SUCCESS'],
  ACCOUNT_COMPROMISE: ['LOGIN_FAILED', 'LOGIN_FAILED', 'LOGIN_FAILED', 'LOGIN_SUCCESS', 'PRIVILEGE_ESCALATION', 'SUSPICIOUS_PROCESS', 'UNUSUAL_NETWORK_CONNECTION', 'LARGE_DATA_TRANSFER'],
  PRIVILEGE_ESCALATION: ['LOGIN_SUCCESS', 'PRIVILEGE_ESCALATION', 'SUSPICIOUS_PROCESS'],
  DATA_EXFILTRATION: ['LOGIN_SUCCESS', 'SUSPICIOUS_PROCESS', 'UNUSUAL_NETWORK_CONNECTION', 'LARGE_DATA_TRANSFER'],
  MULTI_STAGE: ['LOGIN_FAILED', 'LOGIN_FAILED', 'LOGIN_FAILED', 'LOGIN_SUCCESS', 'PRIVILEGE_ESCALATION', 'SUSPICIOUS_PROCESS', 'UNUSUAL_NETWORK_CONNECTION', 'LARGE_DATA_TRANSFER', 'FILE_MODIFICATION'],
} as const

const scenarioTitle = (scenario: string) => ({ BRUTE_FORCE: 'Brute force authentication', ACCOUNT_COMPROMISE: 'Possible account compromise', PRIVILEGE_ESCALATION: 'Suspicious privilege escalation', DATA_EXFILTRATION: 'Suspicious outbound transfer', MULTI_STAGE: 'Multi-stage attack detected' }[scenario] ?? 'Synthetic security incident')

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders() })
  try {
    const context = await requireContext(req)
    requireRole(context, ['ADMIN', 'ANALYST'])
    const { scenario } = await req.json() as { scenario?: keyof typeof scenarios }
    if (!scenario || !scenarios[scenario]) throw new Error('Unknown simulation scenario')
    const correlationId = crypto.randomUUID()
    const now = Date.now()
    const eventTypes = scenarios[scenario]
    const events = eventTypes.map((eventType, index) => ({
      timestamp: new Date(now - (eventTypes.length - index) * 45_000).toISOString(),
      event_type: eventType,
      source: 'sentinel-synthetic-sensor',
      source_ip: '185.220.101.4',
      destination_ip: eventType === 'LARGE_DATA_TRANSFER' ? '203.0.113.40' : null,
      username: 'synthetic.user',
      hostname: 'sentinel-lab-01',
      process: eventType === 'SUSPICIOUS_PROCESS' ? 'encoded-powershell.exe' : null,
      severity: severityFor(eventType),
      metadata: { synthetic: true, scenario, sequence: index + 1 },
      correlation_id: correlationId,
      ingested_by: context.user.id,
    }))
    const { data: insertedEvents, error: eventError } = await context.db.from('security_events').insert(events).select('id,event_type')
    if (eventError || !insertedEvents) throw eventError ?? new Error('Events were not inserted')
    const { score, severity } = calculateRisk(insertedEvents)
    const { data: incident, error: incidentError } = await context.db.from('incidents').insert({ title: scenarioTitle(scenario), description: `Synthetic ${scenario.toLowerCase().replaceAll('_', ' ')} sequence detected by the Sentinel detection engine.`, status: 'OPEN', severity, risk_score: score, confidence: Math.min(99, 70 + insertedEvents.length * 3), correlation_id: correlationId }).select().single()
    if (incidentError || !incident) throw incidentError ?? new Error('Incident was not created')
    await context.db.from('incident_events').insert(insertedEvents.map((event) => ({ incident_id: incident.id, event_id: event.id, relation: 'correlated sequence' })))
    const { data: rules } = await context.db.from('detection_rules').select('id,name').eq('enabled', true)
    const matchingRules = (rules ?? []).filter((rule) => (rule.name.includes('Brute') && insertedEvents.filter((event) => event.event_type === 'LOGIN_FAILED').length >= 3) || (rule.name.includes('Privilege') && insertedEvents.some((event) => event.event_type === 'PRIVILEGE_ESCALATION')) || (rule.name.includes('exfiltration') && insertedEvents.some((event) => event.event_type === 'LARGE_DATA_TRANSFER')))
    if (matchingRules.length) await context.db.from('detection_matches').insert(matchingRules.map((rule) => ({ rule_id: rule.id, incident_id: incident.id, event_ids: insertedEvents.map((event) => event.id), evidence: { matched_event_types: insertedEvents.map((event) => event.event_type), deterministic_score: score } })))
    await audit(context, 'SYNTHETIC_ATTACK_SIMULATED', 'incident', incident.id, 'SUCCESS', { scenario, event_count: insertedEvents.length, risk_score: score })
    return json({ incident, eventCount: insertedEvents.length })
  } catch (error) { return errorResponse(error) }
})
