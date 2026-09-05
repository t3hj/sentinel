import { audit, corsHeaders, errorResponse, json, requireContext, requireRole } from '../_shared/auth.ts'

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders() })
  try {
    const context = await requireContext(req)
    requireRole(context, ['ADMIN', 'ANALYST'])
    const { incidentId } = await req.json() as { incidentId?: string }
    if (!incidentId) throw new Error('incidentId is required')
    const { data: incident, error: incidentError } = await context.db.from('incidents').select('*').eq('id', incidentId).single()
    if (incidentError || !incident) throw new Error('Incident not found')
    const { data: links, error: linkError } = await context.db.from('incident_events').select('event:security_events(*)').eq('incident_id', incidentId)
    if (linkError) throw linkError
    const events = (links ?? []).map((link) => (link as { event: unknown }).event)
    const eventTypes = events.map((event) => (event as { event_type: string }).event_type)
    const findings = { attack_stages: ['initial access', ...(eventTypes.includes('PRIVILEGE_ESCALATION') ? ['privilege escalation'] : []), ...(eventTypes.includes('SUSPICIOUS_PROCESS') ? ['execution'] : []), ...(eventTypes.includes('LARGE_DATA_TRANSFER') ? ['exfiltration'] : [])], evidence_based: true, inference: 'The sequence and shared correlation identifier indicate one coordinated synthetic activity window.', event_count: events.length }
    const recommendation = eventTypes.includes('LARGE_DATA_TRANSFER') ? { action: 'ISOLATE_ENDPOINT', target: 'sentinel-lab-01', reason: 'Contain the endpoint while preserving evidence.' } : { action: 'REVOKE_SESSIONS', target: 'synthetic.user', reason: 'Invalidate sessions after suspicious authentication.' }
    const { data: investigation, error: investigationError } = await context.db.from('ai_investigations').insert({ incident_id: incidentId, started_by: context.user.id, status: 'COMPLETED', evidence: events, findings, risk_explanation: `Deterministic risk score ${incident.risk_score}/100 based on event sequence, severity, and correlated indicators.`, recommendation, completed_at: new Date().toISOString() }).select('id').single()
    if (investigationError || !investigation) throw investigationError ?? new Error('Investigation could not be stored')
    await context.db.from('incidents').update({ status: 'INVESTIGATING' }).eq('id', incidentId)
    await audit(context, 'AI_INVESTIGATION_STARTED', 'incident', incidentId, 'SUCCESS', { investigation_id: investigation.id, approved_tools: ['get_incident_events'] })
    await audit(context, 'AI_TOOL_CALLED', 'incident', incidentId, 'SUCCESS', { tool: 'get_incident_events', result_count: events.length })
    return json({ investigationId: investigation.id, findings, recommendation })
  } catch (error) { return errorResponse(error) }
})
