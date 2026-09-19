import { audit, corsHeaders, errorResponse, json, requireContext, requireRole } from '../_shared/auth.ts'
import { ClientError, enforceRateLimit, parseJsonBody, requireEnum, requireUuid } from '../_shared/validation.ts'

const allowed = ['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE'] as const
Deno.serve(async (req) => {
  const origin = req.headers.get('Origin')
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders(origin) })
  if (req.method !== 'POST') throw new ClientError('Method not allowed', 405)
  try {
    const context = await requireContext(req)
    requireRole(context, ['ADMIN', 'ANALYST'])
    await enforceRateLimit(context.db, `incident-status:${context.user.id}`, { windowSeconds: 60, max: 20 })
    const body = await parseJsonBody(req)
    const incidentId = requireUuid(body.incidentId, 'incidentId')
    const status = requireEnum(body.status, 'status', allowed)
    const { error } = await context.db.from('incidents').update({ status, resolved_at: ['RESOLVED', 'FALSE_POSITIVE'].includes(status) ? new Date().toISOString() : null }).eq('id', incidentId)
    if (error) throw error
    await audit(context, 'INCIDENT_UPDATED', 'incident', incidentId, 'SUCCESS', { status })
    return json({ incidentId, status })
  } catch (error) { return errorResponse(error, origin) }
})
