import { audit, corsHeaders, errorResponse, json, requireContext, requireRole } from '../_shared/auth.ts'

const allowed = ['OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE']
Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders() })
  try {
    const context = await requireContext(req)
    requireRole(context, ['ADMIN', 'ANALYST'])
    const { incidentId, status } = await req.json() as { incidentId?: string; status?: string }
    if (!incidentId || !status || !allowed.includes(status)) throw new Error('Valid incidentId and status are required')
    const { error } = await context.db.from('incidents').update({ status, resolved_at: ['RESOLVED', 'FALSE_POSITIVE'].includes(status) ? new Date().toISOString() : null }).eq('id', incidentId)
    if (error) throw error
    await audit(context, 'INCIDENT_UPDATED', 'incident', incidentId, 'SUCCESS', { status })
    return json({ incidentId, status })
  } catch (error) { return errorResponse(error) }
})
