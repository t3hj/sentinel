import { audit, corsHeaders, errorResponse, json, requireContext, requireRole } from '../_shared/auth.ts'

const allowedActions = ['DISABLE_USER', 'REVOKE_SESSIONS', 'BLOCK_IP', 'ISOLATE_ENDPOINT', 'MARK_FALSE_POSITIVE']
Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders() })
  try {
    const context = await requireContext(req)
    const body = await req.json() as { operation?: string; incidentId?: string; actionType?: string; target?: string; reason?: string; actionId?: string }
    if (body.operation === 'request') {
      requireRole(context, ['ADMIN', 'ANALYST'])
      if (!body.incidentId || !body.actionType || !body.target || !body.reason || !allowedActions.includes(body.actionType)) throw new Error('Invalid remediation request')
      const { data, error } = await context.db.from('remediation_actions').insert({ incident_id: body.incidentId, action_type: body.actionType, target: body.target, reason: body.reason, requested_by: context.user.id }).select('id').single()
      if (error || !data) throw error ?? new Error('Remediation request failed')
      await audit(context, 'REMEDIATION_REQUESTED', 'remediation_action', data.id, 'SUCCESS', { action_type: body.actionType, target: body.target })
      return json({ actionId: data.id })
    }
    if (body.operation === 'approve') {
      requireRole(context, ['ADMIN'])
      if (!body.actionId) throw new Error('actionId is required')
      const { data: action, error: actionError } = await context.db.from('remediation_actions').select('*').eq('id', body.actionId).single()
      if (actionError || !action || action.status !== 'REQUESTED') throw new Error('Pending remediation action not found')
      const approvedAt = new Date().toISOString()
      const { error } = await context.db.from('remediation_actions').update({ status: 'EXECUTED', approved_by: context.user.id, approved_at: approvedAt, executed_at: approvedAt, metadata: { simulated: true, execution: 'predefined_action_only' } }).eq('id', body.actionId)
      if (error) throw error
      await audit(context, 'REMEDIATION_APPROVED', 'remediation_action', body.actionId, 'SUCCESS', { action_type: action.action_type })
      await audit(context, 'REMEDIATION_EXECUTED', 'remediation_action', body.actionId, 'SUCCESS', { simulated: true })
      return json({ actionId: body.actionId, status: 'EXECUTED' })
    }
    throw new Error('Unknown remediation operation')
  } catch (error) { return errorResponse(error) }
})
