import { audit, corsHeaders, errorResponse, json, requireContext, requireRole } from '../_shared/auth.ts'
import { ClientError, enforceRateLimit, parseJsonBody, requireEnum, requireString, requireUuid } from '../_shared/validation.ts'

const allowedActions = ['DISABLE_USER', 'REVOKE_SESSIONS', 'BLOCK_IP', 'ISOLATE_ENDPOINT', 'MARK_FALSE_POSITIVE'] as const

Deno.serve(async (req) => {
  const origin = req.headers.get('Origin')
  if (req.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders(origin) })
  if (req.method !== 'POST') throw new ClientError('Method not allowed', 405)
  try {
    const context = await requireContext(req)
    const body = await parseJsonBody(req)
    const operation = requireEnum(body.operation, 'operation', ['request', 'approve'] as const)
    if (operation === 'request') {
      requireRole(context, ['ADMIN', 'ANALYST'])
      await enforceRateLimit(context.db, `remediation:${context.user.id}`, { windowSeconds: 60, max: 10 })
      const incidentId = requireUuid(body.incidentId, 'incidentId')
      const actionType = requireEnum(body.actionType, 'actionType', allowedActions)
      const target = requireString(body.target, 'target', 200)
      const reason = requireString(body.reason, 'reason', 1000)
      const { data, error } = await context.db.from('remediation_actions').insert({ incident_id: incidentId, action_type: actionType, target, reason, requested_by: context.user.id }).select('id').single()
      if (error || !data) throw error ?? new Error('Remediation request failed')
      await audit(context, 'REMEDIATION_REQUESTED', 'remediation_action', data.id, 'SUCCESS', { action_type: actionType, target })
      return json({ actionId: data.id })
    }
    if (operation === 'approve') {
      requireRole(context, ['ADMIN'])
      await enforceRateLimit(context.db, `remediation:${context.user.id}`, { windowSeconds: 60, max: 10 })
      const actionId = requireUuid(body.actionId, 'actionId')
      const { data: action, error: actionError } = await context.db.from('remediation_actions').select('*').eq('id', actionId).single()
      if (actionError || !action || action.status !== 'REQUESTED') throw new Error('Pending remediation action not found')
      const approvedAt = new Date().toISOString()
      const { error } = await context.db.from('remediation_actions').update({ status: 'EXECUTED', approved_by: context.user.id, approved_at: approvedAt, executed_at: approvedAt, metadata: { simulated: true, execution: 'predefined_action_only' } }).eq('id', actionId)
      if (error) throw error
      await audit(context, 'REMEDIATION_APPROVED', 'remediation_action', actionId, 'SUCCESS', { action_type: action.action_type })
      await audit(context, 'REMEDIATION_EXECUTED', 'remediation_action', actionId, 'SUCCESS', { simulated: true })
      return json({ actionId, status: 'EXECUTED' })
    }
    throw new ClientError('Unknown remediation operation')
  } catch (error) { return errorResponse(error, origin) }
})
