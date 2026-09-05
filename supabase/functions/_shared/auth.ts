import { createClient, type SupabaseClient, type User } from 'https://esm.sh/@supabase/supabase-js@2'

export type Context = { user: User; role: 'ADMIN' | 'ANALYST' | 'VIEWER'; db: SupabaseClient }

export function corsHeaders() {
  return { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type', 'Access-Control-Allow-Methods': 'POST, OPTIONS' }
}

export async function requireContext(req: Request): Promise<Context> {
  const authHeader = req.headers.get('Authorization')
  if (!authHeader?.startsWith('Bearer ')) throw new Error('Authentication required')
  const url = Deno.env.get('SUPABASE_URL')!
  const anonKey = Deno.env.get('SUPABASE_ANON_KEY')!
  const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!
  const userClient = createClient(url, anonKey, { global: { headers: { Authorization: authHeader } } })
  const { data: { user }, error: userError } = await userClient.auth.getUser()
  if (userError || !user) throw new Error('Invalid authentication token')
  const db = createClient(url, serviceKey, { auth: { autoRefreshToken: false, persistSession: false } })
  const { data: profile, error: profileError } = await db.from('users').select('role').eq('id', user.id).single()
  if (profileError || !profile) throw new Error('User profile is not provisioned')
  return { user, role: profile.role, db }
}

export function requireRole(context: Context, roles: Context['role'][]) {
  if (!roles.includes(context.role)) throw new Error('Insufficient permissions')
}

export async function audit(context: Context, action: string, resource: string, resourceId: string | null, result: string, metadata: Record<string, unknown> = {}) {
  await context.db.from('audit_logs').insert({ actor: context.user.id, action, resource, resource_id: resourceId, result, metadata })
}

export function json(data: unknown, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { ...corsHeaders(), 'Content-Type': 'application/json' } })
}

export function errorResponse(error: unknown) {
  const message = error instanceof Error ? error.message : 'Unexpected server error'
  const status = message.includes('Authentication') || message.includes('token') ? 401 : message.includes('permissions') ? 403 : 400
  return json({ error: message }, status)
}
