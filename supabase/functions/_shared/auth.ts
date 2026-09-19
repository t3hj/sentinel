import { createClient, type SupabaseClient, type User } from 'https://esm.sh/@supabase/supabase-js@2'

import { ClientError, ValidationError } from './validation.ts'

export type Context = { user: User; role: 'ADMIN' | 'ANALYST' | 'VIEWER'; db: SupabaseClient }

/**
 * CORS: restricted to known legitimate frontend origins. The production
 * origin is not confirmed anywhere in the repository, so this defaults to
 * localhost dev servers and is overridable per-deployment via the
 * ALLOWED_ORIGIN environment variable. Update when production origin is known.
 */
const allowedOrigins = [
  ...(Deno.env.get('ALLOWED_ORIGIN') ? [Deno.env.get('ALLOWED_ORIGIN')!] : []),
  'http://localhost:5173',
  'http://127.0.0.1:5173',
  'http://localhost:4173',
  'http://127.0.0.1:4173',
]

export function corsHeaders(origin: string | null = null) {
  const allowedOrigin = origin && allowedOrigins.includes(origin) ? origin : allowedOrigins[0]
  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Vary': 'Origin',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
  }
}

/** Deliberate, client-safe errors thrown by requireContext/requireRole. */
const SAFE_ERROR_MESSAGES = new Set(['Authentication required', 'Invalid authentication token', 'User profile is not provisioned', 'Insufficient permissions'])
const SAFE_ERROR_STATUSES = new Map([
  ['Authentication required', 401],
  ['Invalid authentication token', 401],
  ['User profile is not provisioned', 403],
  ['Insufficient permissions', 403],
])

/** Known-safe errors thrown by function logic (not derived from user input). */
const SAFE_FUNCTION_ERRORS = new Set(['Incident not found', 'Pending remediation action not found', 'Remediation request failed', 'Investigation could not be stored', 'Events were not inserted', 'Incident was not created'])

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

export function json(data: unknown, status = 200, origin: string | null = null) {
  return new Response(JSON.stringify(data), { status, headers: { ...corsHeaders(origin), 'Content-Type': 'application/json' } })
}

/**
 * Converts an error into a safe client response.
 * Only messages from ValidationError / ClientError are considered deliberate
 * client-facing errors. Anything else (database errors, unexpected faults)
 * is logged server-side and replaced with a generic safe message so internal
 * details (SQL, constraints, stack traces, env vars) are never exposed.
 */
export function errorResponse(error: unknown, origin: string | null = null) {
  if (error instanceof ValidationError) return json({ error: error.message }, 400, origin)
  if (error instanceof ClientError) return json({ error: error.message }, error.status, origin)
  if (error instanceof Error && SAFE_ERROR_MESSAGES.has(error.message)) {
    return json({ error: error.message }, SAFE_ERROR_STATUSES.get(error.message) ?? 400, origin)
  }
  if (error instanceof Error && SAFE_FUNCTION_ERRORS.has(error.message)) {
    return json({ error: error.message }, 404, origin)
  }
  console.error('edge function error', { name: error instanceof Error ? error.name : typeof error })
  return json({ error: 'An internal server error occurred.' }, 500, origin)
}
