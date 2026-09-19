/**
 * Shared request-hardening helpers for Sentinel Edge Functions.
 *
 * Design goals:
 * - No external dependencies; pure TypeScript + Web APIs.
 * - Reject oversized bodies BEFORE parsing JSON.
 * - Fail closed with controlled client-facing errors.
 * - Never leak internal implementation details.
 */

/** Strict maximum request body size for Sentinel Edge Functions. */
export const MAX_BODY_BYTES = 32 * 1024 // 32 KB

const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/

/** Error subclass marking messages that are safe to show to the client. */
export class ValidationError extends Error {}

/** Thrown for request-level rejections that map to a specific HTTP status. */
export class ClientError extends Error {
  status: number
  constructor(message: string, status = 400) {
    super(message)
    this.status = status
  }
}

/**
 * Reads the request body while enforcing the size limit BEFORE parsing.
 * Uses Content-Length when present, and additionally caps the actual number
 * of bytes streamed so a lying or absent header cannot bypass the limit.
 */
export async function readBody(req: Request): Promise<string> {
  const contentLength = Number(req.headers.get('content-length') ?? '')
  if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
    throw new ClientError('Request body exceeds the maximum allowed size', 400)
  }
  const reader = req.body?.getReader()
  if (!reader) return ''
  const decoder = new TextDecoder()
  let received = 0
  let text = ''
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    received += value.byteLength
    if (received > MAX_BODY_BYTES) {
      await reader.cancel()
      throw new ClientError('Request body exceeds the maximum allowed size', 400)
    }
    text += decoder.decode(value, { stream: true })
  }
  text += decoder.decode()
  return text
}

/**
 * Parses the request body as JSON with strict limits:
 * - 32 KB size cap enforced before parsing
 * - clean rejection of malformed JSON
 * - only top-level JSON objects, with a bounded number of fields
 */
export async function parseJsonBody(req: Request): Promise<Record<string, unknown>> {
  const raw = await readBody(req)
  let parsed: unknown
  try {
    parsed = raw.length ? JSON.parse(raw) : undefined
  } catch {
    throw new ValidationError('Request body must be valid JSON')
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new ValidationError('Request body must be a JSON object')
  }
  const body = parsed as Record<string, unknown>
  if (Object.keys(body).length > 20) throw new ValidationError('Request body has too many fields')
  return body
}

export function requireString(value: unknown, field: string, maxLength = 200): string {
  if (typeof value !== 'string' || value.length === 0) throw new ValidationError(`${field} is required`)
  if (value.length > maxLength) throw new ValidationError(`${field} exceeds the maximum length of ${maxLength} characters`)
  return value
}

export function requireUuid(value: unknown, field: string): string {
  const v = requireString(value, field, 64)
  if (!UUID_RE.test(v)) throw new ValidationError(`${field} must be a valid UUID`)
  return v
}

export function requireEnum<T extends string>(value: unknown, field: string, allowed: readonly T[]): T {
  if (typeof value !== 'string' || !allowed.includes(value as T)) {
    throw new ValidationError(`${field} must be one of: ${allowed.join(', ')}`)
  }
  return value as T
}

/**
 * Postgres-backed distributed rate limiter (no in-memory state, works across
 * Edge Function instances) using the existing service-role Supabase client.
 *
 * Fixed-window counter stored in a dedicated table. The increment happens in
 * a Postgres function (`rate_limit_hit`) via INSERT ... ON CONFLICT DO UPDATE
 * SET hits = hits + 1 RETURNING hits — a plain upsert cannot increment and
 * would reset the counter on conflict. Single round trip, race-safe under
 * concurrent requests (row-level lock held for the duration of the update).
 */
export type RateLimitRule = { windowSeconds: number; max: number }

export async function enforceRateLimit(
  db: { rpc: (fn: string, args: Record<string, unknown>) => Promise<{ data: unknown; error: { code?: string; message?: string } | null }> },
  bucket: string,
  rule: RateLimitRule,
): Promise<void> {
  const windowStart = new Date(Math.floor(Date.now() / (rule.windowSeconds * 1000)) * rule.windowSeconds * 1000).toISOString()
  const { data, error } = await db.rpc('rate_limit_hit', { p_bucket: bucket, p_window_start: windowStart })
  if (error || typeof data !== 'number') {
    // Fail closed for security-sensitive endpoints, without leaking details.
    console.error('rate limiter unavailable', { bucket, code: error?.code })
    throw new ClientError('Request could not be processed at this time', 503)
  }
  if (data > rule.max) {
    throw new ClientError('Too many requests. Please try again later.', 429)
  }
}
