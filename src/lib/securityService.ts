import { supabase } from './supabase'
import type { AppRole, DashboardData, Incident, IncidentWithEvents, RemediationType, SecurityEvent, UserProfile } from './types'

export async function getCurrentProfile(): Promise<UserProfile | null> {
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return null
  const { data, error } = await supabase.from('users').select('id,email,display_name,role').eq('id', user.id).single()
  if (error) throw error
  return data as UserProfile
}

export async function getDashboardData(): Promise<DashboardData> {
  const [{ data: incidents, error: incidentError }, { data: events, error: eventError }, { data: assets, error: assetError }, { count, error: countError }] = await Promise.all([
    supabase.from('incidents').select('*').order('risk_score', { ascending: false }).limit(10),
    supabase.from('security_events').select('*').order('timestamp', { ascending: false }).limit(20),
    supabase.from('assets').select('id,hostname,asset_type,criticality').order('hostname').limit(10),
    supabase.from('security_events').select('*', { count: 'exact', head: true }),
  ])
  if (incidentError || eventError || assetError || countError) throw incidentError ?? eventError ?? assetError ?? countError
  return { incidents: (incidents ?? []) as Incident[], events: (events ?? []) as SecurityEvent[], assets: assets ?? [], eventCount: count ?? 0 }
}

export async function getIncident(id: string): Promise<IncidentWithEvents> {
  const { data, error } = await supabase.from('incidents').select('*, incident_events(event:security_events(*)), detection_matches(id,evidence)').eq('id', id).single()
  if (error) throw error
  return data as unknown as IncidentWithEvents
}

export async function getEvents(filters: { search?: string; severity?: string; eventType?: string; page?: number; pageSize?: number }) {
  const page = filters.page ?? 0
  const pageSize = filters.pageSize ?? 25
  let query = supabase.from('security_events').select('*', { count: 'exact' }).order('timestamp', { ascending: false }).range(page * pageSize, page * pageSize + pageSize - 1)
  if (filters.severity) query = query.eq('severity', filters.severity)
  if (filters.eventType) query = query.eq('event_type', filters.eventType)
  if (filters.search) query = query.or(`source.ilike.%${filters.search}%,username.ilike.%${filters.search}%,hostname.ilike.%${filters.search}%`)
  const { data, count, error } = await query
  if (error) throw error
  return { events: (data ?? []) as SecurityEvent[], count: count ?? 0 }
}

export async function invokeSecurityFunction<T>(name: string, body: Record<string, unknown>): Promise<T> {
  const { data, error } = await supabase.functions.invoke(name, { body })
  if (error) throw error
  return data as T
}

export async function simulateAttack(scenario: string) { return invokeSecurityFunction<{ incident: Incident | null; eventCount: number }>('simulate-attack', { scenario }) }
export async function investigateIncident(incidentId: string) { return invokeSecurityFunction<{ investigationId: string }>('investigate-incident', { incidentId }) }
export async function requestRemediation(incidentId: string, actionType: RemediationType, target: string, reason: string) { return invokeSecurityFunction<{ actionId: string }>('remediation', { operation: 'request', incidentId, actionType, target, reason }) }
export async function approveRemediation(actionId: string) { return invokeSecurityFunction<{ actionId: string }>('remediation', { operation: 'approve', actionId }) }
export async function updateIncidentStatus(incidentId: string, status: string) { return invokeSecurityFunction<{ incidentId: string }>('incident-status', { incidentId, status }) }
export async function signIn(email: string, password: string) { return supabase.auth.signInWithPassword({ email, password }) }
export async function signOut() { return supabase.auth.signOut() }
export async function signUp(email: string, password: string, displayName: string) { return supabase.auth.signUp({ email, password, options: { data: { display_name: displayName } } }) }
export async function getRole(): Promise<AppRole | null> { const profile = await getCurrentProfile(); return profile?.role ?? null }
