import { useEffect, useState } from 'react'
import { getDetectionRules, getPlaybooks, getRecentAuditLogs, getUsers, setDetectionRuleEnabled, setUserRole } from './lib/securityService'
import type { AppRole, AuditLog, DetectionRule, Playbook, UserProfile } from './lib/types'

const roles: AppRole[] = ['ADMIN', 'ANALYST', 'VIEWER']

export function AdminConsole() {
  const [rules, setRules] = useState<DetectionRule[]>([])
  const [playbooks, setPlaybooks] = useState<Playbook[]>([])
  const [users, setUsers] = useState<UserProfile[]>([])
  const [logs, setLogs] = useState<AuditLog[]>([])
  const [error, setError] = useState('')
  const [saving, setSaving] = useState('')
  const load = () => Promise.all([getDetectionRules(), getPlaybooks(), getUsers(), getRecentAuditLogs()]).then(([nextRules, nextPlaybooks, nextUsers, nextLogs]) => { setRules(nextRules); setPlaybooks(nextPlaybooks); setUsers(nextUsers); setLogs(nextLogs) }).catch((reason) => setError(reason instanceof Error ? reason.message : 'Admin data query failed'))
  useEffect(() => { void load() }, [])
  const toggleRule = async (rule: DetectionRule) => { setSaving(rule.id); setError(''); try { await setDetectionRuleEnabled(rule.id, !rule.enabled); await load() } catch (reason) { setError(reason instanceof Error ? reason.message : 'Rule update failed') } finally { setSaving('') } }
  const changeRole = async (user: UserProfile, role: AppRole) => { setSaving(user.id); setError(''); try { await setUserRole(user.id, role); await load() } catch (reason) { setError(reason instanceof Error ? reason.message : 'Role update failed') } finally { setSaving('') } }
  if (error && !rules.length && !playbooks.length && !users.length) return <div className="state error-state"><strong>Admin console unavailable</strong><span>{error}</span></div>
  return <div className="admin-grid">
    <article className="panel table-panel"><div className="panel-title"><div><h2>Detection rules</h2><p>RLS-protected rule controls for administrators</p></div><span className="status">{rules.filter((rule) => rule.enabled).length} enabled</span></div>{rules.map((rule) => <div className="admin-row" key={rule.id}><div><strong>{rule.name}</strong><small>{rule.description}</small><code>{rule.rule_type} · {JSON.stringify(rule.definition)}</code></div><button className={rule.enabled ? 'secondary' : 'primary'} disabled={saving === rule.id} onClick={() => toggleRule(rule)}>{saving === rule.id ? 'Saving...' : rule.enabled ? 'Disable' : 'Enable'}</button></div>)}</article>
    <article className="panel table-panel"><div className="panel-title"><div><h2>Response playbooks</h2><p>Predefined remediation sequences</p></div><span className="status">{playbooks.length} configured</span></div>{playbooks.map((playbook) => <div className="admin-row" key={playbook.id}><div><strong>{playbook.name}</strong><small>{playbook.description}</small><code>{playbook.actions.join(' · ')} · requires {playbook.required_role}</code></div><span className={playbook.enabled ? 'status' : 'muted'}>{playbook.enabled ? 'READY' : 'DISABLED'}</span></div>)}</article>
    <article className="panel table-panel"><div className="panel-title"><div><h2>Workspace users</h2><p>Server-side role assignments</p></div><span className="status">{users.length} accounts</span></div>{users.map((user) => <div className="admin-row" key={user.id}><div><strong>{user.display_name || 'Unnamed analyst'}</strong><small>{user.email}</small></div><select value={user.role} disabled={saving === user.id} onChange={(event) => changeRole(user, event.target.value as AppRole)}>{roles.map((role) => <option key={role}>{role}</option>)}</select></div>)}</article>
    <article className="panel table-panel"><div className="panel-title"><div><h2>Audit log</h2><p>Recent security workflow activity</p></div><span className="status">Last 50 records</span></div>{logs.length ? logs.map((log) => <div className="admin-row audit-admin-row" key={log.id}><div><strong>{log.action}</strong><small>{log.resource}{log.resource_id ? ` · ${log.resource_id.slice(0, 8)}` : ''}</small></div><span>{log.result}</span><small>{new Date(log.timestamp).toLocaleString()}</small></div>) : <div className="empty">No audit records are available.</div>}</article>
    {error && <div className="form-note">{error}</div>}
  </div>
}
