import { useEffect, useState } from 'react'
import { getDetectionRules, getPlaybooks, setDetectionRuleEnabled } from './lib/securityService'
import type { DetectionRule, Playbook } from './lib/types'

export function AdminConsole() {
  const [rules, setRules] = useState<DetectionRule[]>([])
  const [playbooks, setPlaybooks] = useState<Playbook[]>([])
  const [error, setError] = useState('')
  const [saving, setSaving] = useState('')
  const load = () => Promise.all([getDetectionRules(), getPlaybooks()]).then(([nextRules, nextPlaybooks]) => { setRules(nextRules); setPlaybooks(nextPlaybooks) }).catch((reason) => setError(reason instanceof Error ? reason.message : 'Admin data query failed'))
  useEffect(() => { void load() }, [])
  const toggle = async (rule: DetectionRule) => { setSaving(rule.id); setError(''); try { await setDetectionRuleEnabled(rule.id, !rule.enabled); await load() } catch (reason) { setError(reason instanceof Error ? reason.message : 'Rule update failed') } finally { setSaving('') } }
  if (error && !rules.length && !playbooks.length) return <div className="state error-state"><strong>Admin console unavailable</strong><span>{error}</span></div>
  return <div className="admin-grid">
    <article className="panel table-panel"><div className="panel-title"><div><h2>Detection rules</h2><p>RLS-protected rule controls for administrators</p></div><span className="status">{rules.filter((rule) => rule.enabled).length} enabled</span></div>{rules.map((rule) => <div className="admin-row" key={rule.id}><div><strong>{rule.name}</strong><small>{rule.description}</small><code>{rule.rule_type} · {JSON.stringify(rule.definition)}</code></div><button className={rule.enabled ? 'secondary' : 'primary'} disabled={saving === rule.id} onClick={() => toggle(rule)}>{saving === rule.id ? 'Saving...' : rule.enabled ? 'Disable' : 'Enable'}</button></div>)}</article>
    <article className="panel table-panel"><div className="panel-title"><div><h2>Response playbooks</h2><p>Predefined remediation sequences</p></div><span className="status">{playbooks.length} configured</span></div>{playbooks.map((playbook) => <div className="admin-row" key={playbook.id}><div><strong>{playbook.name}</strong><small>{playbook.description}</small><code>{playbook.actions.join(' · ')} · requires {playbook.required_role}</code></div><span className={playbook.enabled ? 'status' : 'muted'}>{playbook.enabled ? 'READY' : 'DISABLED'}</span></div>)}</article>
  </div>
}
