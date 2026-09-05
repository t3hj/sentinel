import type { IncidentWithEvents } from './lib/types'

export function IncidentEvidence({ incident }: { incident: IncidentWithEvents }) {
  const users = [...new Set(incident.incident_events.map(({ event }) => event.username).filter(Boolean))]
  const assets = [...new Set(incident.incident_events.map(({ event }) => event.hostname).filter(Boolean))]
  return <section className="evidence-grid">
    <article className="panel evidence-panel">
      <div className="panel-title"><div><h2>Affected users</h2><p>Identities present in correlated evidence</p></div></div>
      {users.length ? users.map((user) => <p className="evidence-item" key={user}>{user}</p>) : <div className="empty">No usernames observed.</div>}
    </article>
    <article className="panel evidence-panel">
      <div className="panel-title"><div><h2>Affected assets</h2><p>Hosts present in correlated evidence</p></div></div>
      {assets.length ? assets.map((asset) => <p className="evidence-item" key={asset}>{asset}</p>) : <div className="empty">No hostnames observed.</div>}
    </article>
    <article className="panel evidence-panel">
      <div className="panel-title"><div><h2>Detection rules</h2><p>Rules that matched this incident</p></div></div>
      {incident.detection_matches.length ? incident.detection_matches.map((match) => <div className="rule-match" key={match.id}><strong>{match.rule?.name ?? 'Matched detection rule'}</strong><small>{match.rule?.description ?? 'Evidence recorded by the detection engine.'}</small><code>{JSON.stringify(match.evidence)}</code></div>) : <div className="empty">No detection matches recorded.</div>}
    </article>
  </section>
}
