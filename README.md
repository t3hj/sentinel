# Sentinel

Sentinel is an AI-assisted Security Operations and Incident Response platform foundation. It is designed around evidence-backed detection, controlled investigation tools, human-approved simulated remediation, and an auditable event trail.

## Architecture

- React + TypeScript + Vite frontend.
- Supabase Auth for identity and PostgreSQL for relational security data.
- Row Level Security protects direct data access.
- Supabase Edge Functions own simulation, detection/correlation, investigation, status changes, remediation approval, and audit writes.
- The AI analyst boundary exposes named investigation operations only. It does not receive SQL, shell, filesystem, or service-role credentials.

See [docs/architecture.md](docs/architecture.md), [docs/threat-model.md](docs/threat-model.md), and [docs/ai-security.md](docs/ai-security.md).

## Local setup

1. Install Node.js 20+ and the Supabase CLI.
2. Copy `.env.example` to `.env.local` and set `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY`.
3. In the Supabase SQL Editor, run `supabase/schema.sql`.
	If the schema was already run, run the incremental migration `supabase/migrations/202609060001_admin_audit_triggers.sql` instead.
4. Deploy functions:

```powershell
supabase login
supabase link --project-ref YOUR_PROJECT_REF
supabase functions deploy simulate-attack
supabase functions deploy investigate-incident
supabase functions deploy incident-status
supabase functions deploy remediation
```

5. Set the function secret used by server-side functions:

```powershell
supabase secrets set SUPABASE_SERVICE_ROLE_KEY=YOUR_SERVICE_ROLE_KEY
```

6. Create a user through the app, then promote the first trusted operator from SQL Editor:

```sql
update public.users set role = 'ADMIN' where email = 'your-admin@example.com';
```

7. Start the app:

```powershell
npm install
npm run dev
```

Never put the service-role key in `.env.local` or frontend code.

## Core flow

The simulator writes a labeled sequence of safe synthetic events. The `simulate-attack` function calculates a deterministic 0-100 risk score, matches enabled detection rules, creates one correlated incident, links events, and records an audit event. Investigations use controlled reads and store evidence, findings, inference, and recommendations. Remediation requests are predefined, require an analyst/admin role, require admin approval, execute only as simulated state transitions, and create audit records.

## Database schema

`supabase/schema.sql` creates users, assets, security_events, incidents, incident_events, detection_rules, detection_matches, remediation_actions, audit_logs, ai_investigations, and playbooks. It also creates enums, indexes, triggers, RLS policies, seed rules/playbooks, and auth profile provisioning.

## Testing and limitations

`npm run build` validates the frontend TypeScript and Vite bundle. Integration testing requires a configured Supabase project, deployed functions, and test accounts for each role. The remediation actions are simulations only; no external identity, network, or endpoint control is performed. The current analyst implementation is deterministic and provides the service boundary for a future model provider.

## Future improvements

Add realtime event subscriptions, stronger pagination controls, rule management UI, production model-provider integration behind a server-side allowlist, structured test fixtures, function integration tests, and separate FastAPI services when scale or deployment isolation requires it.
