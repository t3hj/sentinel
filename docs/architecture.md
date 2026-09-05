# Sentinel architecture

## Boundaries

The browser owns presentation, user input, and Supabase Auth session handling. It calls typed functions in `src/lib/securityService.ts`; it never writes security events or remediation state directly.

Edge Functions own privileged workflows. They validate the JWT, resolve the caller's role from `public.users`, enforce role permissions, and use the service role only inside the function. Each function performs a narrow job:

- `simulate-attack`: safe event generation, deterministic scoring, rule matching, incident creation, and audit.
- `investigate-incident`: approved evidence retrieval and deterministic analyst output.
- `incident-status`: controlled incident state transitions.
- `remediation`: request, admin approval, simulated execution, and audit.

PostgreSQL owns relationships, constraints, indexes, and RLS. `incident_events` is the correlation join table. `detection_matches` preserves the rule evidence that caused an incident.

## Data flow

```text
Authenticated analyst
  -> typed frontend service
  -> Edge Function JWT + role check
  -> validated database transaction/workflow
  -> incident, evidence, remediation, and audit records
  -> dashboard query through RLS
```

## Separation path

The function contracts are intentionally JSON-based and narrow. They can later be moved to FastAPI services without changing the React service boundary or database entities.
