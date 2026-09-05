# AI security boundary

The AI Security Analyst is a controlled service, not a database administrator. It may call named tools such as `get_incident_events`, `get_affected_assets`, and `get_playbooks`. Each tool should validate an incident identifier, enforce the caller's role, select only required columns, and return structured evidence.

The analyst output distinguishes:

- Evidence: facts directly retrieved from stored events, assets, rules, and playbooks.
- Inference: a reasoned interpretation of the evidence.
- Recommendation: a proposed predefined remediation action.

The current implementation stores deterministic findings and recommendations through `investigate-incident`. A model provider can be added later behind the same service boundary. Model prompts must never include secrets or unrestricted records, and event metadata must be treated as untrusted content.

Recommendations do not execute automatically. The analyst can request a predefined remediation, but an admin must approve it. Approval, simulated execution, tool calls, and investigation start are written to `audit_logs`.
