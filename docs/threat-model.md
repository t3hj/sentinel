# Sentinel threat model

## Broken access control

Risk: a viewer changes incident or remediation state. Controls: JWT validation, role lookup on the server, Edge Function role checks, PostgreSQL RLS, and no reliance on hidden buttons.

## Malicious event ingestion

Risk: an attacker injects misleading events or oversized metadata. Controls: simulator input is an allowlisted scenario enum, event types are constrained by the database, inserts are server-side, and metadata is labeled synthetic. Production ingestion should add schema validation, rate limits, source authentication, and payload size limits.

## Prompt injection

Risk: event metadata attempts to instruct an AI analyst. Controls: evidence is passed as structured data, not executable instructions; the current analyst is deterministic; future model prompts must delimit untrusted fields and treat them as evidence only.

## Sensitive information disclosure

Risk: incident or user data is exposed to an unauthorized user or model. Controls: RLS, role checks, narrow investigation functions, and no service-role key in the browser. Add tenant/workspace scoping before multi-tenant deployment.

## Excessive AI agency and insecure tools

Risk: an AI executes arbitrary remediation or SQL. Controls: named read-only investigation operations, predefined remediation enum, human approval, and audit records. No shell, filesystem, arbitrary SQL, or arbitrary action arguments are exposed.

## Audit-log manipulation

Risk: operators delete or rewrite evidence. Controls: audit inserts are server-side and admin reads are policy-controlled. Production should add append-only restrictions, immutable export, retention monitoring, and separate audit storage.

## Supply chain

Risk: compromised dependency or function import. Controls: lockfile, minimal dependencies, regular `npm audit`, pinned/verified function dependencies, and CI dependency review. The current workspace reports two npm audit findings that should be reviewed before production deployment.
