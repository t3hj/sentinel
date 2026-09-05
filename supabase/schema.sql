create extension if not exists pgcrypto;

create type public.app_role as enum ('ADMIN', 'ANALYST', 'VIEWER');
create type public.event_severity as enum ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL');
create type public.incident_status as enum ('OPEN', 'INVESTIGATING', 'CONTAINED', 'RESOLVED', 'FALSE_POSITIVE');
create type public.remediation_type as enum ('DISABLE_USER', 'REVOKE_SESSIONS', 'BLOCK_IP', 'ISOLATE_ENDPOINT', 'MARK_FALSE_POSITIVE');

create table public.users (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  display_name text not null default '',
  role public.app_role not null default 'VIEWER',
  created_at timestamptz not null default now()
);

create table public.assets (
  id uuid primary key default gen_random_uuid(),
  hostname text not null unique,
  asset_type text not null default 'endpoint',
  criticality public.event_severity not null default 'MEDIUM',
  owner text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table public.security_events (
  id uuid primary key default gen_random_uuid(),
  timestamp timestamptz not null,
  event_type text not null check (event_type in ('LOGIN_FAILED','LOGIN_SUCCESS','PRIVILEGE_ESCALATION','SUSPICIOUS_PROCESS','UNUSUAL_NETWORK_CONNECTION','LARGE_DATA_TRANSFER','FILE_MODIFICATION','ACCOUNT_CREATED','ACCOUNT_DISABLED','ENDPOINT_ALERT')),
  source text not null,
  source_ip inet,
  destination_ip inet,
  username text,
  hostname text,
  process text,
  severity public.event_severity not null,
  metadata jsonb not null default '{}'::jsonb,
  correlation_id uuid,
  created_at timestamptz not null default now(),
  ingested_by uuid references public.users(id)
);

create table public.incidents (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  description text not null default '',
  status public.incident_status not null default 'OPEN',
  severity public.event_severity not null,
  risk_score integer not null check (risk_score between 0 and 100),
  confidence numeric(5,2) not null check (confidence between 0 and 100),
  correlation_id uuid unique,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  resolved_at timestamptz
);

create table public.incident_events (
  incident_id uuid not null references public.incidents(id) on delete cascade,
  event_id uuid not null references public.security_events(id) on delete cascade,
  relation text not null default 'related',
  primary key (incident_id, event_id)
);

create table public.detection_rules (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  description text not null,
  enabled boolean not null default true,
  rule_type text not null,
  definition jsonb not null,
  severity public.event_severity not null,
  created_by uuid references public.users(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.detection_matches (
  id uuid primary key default gen_random_uuid(),
  rule_id uuid not null references public.detection_rules(id) on delete cascade,
  incident_id uuid references public.incidents(id) on delete set null,
  event_ids uuid[] not null,
  matched_at timestamptz not null default now(),
  evidence jsonb not null default '{}'::jsonb
);

create table public.remediation_actions (
  id uuid primary key default gen_random_uuid(),
  incident_id uuid not null references public.incidents(id) on delete cascade,
  action_type public.remediation_type not null,
  target text not null,
  reason text not null,
  status text not null default 'REQUESTED' check (status in ('REQUESTED','APPROVED','EXECUTED','REJECTED')),
  requested_by uuid not null references public.users(id),
  approved_by uuid references public.users(id),
  requested_at timestamptz not null default now(),
  approved_at timestamptz,
  executed_at timestamptz,
  metadata jsonb not null default '{}'::jsonb
);

create table public.audit_logs (
  id uuid primary key default gen_random_uuid(),
  timestamp timestamptz not null default now(),
  actor uuid references public.users(id),
  action text not null,
  resource text not null,
  resource_id text,
  result text not null,
  metadata jsonb not null default '{}'::jsonb
);

create table public.ai_investigations (
  id uuid primary key default gen_random_uuid(),
  incident_id uuid not null references public.incidents(id) on delete cascade,
  started_by uuid not null references public.users(id),
  status text not null default 'RUNNING' check (status in ('RUNNING','COMPLETED','FAILED')),
  evidence jsonb not null default '[]'::jsonb,
  findings jsonb not null default '{}'::jsonb,
  risk_explanation text not null default '',
  recommendation jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  completed_at timestamptz
);

create table public.playbooks (
  id uuid primary key default gen_random_uuid(),
  name text not null unique,
  description text not null,
  actions public.remediation_type[] not null,
  required_role public.app_role not null default 'ANALYST',
  enabled boolean not null default true,
  created_at timestamptz not null default now()
);

create index security_events_timestamp_idx on public.security_events(timestamp desc);
create index security_events_correlation_idx on public.security_events(correlation_id);
create index security_events_type_idx on public.security_events(event_type);
create index incidents_status_idx on public.incidents(status);
create index incidents_risk_idx on public.incidents(risk_score desc);
create index audit_logs_timestamp_idx on public.audit_logs(timestamp desc);

create or replace function public.current_role()
returns public.app_role
language sql
stable
security definer
set search_path = public
as $$ select role from public.users where id = auth.uid() $$;

create or replace function public.touch_updated_at()
returns trigger
language plpgsql
as $$ begin new.updated_at = now(); return new; end $$;

create trigger incidents_touch_updated_at before update on public.incidents for each row execute procedure public.touch_updated_at();
create trigger rules_touch_updated_at before update on public.detection_rules for each row execute procedure public.touch_updated_at();

alter table public.users enable row level security;
alter table public.assets enable row level security;
alter table public.security_events enable row level security;
alter table public.incidents enable row level security;
alter table public.incident_events enable row level security;
alter table public.detection_rules enable row level security;
alter table public.detection_matches enable row level security;
alter table public.remediation_actions enable row level security;
alter table public.audit_logs enable row level security;
alter table public.ai_investigations enable row level security;
alter table public.playbooks enable row level security;

create policy users_read_authenticated on public.users for select to authenticated using (true);
create policy users_admin_write on public.users for all to authenticated using (public.current_role() = 'ADMIN') with check (public.current_role() = 'ADMIN');
create policy read_security_data on public.security_events for select to authenticated using (true);
create policy read_assets on public.assets for select to authenticated using (true);
create policy read_incidents on public.incidents for select to authenticated using (true);
create policy analyst_update_incidents on public.incidents for update to authenticated using (public.current_role() in ('ADMIN','ANALYST')) with check (public.current_role() in ('ADMIN','ANALYST'));
create policy read_incident_events on public.incident_events for select to authenticated using (true);
create policy rules_read_authenticated on public.detection_rules for select to authenticated using (true);
create policy rules_admin_write on public.detection_rules for all to authenticated using (public.current_role() = 'ADMIN') with check (public.current_role() = 'ADMIN');
create policy matches_read_authenticated on public.detection_matches for select to authenticated using (true);
create policy remediation_read_authenticated on public.remediation_actions for select to authenticated using (true);
create policy remediation_analyst_request on public.remediation_actions for insert to authenticated with check (public.current_role() in ('ADMIN','ANALYST') and requested_by = auth.uid());
create policy remediation_admin_approve on public.remediation_actions for update to authenticated using (public.current_role() = 'ADMIN') with check (public.current_role() = 'ADMIN');
create policy audit_read_admin on public.audit_logs for select to authenticated using (public.current_role() = 'ADMIN');
create policy ai_read_authenticated on public.ai_investigations for select to authenticated using (true);
create policy playbooks_read_authenticated on public.playbooks for select to authenticated using (true);

insert into public.detection_rules (name, description, rule_type, definition, severity) values
('Brute force followed by success', 'Multiple failed logins followed by a successful login for the same user and source.', 'SEQUENCE', '{"events":["LOGIN_FAILED","LOGIN_SUCCESS"],"minimum_failures":3,"window_minutes":15}', 'HIGH'),
('Privilege escalation after authentication anomaly', 'Privilege escalation shortly after suspicious authentication activity.', 'SEQUENCE', '{"events":["LOGIN_SUCCESS","PRIVILEGE_ESCALATION"],"window_minutes":30}', 'CRITICAL'),
('Possible data exfiltration', 'Large data transfer after authentication or process anomalies.', 'SEQUENCE', '{"events":["SUSPICIOUS_PROCESS","LARGE_DATA_TRANSFER"],"window_minutes":60}', 'HIGH')
on conflict (name) do nothing;

insert into public.playbooks (name, description, actions, required_role) values
('Brute force response', 'Contain suspected credential attack activity.', array['BLOCK_IP','REVOKE_SESSIONS']::public.remediation_type[], 'ANALYST'),
('Account compromise response', 'Protect the identity and invalidate active sessions.', array['DISABLE_USER','REVOKE_SESSIONS']::public.remediation_type[], 'ANALYST'),
('Data exfiltration response', 'Contain the endpoint and block the source.', array['ISOLATE_ENDPOINT','BLOCK_IP']::public.remediation_type[], 'ANALYST')
on conflict (name) do nothing;

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$ begin
  insert into public.users (id, email, display_name, role)
  values (new.id, new.email, coalesce(new.raw_user_meta_data->>'display_name', ''), 'VIEWER')
  on conflict (id) do nothing;
  return new;
end $$;

create trigger on_auth_user_created after insert on auth.users for each row execute procedure public.handle_new_user();

create or replace function public.log_admin_change()
returns trigger
language plpgsql
security definer
set search_path = public
as $$ begin
  if tg_table_name = 'detection_rules' and (old.enabled is distinct from new.enabled or old.definition is distinct from new.definition or old.name is distinct from new.name) then
    insert into public.audit_logs (actor, action, resource, resource_id, result, metadata)
    values (auth.uid(), 'RULE_CHANGED', 'detection_rule', new.id::text, 'SUCCESS', jsonb_build_object('old_enabled', old.enabled, 'new_enabled', new.enabled, 'rule_name', new.name));
  elsif tg_table_name = 'users' and old.role is distinct from new.role then
    insert into public.audit_logs (actor, action, resource, resource_id, result, metadata)
    values (auth.uid(), 'USER_ROLE_CHANGED', 'user', new.id::text, 'SUCCESS', jsonb_build_object('old_role', old.role, 'new_role', new.role));
  end if;
  return new;
end $$;

drop trigger if exists detection_rules_audit on public.detection_rules;
create trigger detection_rules_audit after update on public.detection_rules for each row execute procedure public.log_admin_change();
drop trigger if exists users_role_audit on public.users;
create trigger users_role_audit after update of role on public.users for each row execute procedure public.log_admin_change();
