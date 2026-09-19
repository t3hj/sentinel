-- Sentinel security hardening migration
-- 1. Distributed rate-limit window table (Postgres-backed, works across Edge instances)
-- 2. Append-only protection for audit_logs

-- ---------------------------------------------------------------------------
-- 1. Rate limiting
-- ---------------------------------------------------------------------------
create table if not exists public.rate_limit_windows (
  bucket text not null,
  window_start timestamptz not null,
  hits integer not null default 1,
  primary key (bucket, window_start)
);

-- RLS: no client access at all; the Edge Functions use the service role,
-- which bypasses RLS.
alter table public.rate_limit_windows enable row level security;

-- Atomic counter increment: INSERT ... ON CONFLICT DO UPDATE hits + 1.
-- Exposed to the service-role Edge Functions via RPC. SECURITY DEFINER is
-- required so the counter works even though RLS blocks direct access.
create or replace function public.rate_limit_hit(p_bucket text, p_window_start timestamptz)
returns integer
language plpgsql
security definer
set search_path = public
as $$
declare
  v_hits integer;
begin
  insert into public.rate_limit_windows (bucket, window_start, hits)
  values (p_bucket, p_window_start, 1)
  on conflict (bucket, window_start)
  do update set hits = public.rate_limit_windows.hits + 1
  returning hits into v_hits;
  return v_hits;
end;
$$;

-- Housekeeping: drop windows older than 1 hour.
create or replace function public.purge_rate_limit_windows()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  delete from public.rate_limit_windows where window_start < now() - interval '1 hour';
  return null;
end;
$$;

drop trigger if exists rate_limit_purge on public.rate_limit_windows;
create trigger rate_limit_purge after insert on public.rate_limit_windows
for each statement execute procedure public.purge_rate_limit_windows();

-- ---------------------------------------------------------------------------
-- 2. Append-only audit_logs
-- ---------------------------------------------------------------------------
-- RLS already blocks all client writes to audit_logs (no insert/update/delete
-- policy exists). Add a hard, non-bypassable guard so that even a future
-- RLS policy mistake cannot make audit history mutable. UPDATE and DELETE are
-- denied for everyone except the service role; INSERT (the append path, used
-- by the Edge Functions and by the log_admin_change triggers) is NOT blocked
-- by this trigger — it only fires on UPDATE or DELETE.
create or replace function public.enforce_audit_logs_append_only()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if not (current_user = 'service_role' or auth.role() = 'service_role') then
    raise exception 'audit_logs is append-only'
      using errcode = 'insufficient_privilege';
  end if;
  return coalesce(new, old);
end;
$$;

drop trigger if exists audit_logs_append_only on public.audit_logs;
create trigger audit_logs_append_only
before update or delete on public.audit_logs
for each row execute procedure public.enforce_audit_logs_append_only();
