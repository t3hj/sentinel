create or replace function public.log_admin_change()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if tg_table_name = 'detection_rules' and (old.enabled is distinct from new.enabled or old.definition is distinct from new.definition or old.name is distinct from new.name) then
    insert into public.audit_logs (actor, action, resource, resource_id, result, metadata)
    values (auth.uid(), 'RULE_CHANGED', 'detection_rule', new.id::text, 'SUCCESS', jsonb_build_object('old_enabled', old.enabled, 'new_enabled', new.enabled, 'rule_name', new.name));
  elsif tg_table_name = 'users' and old.role is distinct from new.role then
    insert into public.audit_logs (actor, action, resource, resource_id, result, metadata)
    values (auth.uid(), 'USER_ROLE_CHANGED', 'user', new.id::text, 'SUCCESS', jsonb_build_object('old_role', old.role, 'new_role', new.role));
  end if;
  return new;
end;
$$;

drop trigger if exists detection_rules_audit on public.detection_rules;
create trigger detection_rules_audit after update on public.detection_rules for each row execute procedure public.log_admin_change();

drop trigger if exists users_role_audit on public.users;
create trigger users_role_audit after update of role on public.users for each row execute procedure public.log_admin_change();
