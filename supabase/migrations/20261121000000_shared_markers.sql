begin;

create table if not exists public.qunyou_markers (
  id uuid primary key,
  owner_hash text not null,
  name text not null check (char_length(name) between 1 and 16),
  emoji text not null default '',
  avatar_url text not null default '',
  lat double precision not null check (lat between -90 and 90),
  lng double precision not null check (lng between -180 and 180),
  created_at timestamptz not null,
  expires_at timestamptz
);

alter table public.qunyou_markers enable row level security;
revoke all on public.qunyou_markers from public, anon, authenticated;
grant select, insert, update, delete on public.qunyou_markers to service_role;

create table if not exists public.qunyou_admin_attempts (
  key text not null,
  bucket bigint not null,
  attempts integer not null,
  primary key (key, bucket)
);

alter table public.qunyou_admin_attempts enable row level security;
revoke all on public.qunyou_admin_attempts from public, anon, authenticated;
grant select, insert, update, delete on public.qunyou_admin_attempts to service_role;

create or replace function public.qunyou_admin_attempt(attempt_key text, attempt_bucket bigint)
returns boolean
language plpgsql
set search_path = ''
as $$
declare
  total integer;
begin
  delete from public.qunyou_admin_attempts where bucket < attempt_bucket - 1;
  insert into public.qunyou_admin_attempts as old (key, bucket, attempts)
    values (attempt_key, attempt_bucket, 1)
    on conflict (key, bucket) do update set attempts = least(old.attempts + 1, 9)
    returning attempts into total;
  return total <= 8;
end;
$$;

revoke all on function public.qunyou_admin_attempt(text, bigint) from public, anon, authenticated;
grant execute on function public.qunyou_admin_attempt(text, bigint) to service_role;

commit;
