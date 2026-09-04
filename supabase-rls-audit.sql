-- =====================================================================
--  Supabase RLS & Privilege Audit — read-only
--  https://github.com/basildraz-arch/supabase-rls-audit
--
--  Paste into the Supabase SQL Editor and hit Run.
--  It reads catalogs only. It does not modify a single row.
--
--  Every check below exists because it caught a real bug in a
--  production multi-tenant app — not because it looked good on a
--  checklist. Any row whose count is not 0 deserves a look.
--
--  A note on how to read this: RLS is not the whole story. Postgres
--  GRANTs sit *underneath* RLS, and most of the leaks below get past
--  perfectly correct policies.
-- =====================================================================


-- ---------------------------------------------------------------------
--  SECTION 1 — SUMMARY
--  One row per check. Start here.
-- ---------------------------------------------------------------------

with anon_exists as (select to_regrole('anon') as r)

-- 1. RLS switched off entirely.
--    A table without RLS in the `public` schema is readable by anyone
--    holding your anon key. This is the single most common Supabase leak.
select
  '1. Tables in public with RLS disabled'          as check_name,
  count(*)                                          as found,
  'must be 0'                                       as expected
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public'
  and c.relkind = 'r'
  and not c.relrowsecurity

union all

-- 2. RLS on, but no policies at all.
--    This is deny-all, which is sometimes exactly what you want
--    (service_role-only tables). Listed so you confirm each one is
--    deliberate rather than a table someone forgot to finish.
select
  '2. RLS enabled but zero policies (deny-all — confirm intent)',
  count(*),
  'review each'
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public'
  and c.relkind = 'r'
  and c.relrowsecurity
  and not exists (
    select 1 from pg_policy p where p.polrelid = c.oid
  )

union all

-- 3. Functions the anon role can execute.
--    THE TRAP: `create function` grants EXECUTE to PUBLIC by default,
--    and anon inherits from PUBLIC. Writing
--        revoke execute on function f() from anon;
--    does NOT close this — anon still gets it through PUBLIC.
--    The fix is:
--        revoke all on function f() from public, anon;
--        grant execute on function f() to authenticated;
--    Trigger functions are not exempt. They do not need EXECUTE to
--    fire — Postgres runs them as part of the table operation — so
--    revoking from them costs you nothing.
select
  '3. Functions executable by anon',
  count(*),
  'must be 0 unless deliberately public'
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
cross join anon_exists a
where n.nspname = 'public'
  and p.prokind in ('f', 'p')
  and a.r is not null
  and has_function_privilege(a.r, p.oid, 'execute')

union all

-- 4. SECURITY DEFINER without a pinned search_path.
--    Such a function runs as its owner (usually postgres) while
--    resolving unqualified names through the *caller's* search_path.
--    A caller who can create objects can shadow a table or operator
--    the function references and have it executed as the owner.
--    Fix: alter function f() set search_path = public, pg_temp;
select
  '4. SECURITY DEFINER functions without pinned search_path',
  count(*),
  'must be 0'
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public'
  and p.prosecdef
  and (
    p.proconfig is null
    or not exists (
      select 1 from unnest(p.proconfig) cfg where cfg like 'search_path=%'
    )
  )

union all

-- 5. SECURITY DEFINER views — and this one bites hard.
--    In Postgres 15+ a view runs with its *owner's* rights unless it
--    is created with security_invoker = true. So a view over a table
--    with RLS bypasses that RLS.
--    What people miss: a simple view over one table is AUTOMATICALLY
--    UPDATABLE, and PostgREST will happily expose INSERT / UPDATE /
--    DELETE on it. A view created to work around a *read* restriction
--    silently becomes a *write* hole:
--        delete from base_table  -> 0 rows   (RLS held)
--        delete from the_view    -> 1 row    (RLS bypassed)
--    Fix: revoke all on <view> from authenticated, anon;
--         grant select on <view> to authenticated;
--    or create the view with (security_invoker = true).
select
  '5. Views running as definer (no security_invoker)',
  count(*),
  'review each — check writes are revoked'
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public'
  and c.relkind = 'v'
  and not coalesce(
    (select true from unnest(coalesce(c.reloptions, '{}')) o
      where o ilike 'security_invoker=%true%'),
    false
  )

union all

-- 6. Views that authenticated can write through.
--    The concrete version of check 5. If this is not 0, read the list
--    in Section 2 carefully.
select
  '6. Views writable by authenticated',
  count(*),
  'must be 0 for read-only views'
from information_schema.role_table_grants g
join pg_class c on c.relname = g.table_name
join pg_namespace n on n.oid = c.relnamespace and n.nspname = g.table_schema
where g.table_schema = 'public'
  and g.grantee = 'authenticated'
  and g.privilege_type in ('INSERT', 'UPDATE', 'DELETE')
  and c.relkind = 'v'

union all

-- 7. FOR ALL policies.
--    `for all` covers SELECT, INSERT, UPDATE and DELETE with one
--    predicate. The leaking pattern is a tenant-isolation policy —
--    "the row belongs to my org" — written FOR ALL: every member of
--    the org gets write access, when you only meant to grant read.
--    Some FOR ALL policies are correct. None should be accidental.
select
  '7. FOR ALL policies (read + write share one predicate)',
  count(*),
  'review each'
from pg_policies
where schemaname = 'public'
  and cmd = 'ALL'

union all

-- 8. Policies that let everything through.
--    USING (true) on a SELECT policy means the table is public to
--    every logged-in user. Occasionally right (shared catalogues,
--    lookup tables). Usually a placeholder someone never came back to.
select
  '8. Policies with USING (true)',
  count(*),
  'review each'
from pg_policies
where schemaname = 'public'
  and qual = 'true'

union all

-- 9. Table-wide UPDATE grants — the asymmetry that catches everyone.
--    Column privileges are NOT symmetric, and this surprises people:
--
--      new column + SELECT  ->  DENIED by default (needs a grant)
--      new column + UPDATE  ->  ALLOWED by default (needs a revoke)
--
--    So if a table carries a table-level GRANT UPDATE, every column
--    you add later is writable from the browser the moment it exists,
--    including the ones you were careful never to grant SELECT on.
--    Fix: revoke update on <table> from authenticated;
--         grant update (col_a, col_b) on <table> to authenticated;
select
  '9. Tables where authenticated has table-wide UPDATE',
  count(*),
  'prefer column-level grants'
from information_schema.role_table_grants g
join pg_class c on c.relname = g.table_name
join pg_namespace n on n.oid = c.relnamespace and n.nspname = g.table_schema
where g.table_schema = 'public'
  and g.grantee = 'authenticated'
  and g.privilege_type = 'UPDATE'
  and c.relkind = 'r'

union all

-- 10. Table-wide SELECT grants.
--     Informational, and the reason column-level revokes fail silently:
--         revoke select (secret_col) on t from authenticated;
--     does NOTHING while the role still holds SELECT on the whole
--     table — and Postgres raises no error. You have to
--         revoke select on t from authenticated;
--         grant select (the, columns, you, want) on t to authenticated;
select
  '10. Tables where authenticated has table-wide SELECT',
  count(*),
  'fine unless you hide columns'
from information_schema.role_table_grants g
join pg_class c on c.relname = g.table_name
join pg_namespace n on n.oid = c.relnamespace and n.nspname = g.table_schema
where g.table_schema = 'public'
  and g.grantee = 'authenticated'
  and g.privilege_type = 'SELECT'
  and c.relkind = 'r'

order by 2 desc;


-- ---------------------------------------------------------------------
--  SECTION 2 — DETAIL
--  Run these to name the objects behind any non-zero count above.
--  Uncomment the one you need.
-- ---------------------------------------------------------------------

-- -- 1. Which tables have RLS off?
-- select c.relname as table_name
-- from pg_class c join pg_namespace n on n.oid = c.relnamespace
-- where n.nspname='public' and c.relkind='r' and not c.relrowsecurity
-- order by 1;

-- -- 3. Which functions can anon call?
-- select p.proname as function_name, pg_get_function_identity_arguments(p.oid) as args
-- from pg_proc p join pg_namespace n on n.oid=p.pronamespace
-- where n.nspname='public' and p.prokind in ('f','p')
--   and to_regrole('anon') is not null
--   and has_function_privilege(to_regrole('anon'), p.oid, 'execute')
-- order by 1;

-- -- 4. Which SECURITY DEFINER functions have no pinned search_path?
-- select p.proname as function_name, p.proconfig
-- from pg_proc p join pg_namespace n on n.oid=p.pronamespace
-- where n.nspname='public' and p.prosecdef
--   and (p.proconfig is null or not exists (
--        select 1 from unnest(p.proconfig) c where c like 'search_path=%'))
-- order by 1;

-- -- 6. Which views can authenticated write through?
-- select distinct g.table_name as view_name, g.privilege_type
-- from information_schema.role_table_grants g
-- join pg_class c on c.relname=g.table_name
-- join pg_namespace n on n.oid=c.relnamespace and n.nspname=g.table_schema
-- where g.table_schema='public' and g.grantee='authenticated'
--   and g.privilege_type in ('INSERT','UPDATE','DELETE') and c.relkind='v'
-- order by 1, 2;

-- -- 7 & 8. Every policy, with its predicate.
-- select tablename, policyname, cmd, roles, qual, with_check
-- from pg_policies where schemaname='public'
-- order by tablename, policyname;

-- -- 9. Which tables give authenticated table-wide UPDATE?
-- select distinct g.table_name
-- from information_schema.role_table_grants g
-- join pg_class c on c.relname=g.table_name
-- join pg_namespace n on n.oid=c.relnamespace and n.nspname=g.table_schema
-- where g.table_schema='public' and g.grantee='authenticated'
--   and g.privilege_type='UPDATE' and c.relkind='r'
-- order by 1;


-- ---------------------------------------------------------------------
--  SECTION 3 — THE CHECK NO CATALOG QUERY CAN DO FOR YOU
-- ---------------------------------------------------------------------
--
--  Everything above reads metadata. Metadata can look perfect while
--  the database still hands data to the wrong person. The only test
--  that settles it is to BE that person.
--
--  Log in as a real low-privilege user, then count every table:
--
--      select set_config('request.jwt.claims',
--        '{"sub":"<that user auth uid>","role":"authenticated"}', true);
--      select set_config('role', 'authenticated', true);
--      -- then loop over pg_class and count(*) each table
--
--  Look at every table that returned rows and ask whether that user
--  is supposed to see it. Two minutes of this found two leaks in my
--  own app that reading the policies had missed: the owner's email
--  address, and a pending PIN, both readable by a cashier account.
--
--  The same idea applies to writes. Do not conclude a door is shut
--  because the app stopped knocking on it — call the function
--  directly as that user and read what comes back.
--
--  "I ran the revoke" is not evidence. Ask the database:
--      select has_function_privilege('anon', 'public.my_func()', 'execute');
-- ---------------------------------------------------------------------
