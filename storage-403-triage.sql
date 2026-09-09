-- ============================================================================
--  Supabase Storage 403 triage
--  "new row violates row-level security policy" on upload
--
--  Read-only except for Section 6, which runs inside an explicit transaction
--  and rolls back. Nothing here modifies your data.
--
--  Run top to bottom in the SQL editor. Each section narrows the next.
--  Basel Draz — github.com/basildraz-arch/supabase-rls-audit
-- ============================================================================


-- ----------------------------------------------------------------------------
-- 1. Is RLS even the thing that is failing?
--    A 403 from Storage can also be a size limit or a mime-type limit. Those
--    look different in the message but people report them the same way.
-- ----------------------------------------------------------------------------
select
  id                as bucket,
  public            as is_public,
  file_size_limit,
  allowed_mime_types,
  created_at
from storage.buckets
order by id;

-- If file_size_limit is set and your file is larger, or allowed_mime_types is
-- set and your file's type is not in it, stop here. That is your answer.


-- ----------------------------------------------------------------------------
-- 2. Is RLS on, and does a policy exist for the command you are running?
--    Uploading a NEW file is INSERT.
--    Uploading with upsert:true, and every resumable/TUS upload, also needs
--    UPDATE. Creating a signed URL needs SELECT.
-- ----------------------------------------------------------------------------
select relrowsecurity as rls_enabled
from pg_class
where oid = 'storage.objects'::regclass;

select
  policyname,
  cmd,
  roles,
  permissive,
  qual        as using_expression,
  with_check  as with_check_expression
from pg_policies
where schemaname = 'storage'
  and tablename  = 'objects'
order by cmd, policyname;

-- Two things to read here, both of which cause the exact same 403:
--   * INSERT is judged by with_check_expression. A policy that only has a
--     using_expression does nothing for an upload.
--   * roles must contain the role the request actually arrives as. A policy
--     granted to {authenticated} does nothing for a request that arrives anon.


-- ----------------------------------------------------------------------------
-- 3. The layer underneath the policy.
--    A missing grant returns the same error as a failing policy.
-- ----------------------------------------------------------------------------
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema = 'storage'
  and table_name   = 'objects'
  and grantee in ('anon', 'authenticated', 'service_role')
order by grantee, privilege_type;

-- anon and authenticated should both have SELECT, INSERT, UPDATE, DELETE here
-- on a stock project. If someone "hardened" this earlier, that is your 403.


-- ----------------------------------------------------------------------------
-- 4. What the request actually looks like when it arrives.
--    Run this one from your APP, as an RPC, not from the SQL editor — the
--    editor connects as postgres and will tell you nothing useful.
--
--    create or replace function public.whoami()
--    returns json language sql stable as $$
--      select json_build_object(
--        'current_user', current_user,
--        'auth_role',    auth.role(),
--        'auth_uid',     auth.uid(),
--        'claims',       current_setting('request.jwt.claims', true)
--      );
--    $$;
--    revoke execute on function public.whoami() from public;
--    grant  execute on function public.whoami() to authenticated;
--
--    Then, in the same client that fails to upload:
--      const { data } = await supabase.rpc('whoami')
--
--    auth_uid null  ->  the session is not on the request. That is the single
--                       most common cause. The client was created without the
--                       user's access token, or you are calling from the server
--                       with the anon key and no Authorization header.
--    Drop the function when you are done.
-- ----------------------------------------------------------------------------


-- ----------------------------------------------------------------------------
-- 5. The path assumption.
--    Most upload policies compare a folder segment to the user id. Check that
--    the segment you think you are comparing is the one that exists.
-- ----------------------------------------------------------------------------
select
  storage.foldername('avatars/8f14e45f-ea2a-4b3b-9f0e-1a2b3c4d5e6f/pic.png') as segments,
  (storage.foldername('avatars/8f14e45f-ea2a-4b3b-9f0e-1a2b3c4d5e6f/pic.png'))[1] as segment_1,
  (storage.foldername('avatars/8f14e45f-ea2a-4b3b-9f0e-1a2b3c4d5e6f/pic.png'))[2] as segment_2;

-- Replace with a real path from your client. If your policy reads
-- (storage.foldername(name))[1] = auth.uid()::text but your path is
-- 'avatars/<uid>/pic.png', then segment 1 is 'avatars' and the policy can
-- never pass. The bucket is not part of the name.


-- ----------------------------------------------------------------------------
-- 6. Prove it, as the user, without touching production data.
--    Replace the uid and the path. Everything is rolled back.
-- ----------------------------------------------------------------------------
begin;

select set_config(
  'request.jwt.claims',
  '{"sub":"<paste a real auth uid>","role":"authenticated"}',
  true
);
select set_config('role', 'authenticated', true);

-- What this user can already see in the bucket:
select count(*) from storage.objects where bucket_id = '<your-bucket>';

-- The upload itself, as that user:
insert into storage.objects (bucket_id, name, owner)
values ('<your-bucket>', '<the exact path your client sends>', auth.uid());

rollback;

-- Success here with a 403 in the browser means the database is fine and the
-- request is arriving as somebody else — go back to section 4.
-- Failure here reproduces the bug in one line you can iterate on, without
-- redeploying anything.


-- ----------------------------------------------------------------------------
-- 7. After you fix it: what did you just open?
--    Run section 6 again, as a DIFFERENT user, writing into the FIRST user's
--    path. It must fail. If it succeeds, the fix did not tighten anything —
--    it made the bucket writable by anyone with a login.
-- ----------------------------------------------------------------------------
