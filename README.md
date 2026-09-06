# supabase-rls-audit

A single read-only SQL script that checks a Supabase project for the privilege mistakes that get past correct RLS policies.

Paste it into the Supabase SQL editor, hit Run, and read the counts. It reads system catalogs only — it does not modify a row.

```
Section 1  →  summary, one line per check
Section 2  →  detail queries that name the objects behind any non-zero count
Section 3  →  the check no catalog query can do for you
```

---

## Why this exists

I build a multi-tenant point-of-sale system on Supabase — around ninety migrations, real shops, real money moving through it every day. Over six weeks I ran three security reviews on it and found six real holes.

**Every one of them got past policies that were, as written, correct.**

That is the part that surprised me. Row Level Security is one layer. Underneath it sits the Postgres GRANT system, and above it sits PostgREST, and the leaks live in the seams. Reading my policies never found a single one. These catalog queries found most of them in seconds.

---

## What each check catches

| # | Check | The mistake underneath |
|---|---|---|
| 1 | Tables with RLS disabled | Anyone holding your anon key can read the table. The most common Supabase leak. |
| 2 | RLS on, zero policies | Deny-all. Sometimes deliberate, sometimes a table someone forgot to finish. |
| 3 | Functions `anon` can execute | `create function` grants EXECUTE to PUBLIC by default and anon inherits it. Revoking from `anon` alone does nothing. |
| 4 | `SECURITY DEFINER` without pinned `search_path` | Runs as its owner while resolving names through the *caller's* search_path. |
| 5 | Views running as definer | In PG15+ a view bypasses the base table's RLS unless created `security_invoker = true`. |
| 6 | Views writable by `authenticated` | A simple view over one table is **automatically updatable**, and PostgREST exposes INSERT/UPDATE/DELETE on it. A view built to *read* a protected column becomes a write hole. |
| 7 | `FOR ALL` policies | One predicate covering read and write. A tenant-isolation rule written FOR ALL grants writes you never meant to grant. |
| 8 | Policies with `USING (true)` | Occasionally right for shared catalogues. Usually a placeholder nobody came back to. |
| 9 | Table-wide `UPDATE` grants | New columns are **allow-by-default** for writes. Anything you add later is writable from the browser the moment it exists. |
| 10 | Table-wide `SELECT` grants | Why column-level revokes fail silently — and Postgres raises no error when they do. |

Checks 9 and 10 together are the asymmetry worth memorising:

```
new column + SELECT  ->  denied  until you grant
new column + UPDATE  ->  allowed until you revoke
```

---

## The one that is not in the script

Everything above reads metadata, and metadata can look perfect while the database still hands data to the wrong person. The only test that settles it is to be that person:

```sql
select set_config('request.jwt.claims',
  '{"sub":"<that user auth uid>","role":"authenticated"}', true);
select set_config('role', 'authenticated', true);
-- then loop over pg_class and count(*) each table
```

Look at every table that returned rows and ask whether that user is supposed to see it. Two minutes of this found two things in my own app that reading the code had missed: the owner's email address, and a pending PIN, both readable by a cashier account.

The same applies to writes. **Code that stopped using a door did not close it.** I once assumed a function was locked because the app no longer called it; it still had `grant execute ... to authenticated`, still returned cost data to anyone who called it directly, and decremented stock with no sale attached.

After every revoke, ask the database rather than trusting the migration:

```sql
select has_function_privilege('anon', 'public.my_func()', 'execute');
```

"I ran the command" is not evidence.

---

## Usage

1. Open your Supabase project → SQL Editor → New query
2. Paste [`supabase-rls-audit.sql`](./supabase-rls-audit.sql)
3. Run
4. Any count that is not `0` — uncomment the matching query in Section 2 to see which objects are behind it

Requires no extensions and no elevated role beyond what the SQL editor already gives you. Written for Supabase; the checks are plain Postgres and work on any Postgres 15+ database using row level security.

**A count above zero is not automatically a vulnerability.** Several checks are review prompts, not failures — `FOR ALL` policies and deny-all tables are often deliberate. The script tells you where to look; you decide what it means for your data.

---

## The full write-up

All six holes, with the fix for each and how I proved it actually landed:

**[Six ways I leaked data through correct RLS policies](https://dev.to/basildrazarch/six-ways-i-leaked-data-through-correct-rls-policies-3l39)**

Also mirrored in this repo: [six-ways-rls-leaks.md](./six-ways-rls-leaks.md)

بالعربي: [ست طرق سرّبت بيها بيانات رغم إن سياسات RLS كانت مكتوبة صح](./six-ways-rls-leaks-ar.md)

---

## Contributing

Found a check that caught something real in your project? Open an issue with the catalog query and what it caught. Checks that only catch theoretical problems tend to get ignored in practice, so this stays limited to ones that have found actual bugs.

---

## About

I'm Basel, a Next.js and Supabase developer. I build multi-tenant systems and I do security passes on them — RLS, grants, functions, views — with every finding proved by testing as a real low-privilege user rather than by reading the code.

If you run this and something comes back that you cannot explain, open an issue — I read them. I also do full audits: every finding proved by running the query as a real low-privilege user in your project, ranked by what someone could actually do today, with the migration for each and a re-test showing it closed.

**[@basildraz-arch](https://github.com/basildraz-arch)**

---

## License

MIT
