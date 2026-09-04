# Six ways I leaked data through correct RLS policies

I build a point-of-sale system for retail shops. Multi-tenant, Supabase, Postgres, ninety-odd migrations, real money going through it every day. Over about six weeks I ran three security reviews on it.

Every hole I found got past policies that were, as written, correct.

That is the part nobody tells you when you turn on Row Level Security and feel safe. RLS is one layer. Underneath it sits the Postgres privilege system, and above it sits PostgREST, and the leaks live in the seams between them. Here are the six that cost me real time, each with the fix and the way to prove the fix landed.

---

## 1. Revoking from `anon` does nothing

I wrote this and moved on:

```sql
revoke execute on function my_function() from anon;
```

`anon` could still call it.

`create function` grants `EXECUTE` to `PUBLIC` by default, and `anon` inherits from `PUBLIC`. Revoking the role's own grant leaves the inherited one untouched, and Postgres does not warn you.

```sql
revoke all on function my_function() from public, anon;
grant execute on function my_function() to authenticated;
```

Trigger functions are not exempt from the default grant either. They also do not need `EXECUTE` to fire — Postgres runs a trigger as part of the table operation, not on behalf of the calling role — so revoking costs you nothing. I found three exposed trigger functions in one review, and then, in the *next* review, found two more that I had created myself while fixing the first three.

Any `create function` should end with a revoke.

---

## 2. Column-level revokes fail silently under a table-level grant

The purchase price of an item is the number my whole product exists to protect. A cashier must never see it. So:

```sql
revoke select (buy_price) on items from authenticated;
```

No error. No effect. The role still held `SELECT` on the whole table, and a table-wide grant subsumes column grants.

```sql
revoke select on items from authenticated;
grant select (id, name, sell_price, stock) on items to authenticated;
```

This has a cost you should accept knowingly: `select *` on that table now fails. Every read has to name its columns, and every new column has to be added to the grant *and* to the query. That is a real maintenance burden, and it is the correct trade.

---

## 3. New columns are deny-by-default for reads and allow-by-default for writes

This asymmetry is the one I would most like to have known a year ago:

```
new column + SELECT  ->  denied  until you grant
new column + UPDATE  ->  allowed until you revoke
```

I had locked down reads on a table column by column. Writes still carried a table-level `GRANT UPDATE`. Months later I added an invoice counter column to that table, granted it nothing, and assumed nothing meant nothing.

The browser could set it. Tested with a real user account:

```
counter before = 54    after = 1    response = no error
```

The next invoice would have been number 1 again — a duplicate in a tax invoice book, written silently. I closed it with a trigger and a unique index on `(business_id, invoice_number)` as a second belt.

**Every new column needs two questions, not one: who can read it (grants), and who can write it (grants and triggers).** They fail in opposite directions.

---

## 4. A `SECURITY DEFINER` view that bypasses RLS to read, bypasses it to write

I needed one screen to read a column that RLS forbade, so I made a view. In Postgres 15+, a view runs with its owner's rights unless you create it with `security_invoker = true`, so the view saw what the caller could not. That was the intent.

What I did not think about: a simple `select` over a single table is **automatically updatable**, and PostgREST exposes `INSERT`, `UPDATE` and `DELETE` on it like any table.

Tested with a real employee account:

```
delete from items       ->  0 rows    (the RLS policy held)
delete from item_costs  ->  1 row     (it did not)
```

An employee could delete any product in the shop through a view I built to *read* a price.

```sql
revoke all on item_costs from authenticated, anon;
grant select on item_costs to authenticated;
```

What partly saved me was a column-protection trigger that refused a tenant-id change coming through the view. **Triggers fire even when the write arrives through a view.** Deletes had no trigger, which is exactly why that one got through. If you rely on triggers as a backstop, cover delete too.

---

## 5. `auth.role()` cannot tell you where a write came from

I wrote a trigger to stop the browser tampering with a counter, and guarded it with `auth.role() = 'authenticated'`.

It would have blocked every sale in the application.

`auth.role()` reads the JWT, and the JWT does not change when you enter a `SECURITY DEFINER` function. Inside my own reviewed, trusted `record_sale()`, it still said `authenticated` — so the trigger blocked the legitimate path along with the illegitimate one.

`current_user` is the one that knows. PostgREST runs as `authenticated`; inside a `SECURITY DEFINER` function owned by `postgres`, it is `postgres`.

> `auth.role()` tells you **who the user is**.
> `current_user` tells you **where the write is coming from**.

A trigger that distinguishes "the browser" from "a function I reviewed" needs the second.

---

## 6. RLS answers the question you asked, not the one you meant

Two products in a customer's shop had stock that did not match the sum of their batches. The extra batches carried *my* tenant id, on *their* products.

I had an admin role that could read across tenants. I opened one of their products, adjusted a quantity, and my code wrote a stock batch stamped with my own tenant id onto a product that was not mine.

RLS did not stop it, and it was right not to. The policy asked: *does this batch belong to your tenant?* Yes, it did. **Nobody asked whether the product it points at belongs to your tenant too.**

> Any row that joins two tables needs a policy that asks about **both**, not about the row.

I added a trigger asserting that batch, product and warehouse all share a tenant.

---

## What actually finds these

Reading policies did not find any of the six. Three things did.

**Query the catalog.** Most of the above leaves a fingerprint in `pg_proc`, `pg_policies`, `pg_class` or `information_schema.role_table_grants`. I put the checks in one read-only script and run it after every migration. It has caught a function left behind by an ad-hoc fix in the SQL editor — `SECURITY DEFINER`, no `search_path`, no auth check at all, callable by `anon`, writing to a cost column. Unused by any code. Sitting there for months. The only reason it was never exploited is that it referenced a table that did not exist, so it errored before it reached the update.

Anything created in the SQL editor outside your migrations gets no review, appears in no diff, and stays forever. Delete your scratch work in the same session you create it.

**Be the user.** Set the JWT claims to a real low-privilege account, then `count(*)` every table in the schema and look at everything that returned rows:

```sql
select set_config('request.jwt.claims',
  '{"sub":"<user auth uid>","role":"authenticated"}', true);
select set_config('role', 'authenticated', true);
-- then loop pg_class and count each table
```

Two minutes of that found two things reading the code had missed: the shop owner's email address and a pending PIN, both visible to a cashier.

**Believe the database, not the migration.** The worst hour I lost came from assuming a door was shut because the application had stopped knocking on it. The code no longer called a function; the function still had `grant execute ... to authenticated` and still returned cost data to anyone who asked it directly. Worse, calling it decremented stock with no sale attached — an employee could walk goods out and the count would simply be short.

> **Code that stopped using a door did not close it.**

After every revoke, ask:

```sql
select has_function_privilege('anon', 'public.my_func()', 'execute');
```

"I ran the command" is not evidence.

---

## The script

The catalog checks are in one file you can paste into the Supabase SQL editor. It is read-only — it does not modify a row — and any count above zero is worth a look:

**[supabase-rls-audit.sql](./supabase-rls-audit.sql)**

I ran it against my own database while writing this. The four checks that must be zero were zero — the work above held. It still found two tables where reads are restricted column by column while writes are granted on the whole table: the exact asymmetry from #3, sitting there waiting for the next column I add.

That is the honest use of a tool like this. It does not tell you that you are safe. It tells you where the next mistake is going to come from.

If you run it and something comes back non-zero that you cannot explain, open an issue — I am happy to look at the output with you. That is what I do.
