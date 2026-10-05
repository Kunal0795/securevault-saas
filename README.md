# SecureVault SaaS

Multi-tenant Django/PostgreSQL backend demonstrating defense-in-depth security: Row-Level Security tenant isolation, JWT auth with refresh rotation, and layered RBAC/ABAC access control.

## Access Control (RBAC + ABAC)

| Role   | Read PUBLIC/INTERNAL | Read CONFIDENTIAL | Create | Update/Delete |
|--------|----------------------|-------------------|--------|---------------|
| ADMIN  | all tenant docs      | all tenant docs   | yes    | any tenant doc |
| MEMBER | all tenant docs      | own only          | yes    | own only      |
| VIEWER | all tenant docs      | never             | no     | no            |

Enforcement layers, outermost first:
1. JWT auth + `TenantMiddleware` (tenant derived from the token, never from the client)
2. PostgreSQL Row-Level Security (fail-closed without tenant context)
3. Queryset filter: tenant scope + ABAC read visibility (`visible_documents`)
4. `RolePermission`: RBAC, which verbs a role may use at all
5. `DocumentAccessPolicy`: ABAC, per-object ownership/sensitivity/tenant check

Documents a user may not read return 404, not 403, so their existence isn't revealed.

Verified by `verify_matrix.sh` (43/43 checks: every role x sensitivity x ownership x tenant combination). To re-run it, start the dev server, set `SV_TEST_PASSWORD` to the seed users' password, and run `./verify_matrix.sh`.

## Audit logging

Every security-relevant API event is recorded in an append-only, hash-chained audit log, written asynchronously so it stays off the request path.

### Pipeline

~~~
API request
  -> AuditedViewSetMixin (documents) / audited token views (login, refresh)
  -> emit_audit_event()            JSON event, built once the response status is known
  -> Redis                         password-protected, localhost-only, JSON-only serialization
  -> Celery worker, "audit" queue  task audit.write_event
  -> audit_auditlog                per-tenant SHA-256 hash chain
~~~

**What is logged:** document list/read/create/update/delete (success, denied and failure), and `auth.login` / `auth.refresh`, including failed logins and reuse of an already-rotated refresh token. Stored fields: actor, tenant, action, outcome, resource id, IP (`REMOTE_ADDR` only), user agent, method, path and status. Never request bodies, passwords or tokens.

### Tamper evidence

- **Hash chain per tenant.** Each entry stores `prev_hash` and `entry_hash`, the SHA-256 of a canonical JSON encoding of the entry plus `prev_hash`. The first entry links to a genesis hash of 64 zeros.
- **Concurrent writers are serialized per tenant** with a Postgres advisory lock; a unique `(tenant, sequence)` constraint is the backstop. A unique `event_id` makes redelivered messages (at-least-once delivery) harmless.
- **Append-only, enforced three ways:** an ORM guard (`ImmutableAuditError`), a Postgres trigger that rejects UPDATE, DELETE and TRUNCATE (superuser included), and forced row-level security with SELECT and INSERT policies only, scoped to the current tenant and fail-closed when no tenant is set.
- **Verification:** `python manage.py verify_audit_chain` recomputes every hash from the stored rows and checks sequence continuity and links. It exits non-zero on any failure.

~~~bash
python manage.py verify_audit_chain                        # all tenants
python manage.py verify_audit_chain --tenant tenant-a      # one tenant (slug or UUID)
python manage.py verify_audit_chain --anchor-file ~/securevault-anchors.json --update-anchor   # save trusted chain heads
python manage.py verify_audit_chain --anchor-file ~/securevault-anchors.json                   # verify against them
~~~

### What was demonstrated

Attacks run as the database superuser with the trigger disabled (the case prevention cannot stop), each followed by verification:

| Attack | Result |
|---|---|
| Flip a stored `denied` event to `success` | `content altered at sequence N` |
| Delete one entry from the middle of a chain | `sequence gap: expected 3, found 4` |
| Delete the last entries of a chain | Undetected by the chain alone; caught by the anchor: `chain truncated` |
| 150 events queued at once to one tenant, 4 workers | Gapless, valid chain |

### Running it

~~~bash
sudo apt install redis-server
# set CELERY_BROKER_URL in .env (see .env.example); password-protect Redis with requirepass
celery -A securevault worker -Q audit -l info
~~~

### Known limitations

- **Emission is fail-open.** If Redis is down, the request still succeeds and the failure is logged. A crash between the database commit and the publish loses that event. The production fix is a transactional outbox.
- **An unkeyed hash chain can be recomputed** by anyone with database write access who knows the algorithm. Anchoring chain heads outside the database (or an HMAC with a key held outside it) defends against that, and truncation of the tail is only detectable through an anchor.
- **Logins for usernames that do not exist** (and tenant-less users) have no tenant chain to join and are only written to the application log.
- **Requests rejected by the tenant middleware** before reaching a view (for example a missing token) are not yet audited.
- **The token-endpoint throttle (30/min per IP)** bounds log growth from anonymous callers; it is not brute-force protection, which would need per-account lockout.
- **`sequence` is write order**, which can differ slightly from `occurred_at` under concurrency.

## Audit logging

Every security-relevant API event is recorded in an append-only, hash-chained audit log, written asynchronously so it stays off the request path.

### Pipeline

~~~
API request
  -> AuditedViewSetMixin (documents) / audited token views (login, refresh)
  -> emit_audit_event()            JSON event, built once the response status is known
  -> Redis                         password-protected, localhost-only, JSON-only serialization
  -> Celery worker, "audit" queue  task audit.write_event
  -> audit_auditlog                per-tenant SHA-256 hash chain
~~~

**What is logged:** document list/read/create/update/delete (success, denied and failure), and `auth.login` / `auth.refresh`, including failed logins and reuse of an already-rotated refresh token. Stored fields: actor, tenant, action, outcome, resource id, IP (`REMOTE_ADDR` only), user agent, method, path and status. Never request bodies, passwords or tokens.

### Tamper evidence

- **Hash chain per tenant.** Each entry stores `prev_hash` and `entry_hash`, the SHA-256 of a canonical JSON encoding of the entry plus `prev_hash`. The first entry links to a genesis hash of 64 zeros.
- **Concurrent writers are serialized per tenant** with a Postgres advisory lock; a unique `(tenant, sequence)` constraint is the backstop. A unique `event_id` makes redelivered messages (at-least-once delivery) harmless.
- **Append-only, enforced three ways:** an ORM guard (`ImmutableAuditError`), a Postgres trigger that rejects UPDATE, DELETE and TRUNCATE (superuser included), and forced row-level security with SELECT and INSERT policies only, scoped to the current tenant and fail-closed when no tenant is set.
- **Verification:** `python manage.py verify_audit_chain` recomputes every hash from the stored rows and checks sequence continuity and links. It exits non-zero on any failure.

~~~bash
python manage.py verify_audit_chain                        # all tenants
python manage.py verify_audit_chain --tenant tenant-a      # one tenant (slug or UUID)
python manage.py verify_audit_chain --anchor-file ~/securevault-anchors.json --update-anchor   # save trusted chain heads
python manage.py verify_audit_chain --anchor-file ~/securevault-anchors.json                   # verify against them
~~~

### What was demonstrated

Attacks run as the database superuser with the trigger disabled (the case prevention cannot stop), each followed by verification:

| Attack | Result |
|---|---|
| Flip a stored `denied` event to `success` | `content altered at sequence N` |
| Delete one entry from the middle of a chain | `sequence gap: expected 3, found 4` |
| Delete the last entries of a chain | Undetected by the chain alone; caught by the anchor: `chain truncated` |
| 150 events queued at once to one tenant, 4 workers | Gapless, valid chain |

### Running it

~~~bash
sudo apt install redis-server
# set CELERY_BROKER_URL in .env (see .env.example); password-protect Redis with requirepass
celery -A securevault worker -Q audit -l info
~~~

### Known limitations

- **Emission is fail-open.** If Redis is down, the request still succeeds and the failure is logged. A crash between the database commit and the publish loses that event. The production fix is a transactional outbox.
- **An unkeyed hash chain can be recomputed** by anyone with database write access who knows the algorithm. Anchoring chain heads outside the database (or an HMAC with a key held outside it) defends against that, and truncation of the tail is only detectable through an anchor.
- **Logins for usernames that do not exist** (and tenant-less users) have no tenant chain to join and are only written to the application log.
- **Requests rejected by the tenant middleware** before reaching a view (for example a missing token) are not yet audited.
- **The token-endpoint throttle (30/min per IP)** bounds log growth from anonymous callers; it is not brute-force protection, which would need per-account lockout.
- **`sequence` is write order**, which can differ slightly from `occurred_at` under concurrency.