# SecureVault SaaS

Multi-tenant Django/PostgreSQL backend demonstrating defense-in-depth security: Row-Level Security tenant isolation, JWT auth with refresh rotation, and layered RBAC/ABAC access control.

## Quick start (Docker)

Requires Docker with the Compose plugin.

```bash
./docker/gen-env.sh      # per-service secrets -> .env.docker.* (git-ignored, mode 600)
docker compose build
docker compose up -d
docker compose ps        # db, redis, web healthy; migrate exited 0; worker up
```

| Service | What it runs | Exposure |
|---|---|---|
| `web` | gunicorn serving the Django/DRF API | `127.0.0.1:8000` only |
| `worker` | Celery worker on the `audit` queue (hash-chained audit events) | none |
| `db` | PostgreSQL 16; the app connects as a non-superuser role without `BYPASSRLS`, so RLS applies | none |
| `redis` | Celery broker: password-protected, AOF persistence | none |
| `migrate` | one-shot `manage.py migrate` that web and worker wait for | none |

The app containers run as a non-root user (uid 10001) with a read-only root filesystem, all Linux capabilities dropped and `no-new-privileges`. The database, Redis, worker and migration job sit on an internal network with no internet access and publish no host ports.

Smoke checks:

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/api/documents/   # 401 without a token
docker compose exec -T worker celery -A securevault inspect ping                 # pong
```

Stop with `docker compose down` (keeps data; `down -v` also deletes the database).

## Configuration

Copy `.env.example` to `.env` for local development. The compose stack gets its values from the generated `.env.docker.*` files.

| Variable | Required | Notes |
|---|---|---|
| `SECRET_KEY` | yes | the app refuses to start without it |
| `DB_NAME`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT` | yes | `DB_USER` must not be a superuser or have `BYPASSRLS`, otherwise RLS is silently skipped |
| `CELERY_BROKER_URL` | yes | `redis://:<password>@host:6379/0`; the app refuses to start without it |
| `DEBUG` | no | defaults to `False` |
| `ALLOWED_HOSTS` | when `DEBUG` is off | comma-separated host names |
| `HTTPS_ONLY` | no | `true` behind a TLS-terminating proxy: SSL redirect, HSTS, secure cookies |
| `EMAIL_HOST` (+ `EMAIL_PORT`, `EMAIL_HOST_USER`, `EMAIL_HOST_PASSWORD`) | when `DEBUG` is off | SMTP settings; with `DEBUG` on, emails go to the console |

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

## Security posture and how it is verified

No single layer is trusted on its own: JWT authentication, tenant binding in middleware, application-level filtering, RBAC and ABAC, PostgreSQL row-level security, and an append-only hash-chained audit log each enforce isolation independently. The adversarial suite attacks them directly.

| Area | Module (`adversarial/`) | Tests |
|---|---|---|
| Harness and RLS smoke test | `test_harness` | 7 |
| Tenant context leaking across requests | `test_tenant_context_leak` | 3 |
| JWT tampering (alg none, wrong key, forged claims, token-type confusion, refresh replay) | `test_jwt_tampering` | 14 |
| Hostile token structure must give 401, not 500 | `test_jwt_parser_robustness` | 2 |
| IDOR, role matrix, mass assignment, cross-tenant writes | `test_access_control` | 15 |
| Audit coverage of allowed, denied and cross-tenant requests | `test_audit_coverage` | 7 |
| SQL injection (params, path ids, login, RLS context hijack) | `test_sql_injection` | 10 |
| RLS enforced at the database layer alone | `test_database_layer` | 3 |
| **Total** | | **61** |

Run the suite with `python manage.py test --noinput`. The database role needs `CREATEDB` to build the test database, so the compose role cannot run it; CI does. The role-matrix script `verify_matrix.sh` (43 checks, needs `SV_TEST_PASSWORD`) exercises all seeded users against the live API.

CI (GitHub Actions) runs the suite on PostgreSQL 16 with a non-superuser role, so RLS genuinely applies, plus informational `pip-audit` and `bandit` scans. `pip-audit` once flagged 14 advisories in PyJWT 2.13.0; it was upgraded to 2.15.1 and regression tests for hostile token structure were added. `manage.py check --deploy --fail-level WARNING` passes with `HTTPS_ONLY=true`.

## Deployment notes and limitations

- **TLS:** the compose stack speaks plain HTTP on loopback (`HTTPS_ONLY=False`). For a real deployment, terminate TLS in a proxy that overwrites `X-Forwarded-Proto`, then set `HTTPS_ONLY=true`.
- **Secrets:** generated locally into git-ignored files; a real deployment needs a secrets manager.
- **Redis password:** passed to `redis-server` as an argument, so it is visible in that container's process list; a mounted config file would avoid that.
- **Seed users:** `seed_rbac_users` creates development users with a hardcoded password; it is for local development only.
- **CI:** does not build the Docker image yet.
- **Signup:** there is no signup flow yet, so `CustomUser.tenant` is still nullable.
