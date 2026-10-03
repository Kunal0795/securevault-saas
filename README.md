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