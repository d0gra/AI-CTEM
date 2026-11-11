# ADR 0001: Tenant isolation with PostgreSQL row-level security

**Status:** accepted

**Context.** A cross-tenant leak in this product exposes one customer's vulnerabilities and credentials to another. Application-level filtering alone depends on every query, in every current and future code path, including background jobs and reports, carrying the right predicate.

**Decision.** Every tenant-owned table has `organization_id` and a forced RLS policy keyed on a transaction-local setting (`app.current_org`). The API and workers connect as a role that is neither table owner nor `BYPASSRLS`. Sessions set the context in an `after_begin` hook so it survives commits. A separate, explicit system context exists for authentication lookups, job dispatch and global reference data.

**Consequences.** A forgotten `WHERE` clause returns nothing instead of another tenant's rows; inserts for another tenant fail the `WITH CHECK`. Migrations must enable RLS for new tenant tables (a test enforces this). Two database roles are required. The system context is a deliberate escape hatch and must stay limited to the few call sites that need it. RLS does not protect against arbitrary SQL execution.
