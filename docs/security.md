# Security design

The platform holds credentials to customer environments and a map of their weaknesses. It is designed as a high-value target.

## Threat model summary

| Threat | Controls |
| --- | --- |
| Cross-tenant data access | Forced row-level security on all 43 tenant tables; non-owner database role without `BYPASSRLS`; tenant-scoped sessions for requests and jobs; object-storage keys prefixed and verified per organization; isolation tests over every resource type |
| Account takeover | Argon2id; generic sign-in errors with timing equalisation; lockout; TOTP MFA; idle and absolute session expiry; sessions revoked on password change/reset, role change and deactivation |
| CSRF | `SameSite=Lax` cookie plus a per-session token required on unsafe cookie-authenticated requests |
| Privilege escalation | Permission check on every sensitive route; cannot grant permissions you lack, change your own role or manage more privileged accounts; risk acceptance and policy exceptions need a different approver |
| SSRF | Single outbound client (`core/net.py`): scheme allow-list, no embedded credentials, resolve-validate-pin, no automatic redirects to unvalidated hosts, link-local and metadata ranges always blocked, private ranges blocked unless both deployment and scope allow |
| Abuse of scanning capability | Authorized scope is a hard precondition, checked at definition and again at run time; active engines need `allow_active`; request budgets; no shell; argument validation and `--` separation for external tools |
| Injection | SQLAlchemy bound parameters throughout; `LIKE` patterns escaped; sort keys mapped through allow-lists; XML parsed with defusedxml; pickle never loaded (disassembled only) |
| Credential exposure | Fernet encryption at rest with key rotation; credentials never serialised in API responses; redaction of token patterns before evidence, logs and audit data are stored |
| Malicious uploads | Extension allow-list plus content signature; size limit; generated storage keys; served as `application/octet-stream` attachments with `nosniff` |
| Log tampering | Audit table grants `INSERT, SELECT` only; per-organization hash chain; `GET /audit/verify` and `python -m app.cli verify-audit` |
| Prompt injection against AI features | Platform data passed as delimited untrusted data; fixed output schema validated server-side; no tools; output is advisory and cannot change records |
| Background job abuse | Jobs are created only by authorized API calls or the scheduler; handlers run in the job's tenant session; per-tenant concurrency cap; bounded retries |

## Authentication and sessions

Session tokens are 256-bit random values; only an HMAC-SHA-256 of the token is stored. Cookies are `HttpOnly`, `Secure` (enforced in production) and `SameSite=Lax`. Password reset and email verification tokens are single-use, hashed at rest, and expire (1 hour and 3 days). Sign-in endpoints are rate limited per client address in addition to the per-account lockout.

## Tenant isolation

See [ADR 0001](adr/0001-tenant-isolation-rls.md). The policy on every tenant table is:

```sql
organization_id = nullif(current_setting('app.current_org', true), '')::uuid
OR current_setting('app.system', true) = 'on'
```

`app.system` is set only by `system_session()`, used for pre-authentication lookups, job dispatch and global reference data. RLS protects against application bugs such as a missing `WHERE` clause; it is not a defence against arbitrary SQL execution, which is addressed by using bound parameters everywhere.

## Secrets and key management

- `CTEM_SECRET_KEY`: HMAC key for token hashing. Rotating it invalidates all sessions and outstanding reset links.
- `CTEM_ENCRYPTION_KEYS`: comma-separated Fernet keys. To rotate: prepend a new key, deploy, run `python -m app.cli rotate-secrets`, then remove the old key.
- Supply secrets from a secret manager. The API refuses to start in production with default or missing secrets.
- Use a dedicated, least-privilege credential per integration; required permissions are listed in [integrations.md](integrations.md).

## Assessment safety

- Engines default to non-destructive, read-only techniques. The HTTP engine sends a bounded number of GET requests; the OpenAPI probe sends GET only and never to parameterised or state-changing operations; the MCP probe cannot send `tools/call`.
- AI red-team runs additionally require a written authorization with an expiry of at most 30 days, recorded in the audit log with the operator's identity.
- Remediation is never applied automatically. Creating an external ticket requires explicit confirmation.

## HTTP hardening

API responses carry `Content-Security-Policy: default-src 'none'`, `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store` and, with secure cookies, HSTS. CORS is disabled unless `CTEM_CORS_ORIGINS` is set; the supported topology is same-origin through the frontend proxy. Error responses never include SQL or stack traces.

## Verification

`backend/tests/test_isolation_security.py`, `test_auth.py` and `test_rbac_admin.py` cover authentication bypass, CSRF, lockout, MFA enforcement, privilege escalation, cross-tenant access for every resource type (read, write, reference-by-id, search, export, background job), RLS at the SQL level, SSRF destinations including redirects, input validation, upload restrictions, secret non-disclosure and audit immutability. `test_ai_security.py` covers scope, budget and expiry enforcement for AI assessments and the no-tool-execution guarantee.

## Not yet done

Independent penetration test; SSO; per-API-key credentials for automation (bearer session tokens are used); field-level encryption of evidence; malware scanning of uploads; signed container images and SBOM publication for the platform itself.
