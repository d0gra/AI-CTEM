# API

Base path `/api/v1`. OpenAPI: `/api/docs` (interactive), `/api/openapi.json`.

## Authentication

```bash
curl -s -X POST localhost:8000/api/v1/auth/login -H 'content-type: application/json' \
  -d '{"email":"you@example.com","password":"...","totp_code":null}'
# → {"mfa_required": false, "csrf_token": "...", "access_token": "...", "expires_at": "..."}
```

- **Scripts**: send `Authorization: Bearer <access_token>`. No CSRF token is needed.
- **Browsers**: the `ctem_session` cookie is set by the login response; unsafe methods must send `X-CSRF-Token`.
- If `mfa_required` is true, call `POST /auth/mfa/verify {"code": "123456"}` with the same token before other endpoints.

## Conventions

- **Errors**: `{"error": {"code": "out_of_scope", "message": "...", "details": {...}}}`. Codes: `unauthorized` (401), `forbidden` (403), `out_of_scope` (403), `not_found` (404), `conflict` (409), `validation_failed` (422), `rate_limited` (429), `upstream_error` (502).
- **Pagination**: `page` (from 1) and `page_size` (≤ 200); responses contain `items`, `total`, `page`, `page_size`.
- **Sorting**: `sort=<field>&order=asc|desc`; unknown fields fall back to the default.
- **Filtering**: repeated parameters for multi-value filters, for example `?severity=critical&severity=high`.
- **Tenant scope**: every request acts on the caller's organization. A resource in another organization returns 404.
- **Long-running work** returns 202 with a run or job id; poll `GET /assessment-runs/{id}` or `GET /jobs/{id}`.
- **Rate limits**: per client address, `CTEM_RATE_LIMIT_API` per minute, `CTEM_RATE_LIMIT_AUTH` for sign-in endpoints; 429 carries `Retry-After`.

## Resource map

| Area | Endpoints |
| --- | --- |
| Auth | `/auth/register`, `/auth/login`, `/auth/logout`, `/auth/me`, `/auth/sessions`, `/auth/mfa/*`, `/auth/password/*`, `/auth/email/verify` |
| Administration | `/admin/users`, `/admin/roles`, `/admin/teams`, `/admin/permissions`, `/admin/directory`, `/admin/organization` |
| Assets | `/assets`, `/assets/{id}`, `/assets/{id}/relationships`, `/assets/{id}/history`, `/assets/facets`, `/asset-relationships`, `/asset-graph`, `/scope` |
| Findings | `/findings`, `/findings/{id}`, `/findings/{id}/comments`, `/findings/{id}/evidence`, `/findings/{id}/retest`, `/findings/{id}/verify`, `/findings/facets`, `/evidence/{id}/download` |
| Assessments | `/assessments/engines`, `/assessments`, `/assessments/{id}/run`, `/assessment-runs`, `/jobs`, `/jobs/{id}/cancel`, `/scanner-imports` |
| AI | `/ai/assets`, `/ai/assets/{id}`, `/ai/integrations`, `/ai/governance`, `/ai/governance/approved-providers`, `/ai-redteam/catalog`, `/ai-redteam/assessments`, `/ai-redteam/assessments/{id}/run`, `/ai-redteam/runs/{id}/tests` |
| Intelligence | `/intel/vulnerabilities`, `/intel/items`, `/intel/sources`, `/intel/sync`, `/intel/technique-exposure` |
| Attack paths | `/attack-paths`, `/attack-paths/{id}`, `/attack-paths/compute` |
| Risk | `/risk/policy`, `/risk/recalculate`, `/risk/acceptances`, `/risk/acceptances/{id}/decision`, `/risk/acceptances/{id}/revoke` |
| Remediation | `/remediation/tasks`, `/remediation/tasks/{id}`, `/remediation/tasks/{id}/ticket` |
| Policies | `/policies`, `/policies/{id}`, `/policies/{id}/evaluate`, `/policies/evaluate`, `/policies/{id}/exceptions` |
| Platform | `/integrations`, `/integrations/catalog`, `/integrations/{id}/test`, `/notifications`, `/notifications/rules`, `/reports`, `/reports/{id}/download`, `/audit/events`, `/audit/verify`, `/dashboard/overview`, `/dashboard/ai`, `/analytics/*` |

## Example: discovery to report

```bash
API=localhost:8000/api/v1; AUTH="authorization: Bearer $TOKEN"; JSON='content-type: application/json'

# 1. Authorize a domain (passive discovery)
curl -s -X POST $API/scope -H "$AUTH" -H "$JSON" -d '{"kind":"domain","value":"example.com",
  "authorization_note":"Owned by Example Corp; approved in SEC-1234"}'

# 2. Define and run discovery
ID=$(curl -s -X POST $API/assessments -H "$AUTH" -H "$JSON" -d '{"name":"EASM example.com","kind":"dns_discovery",
  "targets":[{"kind":"domain","value":"example.com"}],"schedule_interval_minutes":1440}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
curl -s -X POST $API/assessments/$ID/run -H "$AUTH" -H "$JSON" -d '{"dry_run":false}'

# 3. Import a scanner report
curl -s -X POST $API/scanner-imports -H "$AUTH" -F format=trivy -F file=@trivy.json

# 4. Highest-risk open findings
curl -s "$API/findings?open_only=true&sort=risk_score&order=desc&page_size=10" -H "$AUTH"

# 5. Generate and download a report
RID=$(curl -s -X POST $API/reports -H "$AUTH" -H "$JSON" -d '{"type":"executive","format":"pdf"}' | python3 -c 'import sys,json;print(json.load(sys.stdin)["id"])')
curl -s -OJ $API/reports/$RID/download -H "$AUTH"
```
