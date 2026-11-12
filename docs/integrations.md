# Integrations

## Connector framework

A connector is a `ConnectorSpec` (`backend/app/integrations/base.py`) registered at import time: key, category, configuration and credential schemas (Pydantic models, published as JSON Schema to the UI), a connection test, required permissions, and its `mode`:

| Mode | Meaning |
| --- | --- |
| `connection` | The platform calls the system's API with stored credentials |
| `tool` | Workers execute the tool locally; its reports can also be uploaded |
| `upload` | Reports are uploaded and normalised |
| `feed` | A public data source synchronised by workers |

Common behaviour (`HttpApi`): SSRF-guarded transport, bounded retries with backoff on 429/5xx and network errors, `Retry-After` support, RFC 8288 `Link` pagination, minimum request interval, and classified errors (`auth`, `permission`, `rate_limit`, `config`, `network`, `upstream`). Connection tests update the integration's health and raise a notification on a new failure. Credentials are stored as an encrypted JSON document and are write-only through the API.

## Scanners

| Tool | Execution | Import format | Required on worker |
| --- | --- | --- | --- |
| Nmap | `nmap -sT -Pn -n` with a rate cap; targets resolved and validated before the scan | XML (`-oX`) | `nmap` |
| Nuclei | `nuclei -jsonl -duc -ni`; `dos`, `fuzz`, `intrusive` tags excluded by default | JSON / JSONL | `nuclei` and templates |
| Trivy | `trivy fs` (vuln, misconfig, secret) | JSON (`--format json`), including image scans | `trivy` |
| Grype | `grype dir:` | JSON (`-o json`) | `grype` |
| Semgrep | `semgrep scan --config p/default --metrics off` (registry rules; `auto` is refused with metrics off) | JSON | `semgrep` |
| Gitleaks | `gitleaks dir --redact` | JSON | `gitleaks` |
| Checkov | `checkov -d` | JSON | `checkov` |
| OWASP ZAP | — | Traditional JSON report | — |
| Prowler | — | OCSF JSON (v4+) | — |
| Any SARIF 2.1.0 producer | — | SARIF | — |
| SBOM | — | CycloneDX JSON, SPDX JSON (components checked against OSV) | — |

A file in the wrong format fails the import with a specific message rather than importing nothing. Secret values in Gitleaks reports are dropped at parse time. Reports reach the platform two ways:

- **From a pipeline** (recommended): see [CI/CD ingestion](#cicd-ingestion).
- **By hand**: **Upload results** on the Integrations catalogue or a module page, or `POST /api/v1/scanner-imports` (multipart: `format`, `file`, optional `target`) with a signed-in session.

Both appear in the upload history (`GET /api/v1/imports?source=all|ci|manual&format=…`, **Integrations → Uploaded results**, and on each module page for its formats).

### CI/CD ingestion

1. **Integrations → CI/CD pipelines → New token** (requires `integrations:manage`). The token (`ctem_ci_…`) is shown once and stored as a SHA-256 hash. It has a single scope, `ingest`: it can upload reports and read back the result of its own organization's uploads, and cannot sign in or call any other endpoint. Tokens expire after 30 days to 2 years, or never; the list shows the last use time and source address, and revoking takes effect immediately.
2. Store it as a CI secret named `CTEM_CI_TOKEN`.
3. After the scanner step, send the report:

```bash
curl --fail-with-body -sS -X POST "$CTEM_URL/api/v1/ci/ingest" \
  -H "Authorization: Bearer $CTEM_CI_TOKEN" \
  --url-query "format=trivy" --url-query "provider=github_actions" \
  --url-query "repository=$GITHUB_REPOSITORY" --url-query "branch=$GITHUB_REF_NAME" --url-query "commit=$GITHUB_SHA" \
  --url-query "fail_on=high" --url-query "exit_code=true" \
  --data-binary @trivy.json
```

The page generates the full job for GitHub Actions, GitLab CI, Jenkins or a plain shell, for each supported format. `--url-query` needs curl 7.87 or later.

| Parameter | Meaning |
| --- | --- |
| `format` (required) | One of the import formats in the table above |
| `target` | What was scanned, when the report does not say (Semgrep, Gitleaks, SARIF) |
| `repository`, `branch`, `commit`, `pipeline_url`, `provider` | Recorded with the upload and on the assets it touched (`last_ci_build`) |
| `fail_on` | `none` (default), `low`, `medium`, `high` or `critical` |
| `exit_code` | `true` returns 412 when the gate fails and 422 when the report cannot be parsed, so `curl --fail-with-body` fails the build |
| `wait`, `wait_seconds` | By default the request processes the report before responding (up to 120 s, max 600). With `wait=false`, or when processing takes longer, the response is 202 and `GET /api/v1/ci/uploads/{id}` returns the outcome |

The body is the raw report, or a multipart form with a `file` field; the size limit is `CTEM_MAX_UPLOAD_BYTES`. The JSON response contains the status, new and seen finding counts, and the gate: `passed`, `blocking_count`, up to 20 blocking findings, and open findings by severity.

**Gate semantics.** The gate counts open findings that this upload observed at or above the threshold, including findings first seen in earlier builds, so an unfixed issue keeps failing the build until it is fixed or a risk acceptance or false-positive decision is recorded for it. Findings in those states are reported as `suppressed` and do not block.

## Cloud

### AWS (`aws`)

Configuration: `regions`, optional `role_arn` and `external_id`, or `use_default_credentials` to use the worker's ambient identity. Credentials: access key pair (optional session token).

Required permissions: the AWS managed policies **SecurityAudit** and **ViewOnlyAccess**. Only `Describe*`, `List*` and `Get*` calls are made, plus `sts:GetCallerIdentity` and optionally `sts:AssumeRole`. Recommended setup: a dedicated IAM role with those two policies, assumed with an external id.

Checks: root MFA and access keys, password policy, console users without MFA, directly attached administrator policy, access keys older than 90 days, roles assumable by any principal or cross-account without an external id; S3 public access (policy, ACL, Block Public Access); security groups open to the internet on administrative and data-store ports; instances allowing IMDSv1; public or unencrypted RDS; CloudTrail not logging across regions or without log validation; KMS rotation; EKS public endpoint. Relationships recorded: account `CONTAINS` resources, instance `AUTHENTICATES_TO` role (instance profile), role `HAS_PERMISSION` on buckets when it holds a broad managed policy. An access-denied error on one service is reported in the run summary and does not hide the others.

Not covered: Lambda, ELB/ALB/NLB, Secrets Manager, VPC flow logs, inline and customer-managed policy analysis.

### Azure and GCP

No native connector. Run Prowler with the provider's reader role and import the OCSF JSON; findings are attributed to resources by their provider identifiers.

## Threat intelligence

| Source | What is stored | Refresh |
| --- | --- | --- |
| CISA KEV | Full catalogue; KEV status, due date, ransomware use | Daily (workers), or on demand |
| FIRST EPSS | Score and percentile for CVEs present in the catalogue | Daily, or on demand |
| NIST NVD | CVSS, CWE, references, affected configurations for catalogue CVEs lacking CVSS | On demand; 40 CVEs per run; set `CTEM_NVD_API_KEY` to raise the limit |
| OSV.dev | Package advisories (includes GitHub Security Advisories) | Queried during SBOM and dependency analysis |
| MITRE ATT&CK Enterprise | Tactics, techniques, mitigations | On demand |
| MITRE ATLAS | Tactics, techniques, mitigations, case studies | On demand |

Each record keeps its source, original identifier, source URL and timestamps. Sync state and the last error per source are shown under Threat Intelligence → Sources.

## Ticketing

GitHub Issues (fine-grained token with Issues read/write on one repository), GitLab Issues (project access token, `api` scope, Reporter), Jira Cloud (API token of a user with Create Issues in the project). A ticket is created only from a remediation task, by a user with `remediation:write`, with explicit confirmation. Ticket status is not synchronised back.

## Notifications

Generic webhook (JSON body; optional `X-CTEM-Signature: sha256=<hmac of "timestamp.body">`), Slack incoming webhook (Block Kit), Microsoft Teams workflow webhook (Adaptive Card), and email through SMTP. Webhook destinations must be publicly routable. Rules select event types and a minimum severity. Repeats of the same event for the same entity within 24 hours increment a counter instead of sending again.

## Claude (`claude`)

Connected under Administration → AI analysis, not from the Integrations page. Credential source is either a Claude Console API key (stored encrypted) or, when `CTEM_ALLOW_SERVER_CLAUDE_CREDENTIALS=true`, the server's own credentials via the Anthropic SDK's default chain. The connection test lists models through the Models API, which is not billed. Claude Pro, Max and Team plans do not include API access.

## Model endpoints for the AI red team (`llm`)

One connector with four styles: `openai_compatible` (OpenAI, Azure OpenAI v1, vLLM, Ollama `/v1`, NVIDIA NIM, LiteLLM), `anthropic` (official SDK; default model `claude-opus-5-5`), `gemini` (REST), and `custom_http` (an application's own chat endpoint, with a request template and response path). Used as AI red-team targets and, if selected, as the provider for AI-assisted analysis. The connection test sends one short prompt, which the provider bills.

## Adding a connector

1. Define config and credential models and a `test(config, credentials) -> ConnectionResult`.
2. `register_connector(ConnectorSpec(...))` in a module imported by `app/engines/registry.py`.
3. If it produces findings, register an engine with `requires_connector`.
4. Add tests, and record in the README what the connector was verified against.
