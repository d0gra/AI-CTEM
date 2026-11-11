# Integrations

## Connector framework

A connector is a `ConnectorSpec` (`backend/app/integrations/base.py`) registered at import time: key, category, configuration and credential schemas (Pydantic models, published as JSON Schema to the UI), a connection test, required permissions and an honest status.

| Status | Meaning |
| --- | --- |
| `available` | Implemented and covered by automated tests |
| `import_only` | Results are ingested from files; the platform does not call the system |
| `reference` | Public data source synchronised by workers; nothing to configure |

`live_validated` is true only where the code path ran against the real thing during development (Nmap, Nuclei, generic webhook). Everything else is tested against controlled fixtures and is labelled "live validation pending" in the UI.

Common behaviour (`HttpApi`): SSRF-guarded transport, bounded retries with backoff on 429/5xx and network errors, `Retry-After` support, RFC 8288 `Link` pagination, minimum request interval, and classified errors (`auth`, `permission`, `rate_limit`, `config`, `network`, `upstream`). Connection tests update the integration's health and raise a notification on a new failure. Credentials are stored as an encrypted JSON document and are write-only through the API.

## Scanners

| Tool | Execution | Import format | Required on worker |
| --- | --- | --- | --- |
| Nmap | `nmap -sT -Pn -n` with a rate cap; targets resolved and validated before the scan | XML (`-oX`) | `nmap` |
| Nuclei | `nuclei -jsonl -duc -ni`; `dos`, `fuzz`, `intrusive` tags excluded by default | JSON / JSONL | `nuclei` and templates |
| Trivy | `trivy fs` (vuln, misconfig, secret) | JSON (`--format json`), including image scans | `trivy` |
| Grype | `grype dir:` | JSON (`-o json`) | `grype` |
| Semgrep | `semgrep scan --config auto --metrics off` | JSON | `semgrep` |
| Gitleaks | `gitleaks dir --redact` | JSON | `gitleaks` |
| Checkov | `checkov -d` | JSON | `checkov` |
| OWASP ZAP | — | Traditional JSON report | — |
| Prowler | — | OCSF JSON (v4+) | — |
| Any SARIF 2.1.0 producer | — | SARIF | — |
| SBOM | — | CycloneDX JSON, SPDX JSON (components checked against OSV) | — |

Import: `POST /api/v1/scanner-imports` (multipart: `format`, `file`, optional `target`) or **Import results** in the UI. A file in the wrong format fails the import with a specific message rather than importing nothing. Secret values in Gitleaks reports are dropped at parse time.

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

## LLM endpoints (`llm`)

One connector with four styles: `openai_compatible` (OpenAI, Azure OpenAI v1, vLLM, Ollama `/v1`, NVIDIA NIM, LiteLLM), `anthropic` (official SDK; default model `claude-opus-5-5`), `gemini` (REST), and `custom_http` (an application's own chat endpoint, with a request template and response path). Used as AI red-team targets and, if selected, as the provider for AI-assisted analysis. The connection test sends one short prompt, which the provider bills.

## Adding a connector

1. Define config and credential models and a `test(config, credentials) -> ConnectionResult`.
2. `register_connector(ConnectorSpec(...))` in a module imported by `app/engines/registry.py`.
3. If it produces findings, register an engine with `requires_connector`.
4. Add fixture-based tests. Set `live_validated=True` only after running against the real system.
