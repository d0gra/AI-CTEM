# Changelog

All notable changes are recorded here. The format follows Keep a Changelog; versions follow Semantic Versioning.

## [0.2.0] - 2026-11-11

### Added
- Connect Claude (Administration → AI analysis): Console API key or server credentials, live model list, connection test, AI executive briefing on the Overview page.
- Platform operator console to suspend and reinstate organizations.
- Screens for teams, custom roles, notification rules and delivery log, background jobs, policy exceptions, organization settings, assessment editing/pausing/deletion/cancellation, integration editing and credential rotation, asset tags and business unit, relationship removal, MFA turn-off.
- Forgot-password, reset-password and email-verification pages; optional enforced email verification.
- Stale-asset detection; `asset.discovered` and `risk.acceptance_expired` notifications; `discovery:run` gates discovery engines.

### Fixed
- Client addresses behind the web proxy: rate limits and the audit log now use the real client address, read only from trusted proxies.
- NVD enrichment failed on CVSS 4.0 vectors and one bad record discarded the batch.
- Scanners installed outside system directories were not found by workers.
- Semgrep runs failed (`--config auto` is refused with metrics off); Checkov findings had no severity; scanner findings showed absolute paths.
- DNS discovery resolved names one at a time and stalled on slow resolvers (405s → 34s for 60 names).
- Tool version checks ran on every page load.

### Removed
- Unused settings (`CTEM_DEMO_MODE`, `CTEM_SENTRY_DSN`), unused columns, and catalogue entries with no implementation behind them (Azure, Google Cloud, Bedrock, Hugging Face).

## [0.1.0] - 2026-11-11

Initial release.

### Added
- Multi-tenant foundation: organizations, users, teams, nine built-in roles and custom roles, sessions, TOTP MFA, password reset, email verification, PostgreSQL row-level security, hash-chained audit log.
- Asset inventory with relationships, provenance and history; authorized-scope enforcement.
- Assessment framework with 17 engines: DNS/CT discovery, HTTP/TLS exposure, Nmap, Nuclei, OpenAPI analysis, scanner import (Nuclei, Trivy, Grype, Semgrep, Gitleaks, Checkov, ZAP, Prowler, SARIF, Nmap XML, CycloneDX/SPDX), path-based scanner runners, AWS posture, repository AI and supply-chain analysis, MCP probe, inference endpoint probe, AI posture review, AI red team.
- Vulnerability catalogue and threat intelligence: CISA KEV, EPSS, NVD, OSV, MITRE ATT&CK, MITRE ATLAS.
- Finding lifecycle with evidence, retest reconciliation and manual verification; unified risk engine with stored breakdown and configurable policy; risk acceptance with separation of duties.
- Attack path analysis with evidence grading and graph visualisation.
- Remediation tasks, SLAs, GitHub/GitLab/Jira ticket creation; policy engine with 13 default policies and exceptions.
- Notifications (in-app, webhook, Slack, Teams, email) with rules and storm control.
- Reports: 10 types in PDF, XLSX, CSV and JSON.
- AI-assisted analysis (optional) with schema validation, budgets and usage accounting.
- Durable PostgreSQL job queue, worker and scheduler; Prometheus metrics; optional OpenTelemetry tracing.
- Next.js frontend covering all 19 navigation sections.
- Docker and Kubernetes assets, CI workflow, documentation and ADRs.

### Known gaps
See "Known limitations" in the README.
