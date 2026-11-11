# Changelog

All notable changes are recorded here. The format follows Keep a Changelog; versions follow Semantic Versioning.

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
