# Security policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through the repository's private security advisory feature ("Report a vulnerability" under the Security tab). If that is unavailable, contact the maintainers through the channel listed on the repository profile. Do not open a public issue.

Include the affected version or commit, reproduction steps, and the impact you observed. Please do not test against deployments you do not own.

We aim to acknowledge reports within three business days and to provide an assessment within ten. Fixes for confirmed issues are released as soon as practical, with credit to the reporter unless anonymity is requested.

## Supported versions

Only the latest release receives security fixes while the project is pre-1.0.

## Scope notes

Reports of particular interest: cross-tenant data access, authentication or authorization bypass, server-side request forgery through assessment or webhook features, ways to make the platform contact targets outside authorized scope, credential disclosure, and prompt injection that causes the AI analysis feature to do anything other than return advisory text.

The design and its known gaps are described in [docs/security.md](docs/security.md).

## Responsible use

This software performs security assessments. Use it only against systems you own or are explicitly authorized to test. The authorized-scope mechanism records your assertion of authorization; it does not replace it.
