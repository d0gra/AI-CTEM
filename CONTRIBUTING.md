# Contributing

1. Open an issue describing the change before large work.
2. Set up the environment as described in [docs/development.md](docs/development.md).
3. Keep changes focused. Follow the conventions in the development guide: domain boundaries, tenant-scoped data access, the shared outbound HTTP client, honest finding confidence.
4. Add tests. New tenant-owned resources need a cross-tenant assertion in `backend/tests/test_isolation_security.py`. New connectors need fixture tests and must not set `live_validated` unless they were run against the real system.
5. Run the checks listed under "Checks before a pull request" in the development guide.
6. Do not document a capability that is not implemented. Update the README's integration table and known limitations when status changes.
7. Never commit credentials, real scan results or customer data. Test fixtures must be synthetic.

Report security vulnerabilities privately as described in [SECURITY.md](SECURITY.md), not in public issues.

By contributing you agree that your contributions are licensed under the Apache License 2.0.
