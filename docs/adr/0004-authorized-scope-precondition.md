# ADR 0004: Authorized scope as a hard precondition for assessment

**Status:** accepted

**Context.** The platform can send traffic to arbitrary hosts. Without a control, it is a scanning proxy and an SSRF primitive, and users can assess systems they have no right to test.

**Decision.** Engines obtain every target through `EngineContext.scope()`, which requires a matching, unexpired `scope_targets` row recorded by a user with `scope:manage`, including an authorization note. Active techniques require `allow_active`. Private addresses require both the entry's `allow_private_network` and the deployment switch `CTEM_ALLOW_PRIVATE_TARGETS`. Scope is checked when an assessment is defined and again when it runs. Link-local and cloud metadata addresses are refused unconditionally by the HTTP client.

**Consequences.** There is one more step before the first assessment. Withdrawing scope stops scheduled assessments on their next run without editing them. The control is only as strong as the organization's process for recording authorizations; the audit log records who authorized what.
