# ADR 0005: Deterministic detection for AI red-team tests

**Status:** accepted

**Context.** A common approach is to have a second model judge whether an attack succeeded. That makes results non-reproducible, adds a second model's failure modes, and lets a model declare a vulnerability confirmed, which this platform does not allow.

**Decision.** Each test plants a random marker or synthetic canary, or offers a specific tool, and counts as vulnerable only if that exact value (in plain or simple transformed form) or that tool call appears in the response. Payloads ask for a harmless echo, never for harmful content. Confidence is derived from reproducibility across attempts and from whether exploitability depends on the surrounding application.

**Consequences.** Results are reproducible and explainable, and evidence is the recorded exchange. Coverage is limited to behaviours that can be detected this way: nuanced policy violations, harmful-content generation and multi-turn manipulation are out of scope, and a "not vulnerable" result means only that these specific probes did not succeed.
