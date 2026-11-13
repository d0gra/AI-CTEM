"""Committed credentials. Values are never stored or printed: findings keep a prefix, the length and a fingerprint."""

from __future__ import annotations

import hashlib

from aictem.catalog import PLACEHOLDER, SECRET_PATTERNS
from aictem.detectors import Context, line_of
from aictem.model import Finding

EXAMPLE_FILES = (".example", ".sample", ".template", ".dist", "example.", "sample.")


def scan(ctx: Context, rel: str, text: str) -> None:
    lower = rel.lower()
    example = any(marker in lower.rsplit("/", 1)[-1] for marker in EXAMPLE_FILES) or "/test" in lower or "fixtures" in lower
    for pattern in SECRET_PATTERNS:
        for m in pattern.pattern.finditer(text):
            value = m.group(0)
            line_start = text.rfind("\n", 0, m.start()) + 1
            line_text = text[line_start:text.find("\n", m.end()) if "\n" in text[m.end():] else len(text)]
            if PLACEHOLDER.search(value) or (example and PLACEHOLDER.search(line_text)):
                continue
            line = line_of(text, m.start())
            prefix = next((g for g in m.groups() if g), value[:4])
            tracked = ctx.is_tracked(rel)
            confidence = "tentative" if example else ("confirmed" if tracked else "firm")
            ai = bool(pattern.provider)
            if ai:
                ctx.signal(pattern.provider, "secret", rel, line)
            # A key in a file git does not track (for example a local .env) is on this machine only, not in the repository.
            local_only = tracked is False
            severity = "low" if local_only else "medium" if example and pattern.severity in ("critical", "high") else pattern.severity
            ctx.inventory.finding(Finding(
                rule_id=f"{'ai.secret' if ai else 'secret'}.{pattern.rule}",
                title=f"{pattern.label} in local file {rel} (not tracked by git)" if local_only else f"{pattern.label} committed in {rel}",
                severity=severity, domain="secrets", asset=ctx.repo.ref, confidence=confidence,
                file=rel, line=line, cwe="CWE-798", owasp_llm="LLM02:2025" if ai else None,
                description=f"A value in the format of a {pattern.label} is present in the repository"
                            + (" (in an example or test file; confirm whether it is real)." if example else ".")
                            + (" The file is not tracked by git, so the value is on this machine only; check it is ignored and was never committed."
                               if local_only else "")
                            + (" Google API keys for browser use (Firebase, Maps) are public by design; restrict the key by referrer and API instead."
                               if pattern.rule == "google_api_key" else ""),
                remediation="Keep the file out of version control and prefer a secret manager." if local_only else
                            "Revoke and rotate the credential, remove it from the repository history, and load it from a secret manager.",
                discriminator=f"{rel}:{line}:{pattern.rule}",
                evidence={"prefix": prefix, "length": len(value), "fingerprint": hashlib.sha256(value.encode()).hexdigest()[:16],
                          "git_tracked": tracked}))
