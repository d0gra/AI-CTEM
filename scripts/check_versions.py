#!/usr/bin/env python3
"""Check that every component of the platform declares the same version, and print it.

The version is written in five places (backend package, backend module, frontend package, the
Kubernetes manifests and the newest changelog entry). A release is refused unless they agree.

    python3 scripts/check_versions.py            # prints the version, or exits 1 naming the mismatch
    python3 scripts/check_versions.py --notes    # prints release notes for that version from CHANGELOG.md

The CLI in cli/ is versioned and released on its own and is not part of this check.
"""

from __future__ import annotations

import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "ghcr.io/d0gra/ai-ctem"


def declared() -> dict[str, str]:
    """Where each version is declared -> the version found there."""
    found = {
        "backend/pyproject.toml": tomllib.loads((ROOT / "backend/pyproject.toml").read_text())["project"]["version"],
        "frontend/package.json": json.loads((ROOT / "frontend/package.json").read_text())["version"],
    }
    module = re.search(r'^__version__ = "([^"]+)"', (ROOT / "backend/app/__init__.py").read_text(), re.M)
    found["backend/app/__init__.py"] = module.group(1) if module else "missing"
    entry = re.search(r"^## \[(\d+\.\d+\.\d+)\]", (ROOT / "CHANGELOG.md").read_text(), re.M)
    found["CHANGELOG.md (newest entry)"] = entry.group(1) if entry else "missing"
    tags = set(re.findall(rf"{re.escape(IMAGE)}:([\w.\-]+)", (ROOT / "infrastructure/kubernetes/ctem.yaml").read_text()))
    found["infrastructure/kubernetes/ctem.yaml (image tags)"] = tags.pop() if len(tags) == 1 else f"inconsistent: {sorted(tags) or 'none'}"
    return found


def notes(version: str) -> str:
    text = (ROOT / "CHANGELOG.md").read_text()
    match = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)", text, re.M | re.S)
    body = match.group(1).strip() if match else ""
    return (f"```\ndocker pull {IMAGE}:{version}\n```\n\nOne image for the whole platform; the role is the command "
            f"(`migrate`, `all`, `serve`, `worker`). It carries build provenance and an SBOM attestation:\n\n"
            f"```\ngh attestation verify oci://{IMAGE}:{version} --owner d0gra\n```\n\n{body}\n")


def main() -> int:
    found = declared()
    versions = set(found.values())
    if len(versions) != 1:
        print("Versions disagree:", file=sys.stderr)
        for place, version in found.items():
            print(f"  {version:<12} {place}", file=sys.stderr)
        return 1
    version = versions.pop()
    print(notes(version) if "--notes" in sys.argv[1:] else version)
    return 0


if __name__ == "__main__":
    sys.exit(main())
