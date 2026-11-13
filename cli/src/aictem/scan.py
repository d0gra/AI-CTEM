"""Run every detector over a directory tree and return the report."""

from __future__ import annotations

import sys
import time
from datetime import UTC, datetime
from pathlib import Path

from aictem import __version__, gitinfo
from aictem.catalog import MODEL_EXTENSIONS, MODEL_FILE_NAMES
from aictem.detectors import Context, code, deps, infra, mcp, models, secrets, synth
from aictem.model import AI_ASSET_TYPES, SCHEMA, Inventory, Location
from aictem.walker import Walker, read_text

SECRET_SCAN_SUFFIXES = {".py", ".js", ".ts", ".tsx", ".jsx", ".mjs", ".cjs", ".go", ".java", ".kt", ".rb", ".php", ".cs", ".rs", ".swift",
                        ".sh", ".bash", ".zsh", ".ps1", ".env", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties",
                        ".tf", ".tfvars", ".xml", ".txt", ".md", ".ipynb", ".pem", ".key", ".config", ".gradle", ".sql"}


def run(root: Path, *, approved_providers: set[str] | None = None, secrets_enabled: bool = True, max_files: int = 50_000,
        excludes: list[str] | None = None) -> dict:
    started = time.monotonic()
    root = root.resolve()
    if not root.is_dir():
        raise SystemExit(f"aictem: {root} is not a directory")
    info = gitinfo.info(root)
    inv = Inventory()
    repo = inv.add("repository", info["identifier"], info["name"],
                   attributes={k: v for k, v in {"remote": info["remote"], "branch": info["branch"], "commit": info["commit"]}.items() if v},
                   location=Location(".", None, "file"))
    ctx = Context(root=root, inventory=inv, repo=repo, repo_info=info, tracked=gitinfo.tracked_files(root) if secrets_enabled else None)
    packages = deps.Packages(ctx)
    walker = Walker(root, max_files=max_files, extra_ignores=excludes)
    counts = {"files": 0, "manifests": 0, "source_files": 0, "model_files": 0}
    errors: list[str] = []

    for path, rel in walker:
        counts["files"] += 1
        try:
            _scan_file(ctx, packages, path, rel, counts, secrets_enabled)
        except Exception as exc:  # noqa: BLE001  (one odd file must not end the whole scan; it is reported instead)
            errors.append(f"{rel}: {type(exc).__name__}: {exc}"[:300])
            if len(errors) <= 5:
                print(f"aictem: skipped {errors[-1]}", file=sys.stderr)

    counts["packages"] = packages.flush()
    synth.build(ctx, approved_providers)
    body = inv.to_dict()
    by_type: dict[str, int] = {}
    for a in body["assets"]:
        by_type[a["type"]] = by_type.get(a["type"], 0) + 1
    by_sev: dict[str, int] = {}
    for f in body["findings"]:
        by_sev[f["severity"]] = by_sev.get(f["severity"], 0) + 1
    return {
        "schema": SCHEMA,
        "tool": {"name": "ctem", "version": __version__},
        "scanned_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "duration_seconds": round(time.monotonic() - started, 2),
        "target": {"path": str(root), "repository": info["identifier"], "branch": info["branch"], "commit": info["commit"], "remote": info["remote"]},
        "summary": {**counts, "truncated": walker.truncated, "errors": len(errors), "error_samples": errors[:20],
                    "assets_by_type": dict(sorted(by_type.items())),
                    "ai_assets": sum(v for k, v in by_type.items() if k in AI_ASSET_TYPES),
                    "findings_by_severity": by_sev},
        **body,
    }


def _scan_file(ctx: Context, packages, path: Path, rel: str, counts: dict, secrets_enabled: bool) -> None:
    name = path.name
    suffix = path.suffix.lower()
    if suffix in MODEL_EXTENSIONS or name in MODEL_FILE_NAMES:
        if models.scan(ctx, path, rel):
            counts["model_files"] += 1
        return
    parse = deps.handler(name)
    text = None
    if parse or suffix in code.CODE_SUFFIXES or suffix in code.CONFIG_SUFFIXES or suffix in SECRET_SCAN_SUFFIXES or name.startswith(".env") \
            or name in ("Dockerfile", "Jenkinsfile", "Containerfile") or name.lower().startswith("dockerfile"):
        text = read_text(path)
    if text is None:
        return
    if parse:
        parse(packages, rel, text)
        counts["manifests"] += 1
    if mcp.is_mcp_config(rel):
        mcp.scan(ctx, rel, text)
    handler = infra.classify(rel, text)
    if handler:
        handler(ctx, rel, text)
    kind = code.CODE_SUFFIXES.get(suffix)
    lockfile = name in deps.LOCKFILES  # generated: nothing to learn from URLs or key-shaped strings inside
    if kind:
        counts["source_files"] += 1
        code.scan_text(ctx, rel, text, kind)
    elif not lockfile and (suffix in code.CONFIG_SUFFIXES or name.startswith(".env") or name.lower().startswith("dockerfile")):
        code.scan_text(ctx, rel, text, "config")
    if secrets_enabled and not lockfile and (suffix in SECRET_SCAN_SUFFIXES or name.startswith(".env") or suffix == ""):
        secrets.scan(ctx, rel, text)
