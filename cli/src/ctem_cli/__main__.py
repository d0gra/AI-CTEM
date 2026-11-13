"""ctem command line.

  ctem discover [PATH]                  inventory a repository: packages, containers, cloud, CI and AI assets, with findings
  ctem discover . --format json -o r.json
  ctem discover . --upload              send the inventory to the CTEM platform (CTEM_URL, CTEM_CI_TOKEN)
  ctem discover . --vulns               also look up known vulnerabilities in pinned packages (OSV)
  ctem discover . --fail-on high        exit 1 if a finding at or above the severity is present
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from ctem_cli import __version__, output, scan
from ctem_cli.model import SEVERITY_RANK

EXIT_FINDINGS, EXIT_UPLOAD_GATE, EXIT_ERROR = 1, 3, 2


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ctem", description="Discover repository and AI assets and send them to the CTEM platform.")
    parser.add_argument("--version", action="version", version=f"ctem {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    d = sub.add_parser("discover", help="inventory a directory tree", description="Inventory a repository: dependencies, container images, cloud "
                       "resources, CI pipelines, secrets, and AI assets (providers, frameworks, agents, RAG, MCP servers, models).")
    d.add_argument("path", nargs="?", default=".", help="directory to scan (default: current directory)")
    d.add_argument("-f", "--format", choices=("table", "json", "sarif"), default="table", help="output format (json is the upload format)")
    d.add_argument("-o", "--output", help="write the report to a file instead of standard output")
    d.add_argument("--approved-providers", help="comma-separated AI provider keys; others are reported as shadow AI (for example openai,anthropic)")
    d.add_argument("--no-secrets", action="store_true", help="skip the committed-credential scan")
    d.add_argument("--vulns", action="store_true", help="look up known vulnerabilities in pinned packages at osv.dev (sends names and versions)")
    d.add_argument("--exclude", action="append", default=[], metavar="GLOB", help="skip paths matching a glob (repeatable; also read from .ctemignore)")
    d.add_argument("--max-files", type=int, default=50_000, help="stop after this many files (default 50000)")
    d.add_argument("--fail-on", choices=("none", "low", "medium", "high", "critical"), default="none",
                   help="exit with status 1 when a finding at or above this severity is present")
    d.add_argument("--all", action="store_true", help="table format: list every asset and finding")
    up = d.add_argument_group("upload to the CTEM platform")
    up.add_argument("--upload", action="store_true", help="send the report to the platform's CI ingestion endpoint")
    up.add_argument("--url", default=os.environ.get("CTEM_URL"), help="platform address (default: $CTEM_URL)")
    up.add_argument("--token-env", default="CTEM_CI_TOKEN", help="environment variable holding the pipeline token (default: CTEM_CI_TOKEN)")
    up.add_argument("--gate", choices=("none", "low", "medium", "high", "critical"), default="none",
                    help="server-side gate: fail (exit 3) when open findings at or above this severity remain after the upload")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    approved = {p.strip().lower() for p in (args.approved_providers or "").split(",") if p.strip()} or None
    report = scan.run(Path(args.path), approved_providers=approved, secrets_enabled=not args.no_secrets, max_files=args.max_files,
                      excludes=args.exclude)
    if args.vulns:
        from ctem_cli import osv

        try:
            added = osv.enrich(report)
            print(f"ctem: {added} known vulnerabilities in {report['summary']['vulnerabilities_checked']} pinned packages", file=sys.stderr)
        except OSError as exc:
            print(f"ctem: vulnerability lookup failed: {exc}", file=sys.stderr)

    if args.format == "table" and not args.output:
        output.table(report, show_all=args.all)
    else:
        rendered = output.to_sarif(report) if args.format == "sarif" else output.to_json(report) if args.format == "json" else None
        if rendered is None:  # table to a file
            with open(args.output, "w", encoding="utf-8") as fh:
                output.table(report, fh, show_all=True)
        elif args.output:
            Path(args.output).write_text(rendered, encoding="utf-8")
        else:
            sys.stdout.write(rendered)
        if args.output:
            s = report["summary"]
            print(f"ctem: wrote {args.output}: {len(report['assets'])} assets ({s['ai_assets']} AI), {len(report['findings'])} findings", file=sys.stderr)

    status = 0
    if args.upload:
        from ctem_cli import upload

        token = os.environ.get(args.token_env)
        if not args.url or not token:
            print(f"ctem: --upload needs --url (or CTEM_URL) and a pipeline token in ${args.token_env}", file=sys.stderr)
            return EXIT_ERROR
        code, body = upload.send(report, args.url, token, fail_on=args.gate)
        if code >= 400 and code != 412:
            print(f"ctem: upload failed (HTTP {code}): {(body.get('error') or {}).get('message') or body}", file=sys.stderr)
            return EXIT_ERROR
        gate = body.get("gate") or {}
        print(f"ctem: uploaded ({body.get('status')}): {body.get('findings_new', 0)} new, {body.get('findings_seen', 0)} seen findings"
              + (f"; gate {'passed' if gate.get('passed') else 'FAILED'} at {gate.get('threshold')}" if gate and gate.get("threshold") != "none" else ""),
              file=sys.stderr)
        if code == 412:
            status = EXIT_UPLOAD_GATE

    if args.fail_on != "none":
        worst = output.worst(report)
        if worst and SEVERITY_RANK[worst] >= SEVERITY_RANK[args.fail_on]:
            print(f"ctem: findings at or above {args.fail_on} present (worst: {worst})", file=sys.stderr)
            status = status or EXIT_FINDINGS
    return status


if __name__ == "__main__":
    sys.exit(main())
