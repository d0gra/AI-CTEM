"""MCP client configuration files (Claude Desktop, Cursor, VS Code, Windsurf, ...): servers and their risks.
Rules and identifiers match the CTEM platform's repository analysis."""

from __future__ import annotations

import json
import re
import tomllib

from aictem.catalog import MCP_CONFIG_NAMES, MCP_CONFIG_PARENTS, SECRET_PATTERNS
from aictem.detectors import Context
from aictem.model import Finding, Location


def is_mcp_config(rel: str) -> bool:
    """Files that may declare MCP servers: known names anywhere, and settings files in editor or agent folders."""
    parts = rel.split("/")
    name = parts[-1]
    in_tool_dir = len(parts) > 1 and parts[-2] in MCP_CONFIG_PARENTS
    return name in MCP_CONFIG_NAMES or (in_tool_dir and (name.endswith(".json") and ("mcp" in name or "settings" in name or "config" in name)
                                                         or name == "config.toml"))


def _strip_json_comments(text: str) -> str:
    """Editor settings files allow // and /* */ comments and trailing commas."""
    out = re.sub(r'''("(?:\\.|[^"\\])*")|//[^\n]*|/\*[\s\S]*?\*/''', lambda m: m.group(1) or "", text)
    return re.sub(r",(\s*[}\]])", r"\1", out)


def load_servers(rel: str, text: str) -> dict | None:
    """{name: definition} from a client configuration, or None when the file declares none."""
    try:
        if rel.endswith(".toml"):
            doc = tomllib.loads(text)
        else:
            try:
                doc = json.loads(text)
            except ValueError:
                doc = json.loads(_strip_json_comments(text))
    except (ValueError, tomllib.TOMLDecodeError):
        return None
    if not isinstance(doc, dict):
        return None
    nested = doc.get("mcp") if isinstance(doc.get("mcp"), dict) else {}
    for candidate in (doc.get("mcpServers"), doc.get("mcp_servers"), nested.get("servers"), nested.get("mcpServers"), doc.get("servers")):
        if isinstance(candidate, dict) and candidate and all(isinstance(v, dict) for v in candidate.values()):
            return candidate
        if isinstance(candidate, dict) and any(isinstance(v, dict) for v in candidate.values()):
            return {k: v for k, v in candidate.items() if isinstance(v, dict)}
    return None


# Launcher options that take a value, so the value is not mistaken for the package or image being run.
_VALUE_FLAGS = {"-e", "--env", "-v", "--volume", "-p", "--publish", "--name", "--network", "--mount", "-w", "--workdir", "-u", "--user",
                "--env-file", "--entrypoint", "--platform", "--with", "--python", "--registry"}
_PACKAGE_FLAGS = {"--from", "--package", "-p"}  # npx -p <pkg> / uvx --from <pkg>: the value is the package


def analyse_definition(name: str, definition: dict) -> tuple[dict, list[dict]]:
    issues: list[dict] = []
    url = definition.get("url") or definition.get("serverUrl") or definition.get("httpUrl")
    url = url if isinstance(url, str) else None
    command = definition.get("command")
    raw_args = definition.get("args")
    if isinstance(command, list) and command:  # ["npx", "-y", "pkg"] form
        command, raw_args = str(command[0]), [*command[1:], *(raw_args if isinstance(raw_args, list) else [])]
    command = command if isinstance(command, str) and command else None
    if command and " " in command.strip() and not raw_args:  # "npx -y pkg" in one string
        command, *raw_args = command.split()
    args = [str(a) for a in raw_args] if isinstance(raw_args, list) else []
    env = definition.get("env") if isinstance(definition.get("env"), dict) else {}
    headers = definition.get("headers") if isinstance(definition.get("headers"), dict) else {}
    transport = "stdio" if command else ("sse" if str(definition.get("type", "")).lower() == "sse" or str(url or "").rstrip("/").endswith("/sse")
                                         else "streamable_http")
    auth = "not_applicable"
    if transport != "stdio":
        auth = "none"
        if any(k.lower() == "authorization" for k in headers):
            auth = "bearer"
        elif any("key" in k.lower() or "token" in k.lower() for k in headers):
            auth = "api_key"
        elif definition.get("oauth") or definition.get("auth"):
            auth = "oauth"
    facts = {"transport": transport, "endpoint": url, "command": " ".join([command, *args])[:500] if command else None, "auth_type": auth,
             "uses_tls": str(url).startswith("https://") if url else None}

    def issue(rule, title, severity, description, remediation, evidence, confidence="firm"):
        issues.append({"rule": rule, "title": title, "severity": severity, "confidence": confidence, "description": description,
                       "remediation": remediation, "evidence": evidence})

    if url and str(url).startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1|\[::1\])([:/]|$)", str(url)):
        issue("mcp.config.insecure_transport", f"MCP server '{name}' is reached over plaintext HTTP", "high",
              "Tool calls, results and any credentials are sent unencrypted and can be read or modified in transit.",
              "Use an https:// endpoint for remote MCP servers.", {"url": url}, "confirmed")
    if transport != "stdio" and auth == "none":
        issue("mcp.config.no_client_auth", f"MCP server '{name}' is configured without client authentication", "medium",
              "The client configuration sends no Authorization header or OAuth settings; if the server accepts unauthenticated clients, anyone who "
              "can reach it can invoke its tools.", "Require OAuth 2.1 or a bearer token on the server and configure the client accordingly.",
              {"url": url, "headers": sorted(headers)}, "tentative")
    literal = []
    for source, mapping in (("env", env), ("headers", headers)):
        for key, value in mapping.items() if isinstance(mapping, dict) else []:
            value = str(value)
            if not value or value.startswith(("$", "{{", "/", "~", "./", "../", "http://", "https://")) or re.fullmatch(r"[A-Za-z]:\\.*", value):
                continue  # an environment reference, a file path or a URL: not a literal credential
            hit = next((p.label for p in SECRET_PATTERNS if p.pattern.search(value)), None)
            if hit or (re.search(r"(key|token|secret|password|authorization|credential)", key, re.IGNORECASE) and len(value) >= 12):
                literal.append({"location": f"{source}.{key}", "kind": hit or "credential", "length": len(value)})
    if any(p.pattern.search(a) for p in SECRET_PATTERNS for a in args):
        literal.append({"location": "args", "kind": "credential"})
    if literal:
        issue("mcp.config.plaintext_secret", f"MCP server '{name}' configuration contains plaintext credentials", "high",
              "Credentials are stored as literals in the configuration file instead of being referenced from the environment or a secret store.",
              "Move the values to a secret manager or an environment reference (${VAR}) and rotate the exposed credentials.",
              {"secrets": literal}, "confirmed")
    if command:
        joined = " ".join([command, *args])
        launcher = command.rsplit("/", 1)[-1]
        if launcher in ("npx", "uvx", "bunx", "pipx", "pnpm", "yarn") or (launcher == "docker" and "run" in args):
            package, skip, take = None, False, False
            for arg in args:
                if take:
                    package = arg
                    break
                if skip:
                    skip = False
                elif arg in _PACKAGE_FLAGS and launcher != "docker":
                    take = True
                elif arg in _VALUE_FLAGS:
                    skip = True
                elif not arg.startswith("-") and arg not in ("run", "exec", "dlx", "x", "tool"):
                    package = arg
                    break
            # pinned: npm @1.2.3, python ==1.2.3, a digest, or an image tag that is a version (:1.2.3, :v1.2.3) but not :latest
            tag = package.rsplit(":", 1)[-1] if package and ":" in package.rsplit("/", 1)[-1] else ""
            pinned = bool(package and (re.search(r"@v?\d", package) or "==" in package or "@sha256:" in package
                                       or re.fullmatch(r"v?\d[\w.\-]*", tag)))
            if package and not pinned:
                issue("mcp.config.unpinned_server", f"MCP server '{name}' runs an unpinned package ({package})", "medium",
                      "The server is fetched at launch without a version pin, so a compromised or replaced release runs automatically with the "
                      "client's privileges.", "Pin an exact version or digest and review updates before adopting them.", {"command": joined[:300]},
                      "confirmed")
        if re.search(r"(^|\s)sudo\s|--privileged|--cap-add[= ]ALL|-v\s+/:/|--pid[= ]host", joined):
            issue("mcp.config.excessive_privilege", f"MCP server '{name}' is launched with elevated host privileges", "high",
                  "The launch command grants root, privileged container mode or the host filesystem to the MCP server.",
                  "Run MCP servers as an unprivileged user with only the mounts they need.", {"command": joined[:300]}, "confirmed")
        if re.search(r"filesystem", joined, re.IGNORECASE):
            broad = [a for a in args if a in ("/", "~", "$HOME", "/home", "/Users", "C:\\") or re.fullmatch(r"(/home|/Users)/[^/]+/?", a)]
            if broad:
                issue("mcp.config.broad_filesystem_scope", f"Filesystem MCP server '{name}' exposes a broad directory ({broad[0]})", "high",
                      "The server gives the model read and write access to an entire home or root directory, including credentials and SSH keys.",
                      "Restrict the allowed directories to the project paths required.", {"allowed_paths": broad}, "confirmed")
    approved = definition.get("autoApprove") or definition.get("alwaysAllow")
    if approved:
        issue("mcp.config.auto_approved_tools", f"MCP server '{name}' has tools approved without confirmation", "medium",
              "Listed tools run without human confirmation, removing the approval step that limits prompt-injection impact.",
              "Limit automatic approval to read-only tools.", {"auto_approved": approved if isinstance(approved, list) else True}, "confirmed")
    return facts, issues


def scan(ctx: Context, rel: str, text: str) -> None:
    servers = load_servers(rel, text)
    if not servers:
        return
    inv = ctx.inventory
    client_name = {"claude_desktop_config.json": "Claude Desktop", ".cursor": "Cursor", ".vscode": "VS Code", ".windsurf": "Windsurf",
                   ".claude": "Claude Code", ".gemini": "Gemini CLI", ".codex": "Codex", ".continue": "Continue", ".roo": "Roo Code", ".kiro": "Kiro",
                   ".amazonq": "Amazon Q"}
    parts = rel.split("/")
    label = client_name.get(parts[-1]) or client_name.get(parts[-2] if len(parts) > 1 else "") or "MCP client"
    client = inv.add("mcp_client", f"mcp-client:{ctx.repo.identifier}:{rel}", f"{label} configuration ({rel})",
                     attributes={"config_file": rel, "client": label, "servers": sorted(servers)}, ai={"provider": "mcp", "managed": False},
                     location=Location(rel, None, "config"))
    inv.link(ctx.repo, client, "CONTAINS", via=rel)
    for name, definition in servers.items():
        if not isinstance(definition, dict):
            continue
        facts, issues = analyse_definition(str(name), definition)
        identifier = facts["endpoint"] or f"stdio:{ctx.repo.identifier}:{name}"
        server = inv.add("mcp_server", identifier, f"MCP server {name}",
                         attributes={"declared_in": [rel], "transport": facts["transport"], "auth_type": facts["auth_type"],
                                     "command": facts["command"], "uses_tls": facts["uses_tls"]},
                         ai={"provider": "mcp", "managed": False}, location=Location(rel, None, "config"))
        inv.link(client, server, "CONNECTS_TO", config=rel)
        for i in issues:
            inv.finding(Finding(rule_id=i["rule"], title=i["title"], severity=i["severity"], domain="ai_mcp", asset=server.ref,
                                description=i["description"], remediation=i["remediation"], confidence=i["confidence"], file=rel,
                                owasp_llm="LLM06:2025" if "privilege" in i["rule"] or "scope" in i["rule"] or "approved" in i["rule"] else "LLM03:2025",
                                discriminator=rel, evidence=i["evidence"]))
