"""Static analysis of MCP server definitions and tool metadata.

Used for MCP client configuration files found in repositories and for tool listings returned
by live servers. Tool-description checks report *indicators* of poisoning: the matched text is
included as evidence so an analyst can judge it; nothing is declared malicious automatically.
"""

import re
import unicodedata

from app.engines.ai.signatures import SECRET_PATTERNS

# (indicator id, description, pattern) applied to tool names/descriptions/parameter docs.
POISONING_INDICATORS: tuple[tuple[str, str, re.Pattern], ...] = (
    ("instruction_override", "Text instructs the model to ignore or override other instructions",
     re.compile(r"(ignore|disregard|forget|override)\s+(all\s+|any\s+)?(previous|prior|above|other|earlier|system)\s+(instructions?|rules?|prompts?)", re.I)),
    ("concealment", "Text instructs the model to hide its behaviour from the user",
     re.compile(r"(do\s+not|don'?t|never)\s+(tell|inform|mention|reveal|show|notify)\s+(this\s+)?(to\s+)?(the\s+)?(user|human)|without\s+(telling|informing|notifying)\s+the\s+user", re.I)),
    ("imperative_block", "Description contains a directive block addressed to the model",
     re.compile(r"<\s*(important|system|instructions?|secret|admin)\s*>|\[\s*(system|important)\s*\]|^\s*(system|assistant)\s*:", re.I | re.M)),
    ("sensitive_file_access", "Description directs access to credential or key material",
     re.compile(r"(~|\$HOME|/home/[^/\s]+|/root)/\.(ssh|aws|gnupg|kube|config/gcloud)|id_rsa|\.env\b|/etc/(passwd|shadow)|credentials\.json|mcp\.json", re.I)),
    ("cross_tool_instruction", "Description tells the model how to use other tools",
     re.compile(r"(before|after|when|whenever)\s+(using|calling|invoking)\s+(any\s+|the\s+)?(other\s+)?tools?|always\s+(call|use|invoke)\s+this\s+tool\s+(first|before)", re.I)),
    ("exfiltration", "Description directs data to an external destination or hidden parameter",
     re.compile(r"(send|post|upload|forward|exfiltrate|include)\s+[^.]{0,60}(to\s+https?://|as\s+(the\s+)?(sidenote|note|context|metadata)\s+param)", re.I)),
)
_INVISIBLE = {"Cf", "Co"}  # format / private-use characters (zero-width, bidi overrides, tags)

# capability -> name/description markers. Capabilities feed the agent least-privilege rules.
CAPABILITY_MARKERS: dict[str, re.Pattern] = {
    "shell": re.compile(r"\b(shell|bash|exec(ute)?[_ ]?(command|cmd)?|run[_ ]?(command|cmd|script)|terminal|subprocess)\b", re.I),
    "code_execution": re.compile(r"\b(eval|run[_ ]?(python|code|js)|code[_ ]?interpreter|execute[_ ]?code)\b", re.I),
    "filesystem_write": re.compile(r"\b(write|delete|remove|move|rename|create)[_ ]?(file|dir|directory|folder)|edit[_ ]?file\b", re.I),
    "database_write": re.compile(r"\b(execute[_ ]?sql|run[_ ]?query|insert|update|drop|delete)[_ ]?(row|table|record|sql|query)?\b.*\b(db|database|sql|table)\b|\bexecute_sql\b", re.I),
    "email_send": re.compile(r"\bsend[_ ]?(e?mail|message|sms|slack)\b", re.I),
    "payment": re.compile(r"\b(pay(ment)?|refund|transfer[_ ]?funds|charge|purchase|invoice)\b", re.I),
    "deploy": re.compile(r"\b(deploy|release|kubectl|terraform[_ ]?apply|merge[_ ]?pull)\b", re.I),
    "iam_admin": re.compile(r"\b(create|delete|grant|revoke|attach)[_ ]?(user|role|policy|permission|key)\b", re.I),
    "delete": re.compile(r"\b(delete|destroy|purge|wipe|drop)\b", re.I),
    "external_http": re.compile(r"\b(fetch|http[_ ]?request|curl|browse|web[_ ]?(search|fetch)|download)\b", re.I),
}


def classify_capabilities(name: str, description: str = "") -> list[str]:
    text = f"{name} {description[:400]}"
    return sorted(cap for cap, pattern in CAPABILITY_MARKERS.items() if pattern.search(text))


def poisoning_indicators(tool: dict) -> list[dict]:
    """Return indicators found in one tool's metadata, each with the matched excerpt."""
    texts = [("description", str(tool.get("description") or ""))]
    schema = tool.get("inputSchema") or tool.get("input_schema") or {}
    for prop, spec in (schema.get("properties") or {}).items() if isinstance(schema, dict) else []:
        if isinstance(spec, dict) and spec.get("description"):
            texts.append((f"parameter '{prop}'", str(spec["description"])))
    found = []
    for location, text in texts:
        for key, description, pattern in POISONING_INDICATORS:
            match = pattern.search(text)
            if match:
                start = max(0, match.start() - 60)
                found.append({"indicator": key, "meaning": description, "location": location,
                              "excerpt": text[start:match.end() + 60].strip()})
        hidden = sorted({f"U+{ord(ch):04X}" for ch in text if unicodedata.category(ch) in _INVISIBLE})
        if hidden:
            found.append({"indicator": "invisible_characters", "location": location, "excerpt": ", ".join(hidden[:10]),
                          "meaning": "Text contains invisible or bidirectional control characters that can hide instructions"})
        if len(text) > 4000:
            found.append({"indicator": "oversized_description", "location": location, "excerpt": f"{len(text)} characters",
                          "meaning": "Unusually long description; long text can bury instructions"})
    return found


def normalise_tools(tools: list) -> list[dict]:
    out = []
    for t in tools or []:
        if isinstance(t, dict) and t.get("name"):
            description = str(t.get("description") or "")
            out.append({"name": str(t["name"])[:200], "description": description[:2000],
                        "capabilities": classify_capabilities(str(t["name"]), description), "requires_approval": False})
    return out


def analyse_server_definition(name: str, definition: dict) -> tuple[dict, list[dict]]:
    """Analyse one entry of an MCP client configuration (`mcpServers.<name>`).

    Returns (server facts, issues). Each issue: {rule, title, severity, confidence, description,
    remediation, evidence}.
    """
    issues: list[dict] = []
    url = definition.get("url") or definition.get("serverUrl")
    command = definition.get("command")
    args = [str(a) for a in definition.get("args") or []]
    env = definition.get("env") or {}
    headers = definition.get("headers") or {}
    transport = "stdio" if command else ("sse" if str(definition.get("type", "")).lower() == "sse" or str(url or "").rstrip("/").endswith("/sse") else "streamable_http")
    auth = "none" if transport != "stdio" else "not_applicable"
    if any(k.lower() == "authorization" for k in headers):
        auth = "bearer"
    elif any("key" in k.lower() or "token" in k.lower() for k in headers):
        auth = "api_key"
    elif definition.get("oauth") or definition.get("auth"):
        auth = "oauth"
    facts = {"transport": transport, "endpoint": url, "command": " ".join([command, *args])[:1000] if command else None,
             "auth_type": auth if transport != "stdio" else "not_applicable",
             "uses_tls": (str(url).startswith("https://") if url else None)}

    def issue(rule, title, severity, description, remediation, evidence, confidence="firm"):
        issues.append({"rule": rule, "title": title, "severity": severity, "confidence": confidence,
                       "description": description, "remediation": remediation, "evidence": evidence})

    if url and str(url).startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1|\[::1\])([:/]|$)", str(url)):
        issue("mcp.config.insecure_transport", f"MCP server '{name}' is reached over plaintext HTTP", "high",
              "Tool calls, results and any credentials are sent unencrypted and can be read or modified in transit.",
              "Use an https:// endpoint for remote MCP servers.", {"url": url}, "confirmed")
    if transport != "stdio" and auth == "none":
        issue("mcp.config.no_client_auth", f"MCP server '{name}' is configured without client authentication", "medium",
              "The client configuration sends no Authorization header or OAuth settings. If the server accepts unauthenticated "
              "clients, anyone who can reach it can invoke its tools. Confirm with the MCP probe.",
              "Require OAuth 2.1 or a bearer token on the server and configure the client accordingly.", {"url": url, "headers": sorted(headers)},
              "tentative")
    literal_secrets = []
    for source, mapping in (("env", env), ("headers", headers)):
        for key, value in mapping.items() if isinstance(mapping, dict) else []:
            value = str(value)
            if value.startswith("${") or value.startswith("$") or not value:
                continue  # reference to an environment variable, not a literal
            provider_hit = next((label for _r, _p, label, pat in SECRET_PATTERNS if pat.search(value)), None)
            sensitive_name = re.search(r"(key|token|secret|password|authorization|credential)", key, re.I)
            if provider_hit or (sensitive_name and len(value) >= 12):
                literal_secrets.append({"location": f"{source}.{key}", "kind": provider_hit or "credential", "length": len(value)})
    for arg in args:
        if any(pat.search(arg) for _r, _p, _l, pat in SECRET_PATTERNS):
            literal_secrets.append({"location": "args", "kind": "credential", "length": len(arg)})
    if literal_secrets:
        issue("mcp.config.plaintext_secret", f"MCP server '{name}' configuration contains plaintext credentials", "high",
              "Credentials are stored as literals in the configuration file instead of being referenced from the environment or a secret store.",
              "Move the values to a secret manager or environment reference (${VAR}) and rotate the exposed credentials.",
              {"secrets": literal_secrets}, "confirmed")
    if command:
        joined = " ".join([command, *args])
        launcher = command.rsplit("/", 1)[-1]
        if launcher in ("npx", "uvx", "bunx", "pipx") or (launcher == "docker" and "run" in args):
            package = next((a for a in args if not a.startswith("-") and a not in ("run", "exec", "-i", "--rm")), None)
            pinned = bool(package and (re.search(r"@\d", package) or re.search(r"==\d", package) or "@sha256:" in package or re.search(r":\d[\w.]*$", package)))
            if package and not pinned:
                issue("mcp.config.unpinned_server", f"MCP server '{name}' runs an unpinned package ({package})", "medium",
                      "The server is fetched at launch without a version pin, so a compromised or replaced release runs automatically "
                      "with the client's privileges.", "Pin an exact version or digest and review updates before adopting them.",
                      {"command": joined[:300]}, "confirmed")
        if re.search(r"(^|\s)sudo\s|--privileged|--cap-add[= ]ALL|-v\s+/:/|--pid[= ]host", joined):
            issue("mcp.config.excessive_privilege", f"MCP server '{name}' is launched with elevated host privileges", "high",
                  "The launch command grants root, privileged container mode or the host filesystem to the MCP server.",
                  "Run MCP servers as an unprivileged user with only the mounts they need.", {"command": joined[:300]}, "confirmed")
        if re.search(r"server-filesystem|mcp-server-filesystem|filesystem", joined, re.I):
            broad = [a for a in args if a in ("/", "~", "$HOME", "/home", "/Users", "C:\\") or re.fullmatch(r"(/home|/Users)/[^/]+/?", a)]
            if broad:
                issue("mcp.config.broad_filesystem_scope", f"Filesystem MCP server '{name}' exposes a broad directory ({broad[0]})", "high",
                      "The server grants the model read/write access to an entire home or root directory, including credentials and SSH keys.",
                      "Restrict the allowed directories to the specific project paths required.", {"allowed_paths": broad}, "confirmed")
    if definition.get("autoApprove") or definition.get("alwaysAllow"):
        approved = definition.get("autoApprove") or definition.get("alwaysAllow")
        issue("mcp.config.auto_approved_tools", f"MCP server '{name}' has tools approved without confirmation", "medium",
              "Listed tools run without human confirmation, removing the approval step that limits prompt-injection impact.",
              "Limit automatic approval to read-only tools.", {"auto_approved": approved if isinstance(approved, list) else True}, "confirmed")
    return facts, issues
