"""Static analysis of MCP server definitions and tool metadata.

Used for tool listings returned by live servers (MCP client configuration files in repositories
are analysed by the aictem library). Tool-description checks report *indicators* of poisoning: the matched text is
included as evidence so an analyst can judge it; nothing is declared malicious automatically.
"""

import re
import unicodedata

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
