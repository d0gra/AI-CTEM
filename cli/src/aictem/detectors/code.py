"""Source and configuration analysis: AI SDK imports, environment variables, endpoints, model references,
agents and their tools, retrieval pipelines, MCP servers implemented in the repository, and risky flags."""

from __future__ import annotations

import ast
import bisect
import json
import re
from urllib.parse import urlsplit

from aictem.catalog import (
    CAPABILITY_MARKERS,
    ENV_INDEX,
    GO_INDEX,
    HF_MODEL_REF,
    HIGH_IMPACT,
    IMPORT_INDEX,
    INFERENCE_MARKERS,
    INTEGRATIONS,
    MODEL_NAME,
    MODEL_PREFIXES,
    POISONING_INDICATORS,
    PREFIXED_MODEL,
    TECHS,
    is_reference_host,
)
from aictem.detectors import Context, line_of
from aictem.model import Finding, Location

CODE_SUFFIXES = {".py": "python", ".pyi": "python", ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript", ".jsx": "javascript",
                 ".ts": "typescript", ".tsx": "typescript", ".mts": "typescript", ".cts": "typescript", ".go": "go", ".ipynb": "notebook"}
CONFIG_SUFFIXES = {".env", ".yaml", ".yml", ".toml", ".json", ".ini", ".cfg", ".conf", ".properties", ".tf", ".tfvars"}
JS_KINDS = ("javascript", "typescript")
TEST_PATH = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|testdata|e2e)/|(^|/)test_[^/]*$|_test\.\w+$|\.(test|spec)\.\w+$|(^|/)conftest\.py$")

PY_IMPORT = re.compile(r"^[ \t]*(?:from\s+([A-Za-z_][\w.]*)\s+import|import\s+([A-Za-z_][\w.]*(?:\s*,\s*[A-Za-z_][\w.]*)*))", re.MULTILINE)
JS_IMPORT = re.compile(r"""(?:\bfrom\s+|\brequire\(\s*|\bimport\(\s*|^\s*import\s+)['"]([^'"]+)['"]""", re.MULTILINE)
GO_IMPORT = re.compile(r'"((?:github\.com|google\.golang\.org|go\.\w+)/[^"\s]+)"')
ENV_REF = re.compile(r"""(?:os\.environ(?:\.get)?\s*[\[(]\s*|os\.getenv\(\s*|getenv\(\s*|process\.env\.|process\.env\[\s*|Deno\.env\.get\(\s*|"""
                     r"""import\.meta\.env\.|os\.Getenv\(\s*)['"]?([A-Z][A-Z0-9_]{2,})""")
ENV_ASSIGN = re.compile(r"""^\s*(?:export\s+|-\s+)?["']?([A-Z][A-Z0-9_]{2,})["']?\s*[=:]""", re.MULTILINE)
URL = re.compile(r"""https?://[^\s'"`<>)\]}\\,]+""")
LOCAL_URL = re.compile(r"https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|host\.docker\.internal)\b")

# Agent constructs: (framework, pattern)
AGENT_PATTERNS: tuple[tuple[str, re.Pattern], ...] = (
    ("deepagents", re.compile(r"\b(create_deep_agent|async_create_deep_agent|define_deep_agent)\s*\(")),
    ("langchain", re.compile(r"\b(create_agent|AgentExecutor|initialize_agent|create_(?:react|tool_calling|openai_functions|structured_chat)_agent)\s*\(")),
    ("langgraph", re.compile(r"\b(create_react_agent|create_supervisor|create_swarm|StateGraph|ToolNode|createReactAgent)\s*\(")),
    ("crewai", re.compile(r"\bAgent\s*\(\s*(?:role|config)\s*=|^\s*@agent\b", re.MULTILINE)),
    ("autogen", re.compile(r"\b(AssistantAgent|UserProxyAgent|ConversableAgent|SelectorGroupChat|RoundRobinGroupChat)\s*\(")),
    ("openai_agents", re.compile(r"\bfrom\s+agents\s+import\s+[^\n]*\bAgent\b|\bfrom\s+['\"]@openai/agents['\"]|\bRunner\.run(?:_sync|_streamed)?\s*\(")),
    ("pydantic_ai", re.compile(r"\bfrom\s+pydantic_ai\s+import[^\n]*\bAgent\b")),
    ("smolagents", re.compile(r"\b(CodeAgent|ToolCallingAgent)\s*\(")),
    ("semantic_kernel", re.compile(r"\b(ChatCompletionAgent|AzureAIAgent|AgentGroupChat)\s*\(")),
    ("google_adk", re.compile(r"\bfrom\s+google\.adk\.agents\s+import|\bLlmAgent\s*\(")),
    ("strands", re.compile(r"\bfrom\s+strands\s+import[^\n]*\bAgent\b")),
    ("llamaindex", re.compile(r"\b(ReActAgent|FunctionAgent|FunctionCallingAgent|AgentWorkflow|OpenAIAgent)\s*[.(]")),
    ("claude_agent_sdk", re.compile(r"\b(ClaudeSDKClient|ClaudeAgentOptions|ClaudeCodeOptions)\s*\(|\bfrom\s+claude_agent_sdk\s+import[^\n]*\bquery\b|"
                                    r"\bfrom\s+['\"]@anthropic-ai/claude-agent-sdk['\"]")),
    ("vercel_ai", re.compile(r"\b(generateText|streamText|generateObject)\s*\(\s*\{(?:[^{}]|\{[^{}]*\})*?\btools\s*:|\bnew\s+(?:Experimental_)?Agent\s*\(\s*\{[^}]*\bmodel\s*:", re.DOTALL)),
    ("mastra", re.compile(r"\bnew\s+Agent\s*\(\s*\{[^}]*\binstructions\s*:", re.DOTALL)),
    ("openai", re.compile(r"""\btools\s*[=:]\s*\[\s*\{\s*["']?type["']?\s*:\s*["']function""")),
    ("anthropic", re.compile(r"""\btools\s*[=:]\s*\[\s*\{\s*["']?name["']?[\s\S]{0,300}["']?input_schema["']?\s*:""")),
)
PY_DECORATOR = re.compile(r"^[ \t]*@(?:[\w.]+\.)?(tool|tool_plain|function_tool|kernel_function)\b", re.MULTILINE)
# The def may follow further decorators, comments or blank lines.
PY_DEF = re.compile(r"[^\n]*\n(?:[ \t]*(?:@[^\n]*|#[^\n]*)?\n)*[ \t]*(?:async\s+)?def\s+(\w+)\s*\(")
DOCSTRING = re.compile(r"""\s*[rRuUbB]{0,2}(\"\"\"|''')([\s\S]*?)\1""")
KW_NAME = re.compile(r"""\bname\s*=\s*["']([\w\-. ]{1,80})["']""")
KW_DESCRIPTION = re.compile(r"""\bdescription\s*[=:]\s*(?:\"\"\"([\s\S]*?)\"\"\"|"((?:[^"\\\n]|\\.)*)"|'((?:[^'\\\n]|\\.)*)'|`([^`]*)`)""")
PY_TOOL_OBJ = re.compile(r"\b(?:Tool|StructuredTool(?:\.from_function)?|FunctionTool(?:\.from_defaults)?)\s*\(")
JS_TOOL = re.compile(r"""(?:\b\w+\.)?\b(?:tool|createTool|registerTool)\s*\(\s*(?:\{\s*(?:id|name)\s*:\s*)?['"]([\w\-.]+)['"]\s*,?\s*(?:\{\s*(?:title\s*:\s*['"][^'"]*['"]\s*,\s*)?description\s*:\s*)?(?:['"`]([^'"`]{0,300})['"`])?""")
JS_KEYED_TOOL = re.compile(r"\b([A-Za-z_$][\w$]*)\s*:\s*tool\s*\(\s*\{")  # Vercel AI SDK: tools: { name: tool({ description, ... }) }
JS_TOOL_VAR = re.compile(r"""\.(?:registerTool|tool)\s*\(\s*([A-Za-z_$][\w$]*)\s*,""")
JS_CONST = re.compile(r"""\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*["'`]([\w\-.]{1,80})["'`]""")
TOOL_CLASS = re.compile(r"\b(PythonREPLTool|PythonAstREPLTool|ShellTool|BashProcess|TerminalTool|RequestsPostTool|RequestsPutTool|RequestsDeleteTool|"
                        r"SQLDatabaseToolkit|QuerySQLDataBaseTool|FileManagementToolkit|WriteFileTool|DeleteFileTool|GmailToolkit|SlackToolkit|"
                        r"CodeInterpreterTool|FileWriterTool)\b")
TOOL_CLASS_CAPS = {"PythonREPLTool": ["code_execution"], "PythonAstREPLTool": ["code_execution"], "ShellTool": ["shell"], "BashProcess": ["shell"],
                   "TerminalTool": ["shell"], "RequestsPostTool": ["external_http"], "RequestsPutTool": ["external_http"],
                   "RequestsDeleteTool": ["delete", "external_http"], "SQLDatabaseToolkit": ["database_write"], "QuerySQLDataBaseTool": ["database_write"],
                   "FileManagementToolkit": ["filesystem_write"], "WriteFileTool": ["filesystem_write"], "DeleteFileTool": ["delete", "filesystem_write"],
                   "GmailToolkit": ["email_send"], "SlackToolkit": ["email_send"], "CodeInterpreterTool": ["code_execution"],
                   "FileWriterTool": ["filesystem_write"]}
APPROVAL_MARKERS = re.compile(r"\b(interrupt_before|interrupt_after|interrupt\s*\(|human_in_the_loop|HumanInTheLoop\w*|require_approval|requires_approval|"
                              r"needsApproval|human_input_mode\s*=\s*['\"]ALWAYS|human_input\s*=\s*True|ask_human|approval_required|confirm_before|"
                              r"can_use_tool|permission_mode)")
RAG_MARKERS = re.compile(r"\b(as_retriever|similarity_search\w*|max_marginal_relevance_search|VectorStoreIndex|SimpleDirectoryReader|DirectoryLoader|"
                         r"PyPDFLoader|WebBaseLoader|RecursiveCharacterTextSplitter|TextSplitter|embed_documents|embed_query|RetrievalQA|"
                         r"create_retrieval_chain|ConversationalRetrievalChain|InMemoryVectorStore|query_engine|\w*Embeddings(?=\s*\()|"
                         r"embeddings\.create(?=\s*\()|query_texts)\b")
# A file implements an MCP server when it constructs one (imports alone are not enough).
MCP_SERVER_IMPL = re.compile(r"\b(FastMCP|MCPServer|McpServer|LowLevelServer)\s*\(|\bnew\s+(?:Mcp)?Server\s*\(|\bserver\.NewMCPServer\s*\(|"
                             r"\bmcp\.NewServer\s*\(|\bServer\s*\(\s*[\"']")
MCP_TOOL_REGISTRATION = re.compile(r"\.registerTool\s*\(|@\w+\.tool\b|\bserver\.tool\s*\(")
MCP_SERVER_IMPORT = re.compile(r"""(?:from\s+(?:mcp\.server|fastmcp|mcp)\b|['"]@modelcontextprotocol/(?:server|sdk/server)[^'"]*['"]|"""
                               r"""['"]github\.com/(?:mark3labs/mcp-go/server|modelcontextprotocol/go-sdk/mcp)['"]|\bMcpServer\b|\bregisterTool\b)""")
MCP_CLIENT_IMPL = re.compile(r"\b(ClientSession\s*\(|stdio_client\s*\(|streamablehttp_client\s*\(|sse_client\s*\(|MultiServerMCPClient|"
                             r"MCPServerStdio|MCPServerStreamableHttp|MCPServerSse|MCPClient\s*\(|McpToolset|MCPToolset|define_mcp\s*\(|mcp_servers\s*=|"
                             r"experimental_createMCPClient|createMCPClient)")
AGENT_ROLE = re.compile(r"""\brole\s*=\s*(?:\(\s*)?["']([^"'\n]{2,80})["']""")
AGENT_NAME = re.compile(r"""\bname\s*[=:]\s*["']([\w .\-]{2,80})["']""")
IDENT = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{2,}\b")
# name: { ... transport: "stdio" | "http" ... } as passed to MultiServerMCPClient, define_mcp or an mcpServers object in code.
MCP_DICT_ENTRY = re.compile(r"""["']?([\w.\-]+)["']?\s*:\s*(\{(?:[^{}]|\{[^{}]*\})*?["']?transport["']?\s*:\s*["'](?:stdio|http|streamable_http|"""
                            r"""streamable-http|sse|websocket)["'](?:[^{}]|\{[^{}]*\})*\})""")

RISKY_FLAGS: tuple[tuple[str, re.Pattern, str, str, str, str, str], ...] = (
    # rule, pattern, severity, domain, title, description, remediation
    ("ai.code.trust_remote_code", re.compile(r"\btrust_remote_code\s*=\s*True"), "high", "ai_model",
     "Model loading executes repository code from the model hub (trust_remote_code=True)",
     "Loading with trust_remote_code runs Python files published alongside the model, with the application's privileges.",
     "Pin a reviewed model revision (revision=<commit>), or load models that do not need custom code."),
    ("ai.code.dangerous_langchain_flag", re.compile(r"\ballow_dangerous_(?:code|requests|deserialization)\s*=\s*True"), "high", "ai_agent",
     "LangChain safety guard disabled (allow_dangerous_*=True)",
     "The flag explicitly enables arbitrary code execution, unrestricted requests or unsafe deserialization driven by model output.",
     "Remove the flag, or run the chain in an isolated sandbox with no credentials or network access."),
)
# exec/eval of a value whose name suggests model output. Only reported in files that use an AI SDK, and as a lead to check.
EXEC_OUTPUT = re.compile(r"(?<![\w.$])(?:exec|eval)\s*\(\s*(?:\w+\.)?(?:content|text|output|completion|response(?:\.[\w\[\]]+)*|result|answer|generated_code)\b")
TORCH_LOAD = re.compile(r"\btorch\.load\s*\(")


def _words(name: str) -> str:
    """refund_order / refundOrder -> "refund order", so word-boundary patterns see identifier parts."""
    return re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name).replace("_", " ").replace("-", " ")


def _tool(name: str, description: str = "") -> dict:
    # The name says what a tool does; descriptions also explain context ("pay-as-you-go rates"), so only their first sentence counts.
    description = " ".join(description.split())
    first = re.split(r"(?<=[.!?])\s", description, maxsplit=1)[0][:300]
    text = f"{name} {_words(name)} {first}"
    caps = sorted(cap for cap, pattern in CAPABILITY_MARKERS.items() if pattern.search(text))
    return {"name": name[:200], "description": description[:400], "capabilities": caps}


def _poisoning(text: str) -> list[dict]:
    hits = []
    for key, meaning, pattern in POISONING_INDICATORS:
        m = pattern.search(text)
        if m:
            hits.append({"indicator": key, "meaning": meaning, "excerpt": text[max(0, m.start() - 40):m.end() + 40].strip()})
    return hits


def _notebook_code(text: str) -> str | None:
    try:
        doc = json.loads(text)
    except ValueError:
        return None
    cells = doc.get("cells") if isinstance(doc, dict) else None
    if not isinstance(cells, list):
        return None
    out = []
    for cell in cells:
        if isinstance(cell, dict) and cell.get("cell_type") == "code":
            source = cell.get("source")
            code = "".join(str(s) for s in source) if isinstance(source, list) else str(source or "")
            # IPython magics and shell escapes are not Python
            out.append("\n".join("" if line.lstrip().startswith(("%", "!")) else line for line in code.split("\n")))
    return "\n".join(out)


def _split(url: str):
    try:
        return urlsplit(url)
    except ValueError:  # malformed text that only looks like a URL
        return None


class Spans:
    """Where string literals and comments are, so structural patterns only count in real code."""

    PY = re.compile(r'''("""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')|(#[^\n]*)''')
    JS = re.compile(r'''("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*'|`(?:\\.|[^`\\])*`)|(//[^\n]*|/\*[\s\S]*?\*/)''')
    GO = re.compile(r'''("(?:\\.|[^"\\\n])*"|`[^`]*`)|(//[^\n]*|/\*[\s\S]*?\*/)''')
    HASH = re.compile(r'''("(?:\\.|[^"\\\n])*"|'(?:\\.|[^'\\\n])*')|((?:^|(?<=\s))#[^\n]*)''', re.MULTILINE)  # YAML, TOML, .env, Dockerfile

    def __init__(self, text: str, kind: str) -> None:
        pattern = {"python": self.PY, "javascript": self.JS, "typescript": self.JS, "go": self.GO, "config": self.HASH}.get(kind)
        self.starts: list[int] = []
        self.ends: list[int] = []
        self.comment: list[bool] = []
        if pattern is not None:
            for m in pattern.finditer(text):
                self.starts.append(m.start())
                self.ends.append(m.end())
                self.comment.append(m.group(2) is not None)

    def at(self, pos: int) -> int | None:
        i = bisect.bisect_right(self.starts, pos) - 1
        return i if i >= 0 and pos < self.ends[i] else None

    def in_code(self, pos: int) -> bool:
        return self.at(pos) is None

    def in_comment(self, pos: int) -> bool:
        i = self.at(pos)
        return i is not None and self.comment[i]


def _code_matches(pattern: re.Pattern, text: str, spans: Spans, *, keys: bool = False):
    """Matches that start in real code. With keys=True a match may also start with a short string literal that
    closes inside the match, which is how a dictionary key looks ({"model": "gpt-4o"})."""
    for m in pattern.finditer(text):
        pos = m.start()
        while pos < m.end() and text[pos].isspace():
            pos += 1
        i = spans.at(pos)
        if i is None or (keys and not spans.comment[i] and spans.starts[i] == pos and spans.ends[i] < m.end()):
            yield m


def _balanced(text: str, start: int, spans: Spans, limit: int = 6000) -> int:
    """Index just past the bracket that closes the one at `start`, skipping strings and comments; -1 if not found."""
    depth, pos, end = 0, start, min(len(text), start + limit)
    while pos < end:
        i = spans.at(pos)
        if i is not None:
            pos = spans.ends[i]
            continue
        ch = text[pos]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return pos + 1
        pos += 1
    return -1


def _kw_description(args: str) -> str:
    m = KW_DESCRIPTION.search(args)
    return next((g for g in m.groups() if g), "") if m else ""


def _python_tools(text: str, spans: Spans) -> list[dict]:
    """Functions decorated as tools (@tool, @mcp.tool(...), @function_tool, ...) and Tool(name=..., description=...) objects."""
    tools: list[dict] = []

    def add(name: str, description: str, pos: int) -> None:
        if name and not any(t["name"] == name for t in tools):
            tools.append(_tool(name, description) | {"line": line_of(text, pos), "poisoning": _poisoning(description)})

    for m in _code_matches(PY_DECORATOR, text, spans):
        pos, args = m.end(), ""
        if text[pos:pos + 1] == "(":  # decorator arguments, possibly over several lines
            close = _balanced(text, pos, spans)
            if close < 0:
                continue
            args, pos = text[pos + 1:close - 1], close
        definition = PY_DEF.match(text, pos)
        if not definition:
            continue
        close = _balanced(text, definition.end() - 1, spans)  # the parameter list may contain calls and annotations
        colon = text.find(":", close) if close > 0 else -1
        doc = DOCSTRING.match(text, colon + 1) if 0 < colon < close + 300 else None
        explicit = KW_NAME.search(args)
        add(explicit.group(1) if explicit else definition.group(1), (doc.group(2) if doc else "") or _kw_description(args), m.start())
    for m in _code_matches(PY_TOOL_OBJ, text, spans):
        close = _balanced(text, m.end() - 1, spans)
        if close > 0:
            args = text[m.end():close - 1]
            explicit = KW_NAME.search(args)
            if explicit:
                add(explicit.group(1), _kw_description(args), m.start())
    return tools


def _javascript_tools(text: str, spans: Spans) -> list[dict]:
    tools: list[dict] = []

    def add(name: str, description: str, pos: int) -> None:
        if name and not any(t["name"] == name for t in tools):
            tools.append(_tool(name, description) | {"line": line_of(text, pos), "poisoning": _poisoning(description)})

    for m in _code_matches(JS_TOOL, text, spans):
        add(m.group(1), m.group(2) or "", m.start())
    for m in _code_matches(JS_KEYED_TOOL, text, spans):
        close = _balanced(text, m.end() - 1, spans)
        add(m.group(1), _kw_description(text[m.end():close if close > 0 else m.end() + 600]), m.start())
    registrations = list(_code_matches(JS_TOOL_VAR, text, spans))
    constants = dict(JS_CONST.findall(text))
    for m in registrations:
        name = constants.get(m.group(1))
        # the description usually lives in a config object declared elsewhere in the module; only unambiguous with one tool
        add(name or "", _kw_description(text) if len(registrations) == 1 else "", m.start())
    return tools


def _unsafe_torch_loads(text: str, spans: Spans):
    for m in _code_matches(TORCH_LOAD, text, spans):
        close = _balanced(text, m.end() - 1, spans)
        args = text[m.end():close - 1] if close > 0 else text[m.end():m.end() + 300]
        if not re.search(r"\bweights_only\s*=\s*True\b", args):
            yield m


def scan_text(ctx: Context, rel: str, text: str, kind: str) -> None:
    """kind: python | javascript | typescript | go | notebook | config"""
    if kind == "notebook":
        code = _notebook_code(text)
        if code is None:
            return
        text, kind = code, "python"
    lang = {"python": "Python", "javascript": "JavaScript", "typescript": "TypeScript", "go": "Go"}.get(kind)
    if lang:
        ctx.languages[lang] = ctx.languages.get(lang, 0) + 1
    spans = Spans(text, kind)
    signals_before = len(ctx.signals)
    in_tests = bool(TEST_PATH.search(rel))

    # Imports
    if kind == "python":
        for m in _code_matches(PY_IMPORT, text, spans):
            modules = [m.group(1)] if m.group(1) else [x.strip() for x in m.group(2).split(",")]
            for module in modules:
                parts = module.split(".")
                for depth in (2, 1):  # "google.genai" before "google"
                    tech = IMPORT_INDEX.get(".".join(parts[:depth]))
                    if tech:
                        ctx.signal(tech.key, "import", rel, line_of(text, m.start()))
                        break
                if INTEGRATIONS.get(parts[0]):
                    ctx.signal(INTEGRATIONS[parts[0]], "import", rel, line_of(text, m.start()))
    elif kind in JS_KINDS:
        for m in _code_matches(JS_IMPORT, text, spans):
            spec = m.group(1)
            root = "/".join(spec.split("/")[:2]) if spec.startswith("@") else spec.split("/")[0]
            tech = IMPORT_INDEX.get(spec) or IMPORT_INDEX.get(root)
            if tech:
                ctx.signal(tech.key, "import", rel, line_of(text, m.start()))
            if INTEGRATIONS.get(root):
                ctx.signal(INTEGRATIONS[root], "import", rel, line_of(text, m.start()))
    elif kind == "go":
        for m in GO_IMPORT.finditer(text):
            if spans.in_comment(m.start()):
                continue
            tech = next((t for mod, t in GO_INDEX.items() if m.group(1) == mod or m.group(1).startswith(mod + "/")), None)
            if tech:
                ctx.signal(tech.key, "import", rel, line_of(text, m.start()))

    # Environment variables naming AI services (code references and config assignments)
    env_matches = ENV_ASSIGN.finditer(text) if kind == "config" else _code_matches(ENV_REF, text, spans)
    for m in env_matches:
        tech = ENV_INDEX.get(m.group(1))
        if tech and not spans.in_comment(m.start(1)):
            ctx.signal(tech.key, "config", rel, line_of(text, m.start()))

    # Endpoints: provider APIs and self-hosted inference servers (URLs live in strings, so only comments are skipped)
    for m in URL.finditer(text):
        if spans.in_comment(m.start()):
            continue
        url = m.group(0).rstrip(".;:'\"")
        split = _split(url)
        if split is None or not split.hostname or "{" in split.netloc or "$" in split.netloc:
            continue
        if is_reference_host(split.hostname) and not LOCAL_URL.match(url):
            continue
        host = split.netloc.lower()
        tech = next((t for t in TECHS for h in t.hosts
                     if (host.endswith(h) if h.startswith(":") else h in host if h.endswith(".") or h.startswith(".") else host == h or host.endswith("." + h))), None)
        line = line_of(text, m.start())
        if tech:
            ctx.signal(tech.key, "endpoint", rel, line)
        if INFERENCE_MARKERS.search(url) and not (tech and tech.category == "provider") and not in_tests:  # fixtures are not infrastructure
            ctx.endpoints.setdefault(f"{split.scheme}://{split.netloc}", Location(rel, line, "endpoint"))

    if kind == "config":
        return

    # Model references
    for m in _code_matches(MODEL_NAME, text, spans, keys=True):
        name = m.group(1)
        family = name.lower()
        key = ("openai" if family.startswith(("gpt-", "o1", "o3", "o4", "text-embedding-")) else "anthropic" if family.startswith("claude-")
               else "google_gemini" if family.startswith("gemini-") else "mistral" if family.startswith(("mistral-", "mixtral"))
               else "aws_bedrock" if family.startswith(("anthropic.", "amazon.", "meta.")) else "xai" if family.startswith("grok-") else None)
        ctx.models_referenced.setdefault(key or "unknown", set()).add(name[:120])
    for m in PREFIXED_MODEL.finditer(text):  # "anthropic:claude-haiku-4-5" names both provider and model
        if spans.in_comment(m.start()):
            continue
        provider = MODEL_PREFIXES[m.group(1)]
        ctx.models_referenced.setdefault(provider, set()).add(m.group(2)[:120])
        ctx.signal(provider, "code", rel, line_of(text, m.start()))
    for m in _code_matches(HF_MODEL_REF, text, spans):
        model_id = m.group(1)
        if (ctx.root / model_id).exists() or (ctx.root / rel).parent.joinpath(model_id).exists():
            continue  # a directory in this repository, not a model on the hub
        asset = ctx.inventory.add("ai_model", f"hf:{model_id}", f"{model_id} (Hugging Face)",
                                  attributes={"source": "huggingface", "model_id": model_id, "referenced_in": [rel]},
                                  ai={"provider": "huggingface", "managed": False}, location=Location(rel, line_of(text, m.start()), "code"))
        ctx.inventory.link(ctx.repo, asset, "DEPENDS_ON", via=rel)
        ctx.signal("huggingface", "import", rel, line_of(text, m.start()))

    # Risky flags
    def flag(rule, m, severity, domain, title, description, remediation, confidence="firm"):
        line = line_of(text, m.start())
        ctx.inventory.finding(Finding(rule_id=rule, title=f"{title} in {rel}", severity=severity, domain=domain, asset=ctx.repo.ref,
                                      description=description, remediation=remediation, file=rel, line=line, confidence=confidence,
                                      cwe="CWE-94" if "exec" in rule or "remote" in rule else "CWE-502" if "torch" in rule else "CWE-693",
                                      owasp_llm="LLM05:2025" if domain == "ai_llm" else "LLM06:2025" if domain == "ai_agent" else "LLM03:2025",
                                      discriminator=f"{rel}:{line}", evidence={"match": " ".join(m.group(0).split())[:200]}))

    for rule, pat, severity, domain, title, description, remediation in RISKY_FLAGS:
        for m in _code_matches(pat, text, spans):
            flag(rule, m, severity, domain, title, description, remediation)
    for m in _unsafe_torch_loads(text, spans):
        flag("ai.code.unsafe_torch_load", m, "medium", "ai_model", "torch.load without weights_only=True",
             "torch.load unpickles the file, so a crafted checkpoint executes code when loaded.", "Pass weights_only=True, or store weights as safetensors.")
    if len(ctx.signals) > signals_before:  # the file uses an AI SDK, so a value named "response" or "completion" is plausibly model output
        for m in _code_matches(EXEC_OUTPUT, text, spans):
            flag("ai.code.llm_output_exec", m, "high", "ai_llm", "Possible model output passed to exec/eval",
                 "A value that looks like model output is executed as code in a file that calls an AI SDK. If it is model output, a prompt "
                 "injection becomes code execution. Confirm where the value comes from.",
                 "Never execute model output directly; use a constrained interpreter in a sandbox with an allow-list.", confidence="tentative")

    # Agents and their tools
    agent_hits = [(fw, m) for fw, pat in AGENT_PATTERNS for m in [next(_code_matches(pat, text, spans), None)] if m]
    frameworks = list(dict.fromkeys(fw for fw, _m in agent_hits))
    tools = _python_tools(text, spans) if kind == "python" else _javascript_tools(text, spans) if kind in JS_KINDS else []
    for m in _code_matches(TOOL_CLASS, text, spans):
        if not any(t["name"] == m.group(1) for t in tools):
            tools.append({"name": m.group(1), "description": "built-in tool", "capabilities": TOOL_CLASS_CAPS[m.group(1)],
                          "line": line_of(text, m.start()), "poisoning": []})
    is_mcp_server = MCP_SERVER_IMPORT.search(text) is not None and next(_code_matches(MCP_SERVER_IMPL, text, spans), None) is not None
    registers_tools = not is_mcp_server and bool(tools) and next(_code_matches(MCP_TOOL_REGISTRATION, text, spans), None) is not None \
        and MCP_SERVER_IMPORT.search(text) is not None
    if frameworks and not in_tests:
        first = min((m for _fw, m in agent_hits), key=lambda m: m.start())
        named = AGENT_NAME.search(text, first.start(), first.start() + 800)
        roles = sorted({m.group(1).strip() for m in AGENT_ROLE.finditer(text)})[:30]
        ctx.agent_files[rel] = {"frameworks": frameworks, "tools": [] if is_mcp_server else tools,
                                "name": named.group(1) if named else (roles[0] if len(roles) == 1 else None), "roles": roles,
                                "approval": next(_code_matches(APPROVAL_MARKERS, text, spans), None) is not None,
                                "uses_mcp": next(_code_matches(MCP_CLIENT_IMPL, text, spans), None) is not None,
                                "line": line_of(text, first.start()), "identifiers": set(IDENT.findall(text)[:20000])}
    elif registers_tools and not in_tests:
        ctx.mcp_tool_files[rel] = tools  # a module that adds tools to an MCP server constructed elsewhere
    elif tools and not is_mcp_server and not in_tests:
        ctx.tool_files[rel] = tools  # tools defined here, used by an agent defined elsewhere
    if is_mcp_server and not in_tests:
        _mcp_server_impl(ctx, rel, text, tools)
    if not in_tests:
        _mcp_servers_in_code(ctx, rel, text, spans, kind)

    # Retrieval pipelines
    markers = sorted({m.group(1) for m in _code_matches(RAG_MARKERS, text, spans)})
    if markers and not in_tests:
        ctx.rag_markers[rel] = markers


def _definition_from_text(body: str) -> dict:
    """Fields of an MCP server entry that uses variables or unquoted keys, so it cannot be parsed as a literal."""
    def field(name: str) -> str | None:
        m = re.search(rf"""["']?{name}["']?\s*:\s*["'`]([^"'`]+)["'`]""", body)
        return m.group(1) if m else None

    definition: dict = {k: v for k in ("transport", "url", "command", "type") if (v := field(k))}
    args = re.search(r"""["']?args["']?\s*:\s*\[([^\]]*)\]""", body)
    if args:
        definition["args"] = re.findall(r"""["'`]([^"'`]*)["'`]""", args.group(1))
    if re.search(r"""["']?authorization["']?\s*:""", body, re.IGNORECASE):
        definition["headers"] = {"Authorization": "${redacted}"}
    return definition


def _mcp_servers_in_code(ctx: Context, rel: str, text: str, spans: Spans, kind: str) -> None:
    from aictem.detectors.mcp import analyse_definition

    for m in MCP_DICT_ENTRY.finditer(text):
        if spans.in_comment(m.start()):
            continue
        definition = None
        if kind == "python":
            try:
                definition = ast.literal_eval(m.group(2))
            except (ValueError, SyntaxError, MemoryError, RecursionError):
                definition = None  # uses variables or calls
        if not isinstance(definition, dict):
            definition = _definition_from_text(m.group(2))
        if not (definition.get("url") or definition.get("command")):
            continue
        name = m.group(1)
        facts, issues = analyse_definition(name, definition)
        identifier = facts["endpoint"] or f"stdio:{ctx.repo.identifier}:{name}"
        line = line_of(text, m.start())
        server = ctx.inventory.add("mcp_server", identifier, f"MCP server {name}",
                                   attributes={"declared_in": [rel], "transport": facts["transport"], "auth_type": facts["auth_type"],
                                               "command": facts["command"], "uses_tls": facts["uses_tls"]},
                                   ai={"provider": "mcp", "managed": False}, location=Location(rel, line, "code"))
        ctx.inventory.link(ctx.repo, server, "DEPENDS_ON", via=rel)
        for i in issues:
            ctx.inventory.finding(Finding(rule_id=i["rule"], title=i["title"], severity=i["severity"], domain="ai_mcp", asset=server.ref,
                                          description=i["description"], remediation=i["remediation"], confidence=i["confidence"], file=rel,
                                          line=line, discriminator=rel, evidence=i["evidence"],
                                          owasp_llm="LLM06:2025" if "privilege" in i["rule"] or "scope" in i["rule"] else "LLM03:2025"))


def _mcp_server_impl(ctx: Context, rel: str, text: str, tools: list[dict]) -> None:
    name = re.search(r"""\b(?:FastMCP|MCPServer|LowLevelServer|Server)\s*\(\s*(?:name\s*=\s*)?["']([^"']+)["']|"""
                     r"""\bnew\s+(?:Mcp)?Server\s*\(\s*\{\s*name\s*:\s*["'`]([^"'`]+)["'`]""", text)
    server_name = next((g for g in (name.groups() if name else ()) if g), None)
    if not server_name:  # index.ts / server.py: the package directory names the server
        parts = [p for p in rel.split("/")[:-1] if p not in ("src", "lib", "app", "dist")]
        stem = rel.rsplit("/", 1)[-1].rsplit(".", 1)[0]
        server_name = (parts[-1] if parts else stem) if stem in ("server", "index", "main", "__main__", "app", "mod") else stem
    transport = ("streamable_http" if re.search(r"streamable[-_]?http|StreamableHTTP", text, re.IGNORECASE) else "sse" if re.search(r"\bsse\b|SSEServerTransport", text)
                 else "stdio" if re.search(r"stdio", text, re.IGNORECASE) else "unknown")
    high = [t for t in tools if HIGH_IMPACT & set(t["capabilities"])]
    asset = ctx.inventory.add("mcp_server", f"local:{ctx.repo.identifier}:{rel}", f"MCP server {server_name} ({rel})",
                              attributes={"implemented_in": rel, "transport": transport,
                                          "tools": [{k: v for k, v in t.items() if k != "poisoning"} for t in tools][:100],
                                          "high_impact_tools": [t["name"] for t in high]},
                              ai={"provider": "mcp", "managed": True}, location=Location(rel, None, "code"))
    ctx.inventory.link(ctx.repo, asset, "CONTAINS", via=rel)
    for tool in tools:
        for hit in tool.get("poisoning") or []:
            ctx.inventory.finding(Finding(
                rule_id=f"ai.mcp.tool_poisoning.{hit['indicator']}", title=f"MCP tool '{tool['name']}' description contains instructions to the model",
                severity="high", domain="ai_mcp", asset=asset.ref, confidence="tentative", file=rel, line=tool.get("line"),
                description=f"{hit['meaning']}. Tool descriptions are read by the model, so text like this can steer it (tool poisoning).",
                remediation="Rewrite the description to describe only what the tool does.", owasp_llm="LLM01:2025", atlas_technique="AML.T0051",
                discriminator=tool["name"], evidence={"excerpt": hit["excerpt"]}))
