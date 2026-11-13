"""Regression tests from a review of the discovery detectors: each case was a wrong or missing result."""

import json

from aictem import scan
from aictem.detectors.mcp import analyse_definition
from aictem.gitinfo import info


def run(tmp_path, files: dict[str, str | bytes], **kw):
    root = tmp_path / "repo"
    for rel, content in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content) if isinstance(content, bytes) else path.write_text(content)
    return scan.run(root, **kw)


def assets(report, kind=None):
    return {a["identifier"]: a for a in report["assets"] if kind is None or a["type"] == kind}


def rules(report):
    return [f["rule_id"] for f in report["findings"]]


def provider(report, key):
    return next((a for a in report["assets"] if a["identifier"].startswith(f"{key}@")), None)


# --- Identity and privacy ------------------------------------------------------------------------------

def test_credentials_in_git_remote_are_not_reported(tmp_path):
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    # A config with a value-less key, which strict parsers reject, and a token in the remote URL.
    (root / ".git" / "config").write_text('[core]\n\tbare\n[remote "origin"]\n\turl = https://ci-user:ghp_SECRETTOKEN123@github.com/acme/app.git\n')
    assert info(root)["identifier"] == "github.com/acme/app"
    assert "SECRETTOKEN" not in json.dumps(scan.run(root))


# --- Providers and models ---------------------------------------------------------------------------------

def test_google_api_key_alone_is_not_gemini(tmp_path):
    # AIza keys are generic Google keys (Maps, Firebase web config), not evidence of Gemini.
    report = run(tmp_path, {"web/firebase.js": 'export const cfg = { apiKey: "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q" };\n',
                            ".env.example": "GOOGLE_API_KEY=\n"})
    assert not assets(report, "ai_application") and not assets(report, "rag_application")
    gemini = provider(report, "google_gemini")
    assert gemini is None or gemini["attributes"]["evidence"] == "weak"
    assert "ai.secret.google_api_key" not in rules(report)


def test_model_names_in_dict_literals(tmp_path):
    report = run(tmp_path, {"app.py": 'import openai\nresp = client.chat.completions.create(**{"model": "gpt-4o-mini", "messages": []})\n',
                            "web.ts": 'import Anthropic from "@anthropic-ai/sdk";\nconst body = { model: "claude-sonnet-4-5", max_tokens: 10 };\n'})
    assert "gpt-4o-mini" in provider(report, "openai")["attributes"]["models"]
    assert "claude-sonnet-4-5" in provider(report, "anthropic")["attributes"]["models"]


def test_host_port_is_not_a_model(tmp_path):
    report = run(tmp_path, {"app.py": 'import ollama\nHOST = "ollama:11434"\nmodel = "ollama:llama3.2"\n'})
    assert provider(report, "ollama")["attributes"]["models"] == ["llama3.2"]


def test_local_model_directory_is_not_a_hub_reference(tmp_path):
    report = run(tmp_path, {"train.py": 'from transformers import AutoModel\nm = AutoModel.from_pretrained("checkpoints/run1")\n'
                                        'n = AutoModel.from_pretrained("acme/real-model")\n',
                            "checkpoints/run1/config.json": "{}"})
    assert set(assets(report, "ai_model")) == {"hf:acme/real-model"}


def test_unrelated_hosts_are_scanned_for_endpoints(tmp_path):
    # "x.com" in the exclusion list must not swallow hosts that merely end in those letters.
    report = run(tmp_path, {"app.py": 'LLM = "https://llm.acme-box.com/v1/chat/completions"\n',
                            "tests/test_app.py": 'STUB = "https://stub.acme-box.com/v1/chat/completions"\n'})
    endpoints = assets(report, "llm_endpoint")
    assert "https://llm.acme-box.com" in endpoints
    assert "https://stub.acme-box.com" not in endpoints  # a fixture URL is not infrastructure


# --- Risky flags -------------------------------------------------------------------------------------------

def test_torch_load_with_nested_call_and_weights_only(tmp_path):
    report = run(tmp_path, {"a.py": 'import torch, os\nsafe = torch.load(os.path.join(d, "m.pt"), weights_only=True)\n'
                                    'unsafe = torch.load(os.path.join(d, "m.pt"))\n'})
    hits = [f for f in report["findings"] if f["rule_id"] == "ai.code.unsafe_torch_load"]
    assert [f["line"] for f in hits] == [3]


def test_exec_of_generic_names_needs_ai_context(tmp_path):
    plain = run(tmp_path / "a", {"calc.py": "result = input()\nprint(eval(result))\n"})
    assert "ai.code.llm_output_exec" not in rules(plain)
    ai = run(tmp_path / "b", {"bot.py": "import openai\nresponse = client.chat.completions.create()\nexec(response.choices[0].message.content)\n"})
    assert "ai.code.llm_output_exec" in rules(ai)


# --- Agents and tools ----------------------------------------------------------------------------------------

AGENT = '''from langchain.agents import create_agent
from langchain.tools import tool
from typing import Annotated
from pydantic import Field


@tool
def delete_customer(customer_id: Annotated[str, Field(description="The customer (id)")], force: bool = False) -> str:
    """Delete a customer record."""


agent = create_agent(model="openai:gpt-4o", tools=[delete_customer])
graph = create_agent(model="openai:gpt-4o", tools=[])
'''


def test_tool_docstring_after_complex_signature(tmp_path):
    report = run(tmp_path, {"agent.py": AGENT})
    agent = next(iter(assets(report, "ai_agent").values()))
    assert agent["attributes"]["frameworks"] == ["langchain"]  # no duplicates
    tool = agent["attributes"]["tools"][0]
    assert tool["name"] == "delete_customer" and tool["description"] == "Delete a customer record." and "delete" in tool["capabilities"]


def test_tool_decorator_separated_from_def_by_comments(tmp_path):
    report = run(tmp_path, {"server.py": '''from mcp.server.fastmcp import FastMCP

server = FastMCP("files")


@server.tool(
    name="fetch",
    description=FETCH_DESCRIPTION,
    annotations=ToolAnnotations(read_only_hint=True),
)
# strict=True: pydantic would otherwise coerce arguments
async def fetch(url: Annotated[AnyUrl, Field(description="URL to fetch")]) -> str:
    """Fetch a URL and return its text."""
'''})
    server = next(iter(assets(report, "mcp_server").values()))
    assert [t["name"] for t in server["attributes"]["tools"]] == ["fetch"]


def test_python_tool_names_are_not_read_with_javascript_patterns(tmp_path):
    report = run(tmp_path, {"crew.py": 'from crewai import Agent\nfrom crewai.tools import tool\n\n@tool("lookup_order")\ndef find(order: str) -> str:\n'
                                       '    """Find an order."""\n\nsupport = Agent(role="Support", goal="help", tools=[find])\n'})
    agent = next(iter(assets(report, "ai_agent").values()))
    assert [t["name"] for t in agent["attributes"]["tools"]] == ["find"]


def test_vercel_ai_sdk_tools(tmp_path):
    report = run(tmp_path, {"route.ts": '''import { generateText, tool } from "ai";
import { openai } from "@ai-sdk/openai";
const result = await generateText({
  model: openai("gpt-4o"),
  tools: {
    refundOrder: tool({ description: "Refund an order payment", inputSchema: z.object({}) , execute: async () => "ok" }),
    getWeather: tool({ description: "Get the weather", inputSchema: z.object({}), execute: async () => "sunny" }),
  },
});
'''})
    agent = next(iter(assets(report, "ai_agent").values()))
    tools = {t["name"]: t for t in agent["attributes"]["tools"]}
    assert set(tools) == {"refundOrder", "getWeather"} and "payment" in tools["refundOrder"]["capabilities"]
    assert provider(report, "openai") is not None


def test_embeddings_and_llamaindex_agents(tmp_path):
    report = run(tmp_path, {"rag.py": "from langchain_openai import OpenAIEmbeddings\nimport chromadb\nemb = OpenAIEmbeddings()\n",
                            "requirements.txt": "chromadb==0.5.0\nlangchain-openai==0.2.0\nllama-index==0.11.0\n",
                            "agent.py": "from llama_index.core.agent.workflow import FunctionAgent\nagent = FunctionAgent(tools=[], llm=llm)\n"})
    assert assets(report, "rag_application")
    assert next(iter(assets(report, "ai_agent").values()))["attributes"]["frameworks"] == ["llamaindex"]


# --- MCP ---------------------------------------------------------------------------------------------------------

def test_mcp_definitions_with_odd_shapes_do_not_crash(tmp_path):
    report = run(tmp_path, {".mcp.json": json.dumps({"mcp": "not-a-dict", "mcpServers": {
        "a": {"command": "npx", "args": "not-a-list", "env": ["x"], "headers": 5}, "b": "nope"}})})
    assert len(assets(report, "mcp_server")) == 1


def test_docker_and_path_values_in_mcp_definitions():
    _facts, issues = analyse_definition("gh", {"command": "docker", "args": ["run", "-i", "--rm", "-e", "GITHUB_TOKEN", "ghcr.io/github/github-mcp-server:v1.2.0"],
                                               "env": {"GITHUB_TOKEN": "${GH_TOKEN}", "SSL_KEY_FILE": "/run/secrets/server-key.pem"}})
    assert [i["rule"] for i in issues] == []  # pinned image; "-e NAME" is not the package; a path is not a credential
    _facts, issues = analyse_definition("gh", {"command": "docker", "args": ["run", "-e", "X", "ghcr.io/github/github-mcp-server"]})
    assert [i["rule"] for i in issues] == ["mcp.config.unpinned_server"] and "ghcr.io/github/github-mcp-server" in issues[0]["title"]


def test_mcp_servers_in_editor_settings_and_javascript(tmp_path):
    report = run(tmp_path, {
        ".vscode/settings.json": '{\n  // editor settings\n  "mcp": {"servers": {"docs": {"url": "https://docs.acme.dev/mcp"}}},\n}\n',
        ".codex/config.toml": '[mcp_servers.search]\ncommand = "npx"\nargs = ["-y", "search-mcp"]\n',
        "client.ts": 'const client = new MultiServerMCPClient({ mcpServers: {\n  billing: { transport: "http", url: "http://billing.internal/mcp" },\n} });\n',
        "client.py": 'servers = {"files": {"transport": "stdio", "command": "uvx", "args": ["files-mcp"], "env": env}}\n'})
    servers = assets(report, "mcp_server")
    assert {"https://docs.acme.dev/mcp", "http://billing.internal/mcp"} <= set(servers), set(servers)
    assert any(s.endswith(":search") for s in servers) and any(s.endswith(":files") for s in servers)
    assert "mcp.config.insecure_transport" in rules(report)


# --- Dependencies ---------------------------------------------------------------------------------------------------

def test_lockfile_edge_cases(tmp_path):
    report = run(tmp_path, {
        "yarn.lock": '__metadata:\n  version: 8\n\n"left-pad@npm:^1.3.0":\n  version: 1.3.0\n\n"myapp@workspace:.":\n  version: 0.0.0-use.local\n',
        "Cargo.lock": '[[package]]\nname = "myapp"\nversion = "0.1.0"\n\n[[package]]\nname = "serde"\nversion = "1.0.200"\n'
                      'source = "registry+https://github.com/rust-lang/crates.io-index"\n',
        "svc-a/requirements.txt": "requests==2.19.0\n", "svc-b/requirements.txt": "requests==2.32.3\n"})
    packages = set(assets(report, "package"))
    assert "pkg:npm/left-pad@1.3.0" in packages and "pkg:cargo/serde@1.0.200" in packages
    assert not any("__metadata" in p or "myapp" in p for p in packages), packages
    assert {"pkg:pypi/requests@2.19.0", "pkg:pypi/requests@2.32.3"} <= packages  # both versions in a monorepo


# --- Infrastructure ------------------------------------------------------------------------------------------------

def test_terraform_types_match_exactly_and_modules_do_not_collide(tmp_path):
    tf = ('resource "aws_s3_bucket" "docs" {}\nresource "aws_s3_bucket_versioning" "docs" {}\nresource "aws_iam_role_policy_attachment" "x" {}\n'
          'resource "aws_lb_listener" "http" {}\nresource "aws_s3_bucket_acl" "docs" {\n  acl = "public-read"\n}\n')
    report = run(tmp_path, {"envs/dev/main.tf": tf, "envs/prod/main.tf": 'resource "aws_s3_bucket" "docs" {}\n'})
    assert len(assets(report, "storage")) == 2 and not assets(report, "identity") and not assets(report, "load_balancer")
    assert "iac.storage.public_acl" in rules(report)


def test_container_checks(tmp_path):
    report = run(tmp_path, {"Dockerfile": "FROM golang:1.22 AS build\nRUN go build\nFROM gcr.io/distroless/static:nonroot\nCOPY --from=build /app /app\n"})
    assert "container.runs_as_root" not in rules(report)


def test_workflow_script_injection(tmp_path):
    report = run(tmp_path, {".github/workflows/ci.yml": "on: issues\njobs:\n  t:\n    steps:\n      - run: echo \"${{ github.event.issue.title }}\"\n"
                                                        "      - env:\n          TITLE: ${{ github.event.issue.title }}\n        run: echo \"$TITLE\"\n"})
    hits = [f for f in report["findings"] if f["rule_id"] == "ci.actions.script_injection"]
    assert [f["line"] for f in hits] == [5]


# --- Models and secrets ------------------------------------------------------------------------------------------------

def test_non_model_binary_files(tmp_path):
    report = run(tmp_path, {"proto/service.pb": b"\x0a" * 200, "data/array.npy": b"\x93NUMPY" + b"\x00" * 200, "fw/blob.bin": b"\x00" * 4096})
    assert not assets(report, "ai_model")


def test_untracked_secret_is_not_called_committed(tmp_path):
    import subprocess

    root = tmp_path / "repo"
    root.mkdir()
    (root / ".gitignore").write_text(".env\n")
    (root / ".env").write_text("OPENAI_API_KEY=sk-proj-" + "A1b2C3d4" * 6 + "\n")
    (root / "config.py").write_text('KEY = "sk-proj-' + "Z9y8X7w6" * 6 + '"\n')
    for cmd in (["init", "-q"], ["add", ".gitignore", "config.py"]):
        subprocess.run(["git", "-C", str(root), *cmd], check=True)
    found = {f["file"]: f for f in scan.run(root)["findings"] if f["rule_id"] == "ai.secret.openai_project_key"}
    assert "committed" in found["config.py"]["title"] and found["config.py"]["severity"] == "critical"
    assert "committed" not in found[".env"]["title"] and found[".env"]["severity"] == "low"


def test_one_unreadable_or_odd_file_does_not_stop_the_scan(tmp_path):
    report = run(tmp_path, {"package.json": '["not", "an", "object"]', "pyproject.toml": "[project\nbroken", "nb.ipynb": '{"cells": [{"cell_type": "code"}]}',
                            "models/x.pkl": b"\x80\x04 definitely not a full pickle" + b"\x00" * 40, "ok.py": "import anthropic\n"})
    assert provider(report, "anthropic") is not None and report["summary"].get("errors", 0) == 0
