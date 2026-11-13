import json

from conftest import FAKE_OPENAI_KEY

from aictem import output, scan
from aictem.__main__ import main
from aictem.detectors.deps import purl
from aictem.gitinfo import normalise_remote

REPO = "github.com/acme/support-bot"


def by_ref(report):
    return {a["ref"]: a for a in report["assets"]}


def rules(report):
    return {f["rule_id"] for f in report["findings"]}


def test_repository_identity_and_packages(repo):
    report = scan.run(repo)
    assets = by_ref(report)
    assert report["target"] == {**report["target"], "repository": REPO, "branch": "main"}
    assert f"repository:{REPO}" in assets
    assert "package:pkg:pypi/openai@1.40.0" in assets and "package:pkg:npm/%40anthropic-ai/sdk@0.20.0" in assets
    assert assets["package:pkg:pypi/flask"]["attributes"]["constraint"] == ">=2"  # range: recorded without a version
    assert assets["package:pkg:npm/vitest@1.0.0"]["attributes"]["dev_only"] is True
    assert not any("mistral" in r for r in assets)  # node_modules is skipped


def test_ai_inventory(repo):
    report = scan.run(repo)
    assets = by_ref(report)
    types = {a["type"] for a in report["assets"]}
    assert {"ai_provider", "ai_framework", "vector_database", "rag_application", "ai_agent", "mcp_server", "mcp_client", "ai_model",
            "llm_endpoint"} <= types
    openai = assets[f"ai_provider:openai@{REPO}"]
    assert set(openai["attributes"]["methods"]) >= {"dependency", "config"} and "gpt-4o" in openai["attributes"]["models"]
    assert f"ai_provider:anthropic@{REPO}" in assets and f"vector_database:qdrant@{REPO}" in assets
    app = assets[f"rag_application:app@{REPO}"]  # vector store + retriever => RAG application
    assert "chroma" in app["attributes"]["vector_stores"]
    agent = assets[f"ai_agent:agent:{REPO}:src/agent.py"]
    tools = {t["name"]: t for t in agent["attributes"]["tools"]}
    assert "payment" in tools["refund_order"]["capabilities"] and agent["attributes"]["approval_step_detected"] is False
    assert "llm_endpoint:http://gpu-box.internal:11434" in assets
    assert "ai_model:hf:acme/support-7b" in assets
    assert assets[f"mcp_server:local:{REPO}:src/server.py"]["attributes"]["high_impact_tools"] == ["delete_invoice"]
    assert f"mcp_server:stdio:{REPO}:files" in assets and "mcp_server:http://crm-mcp.acme.test/mcp" in assets
    rels = {(r["source"], r["type"], r["target"]) for r in report["relationships"]}
    assert (app["ref"], "RETRIEVES_FROM", f"vector_database:chroma@{REPO}") in rels
    assert (f"mcp_client:mcp-client:{REPO}:.mcp.json", "CONNECTS_TO", f"mcp_server:stdio:{REPO}:files") in rels


def test_code_in_strings_and_comments_is_not_counted(repo):
    report = scan.run(repo)
    assert f"ai_agent:agent:{REPO}:src/notes.py" not in by_ref(report)
    assert not any(f.get("file") == "src/notes.py" for f in report["findings"])
    anthropic = by_ref(report)[f"ai_provider:anthropic@{REPO}"]
    assert all(loc["file"] != "src/notes.py" for loc in anthropic["locations"])


def test_findings(repo):
    report = scan.run(repo, approved_providers={"anthropic"})
    found = rules(report)
    assert {
        "ai.secret.openai_project_key", "mcp.config.broad_filesystem_scope", "mcp.config.insecure_transport", "mcp.config.plaintext_secret",
        "mcp.config.unpinned_server", "ai.model.pickle_code_execution", "ai.code.trust_remote_code", "ai.agent.high_impact_tools_without_approval",
        "ai.shadow.unapproved_provider", "container.runs_as_root", "container.image.unpinned", "container.privileged", "iac.storage.public_acl",
        "ci.actions.pwn_request", "ci.actions.unpinned",
    } <= found, found
    assert any(r.startswith("ai.mcp.tool_poisoning.") for r in found)
    assert "mcp.config.unpinned_server" not in {f["rule_id"] for f in report["findings"] if "pinned" in f["asset"]}
    assert not any("PINECONE" in json.dumps(f) for f in report["findings"])  # placeholder value, not a secret
    assert not any(f["rule_id"] == "ci.actions.unpinned" and "actions/checkout" in f["title"] for f in report["findings"])


def test_secret_values_never_appear_in_any_output(repo):
    report = scan.run(repo)
    secret = next(f for f in report["findings"] if f["rule_id"] == "ai.secret.openai_project_key")
    assert secret["evidence"]["prefix"] == "sk-proj-" and len(secret["evidence"]["fingerprint"]) == 16
    for rendered in (output.to_json(report), output.to_sarif(report)):
        assert FAKE_OPENAI_KEY not in rendered and "tok_live_9f8e7d6c5b4a39281706" not in rendered


def test_sarif_and_exit_codes(repo, tmp_path, capsys):
    out = tmp_path / "r.sarif"
    assert main(["discover", str(repo), "-f", "sarif", "-o", str(out)]) == 0
    sarif = json.loads(out.read_text())
    assert sarif["version"] == "2.1.0" and sarif["runs"][0]["results"]
    assert main(["discover", str(repo), "-f", "json", "-o", str(tmp_path / "r.json"), "--fail-on", "high"]) == 1
    assert json.loads((tmp_path / "r.json").read_text())["schema"] == "aictem-inventory/1"
    assert main(["discover", str(repo), "--no-secrets", "--exclude", ".env", "--fail-on", "critical", "-f", "json", "-o", str(tmp_path / "x.json")]) == 0
    assert main(["discover", str(repo)]) == 0 and "AI inventory" in capsys.readouterr().out


def test_helpers():
    assert normalise_remote("git@github.com:acme/shop.git") == "github.com/acme/shop"
    assert normalise_remote("https://token@gitlab.example.com:8443/group/sub/repo.git") == "gitlab.example.com/group/sub/repo"
    assert purl("npm", "@scope/pkg", "1.0.0") == "pkg:npm/%40scope/pkg@1.0.0" and purl("Maven", "org.x:y", "2") == "pkg:maven/org.x/y@2"


def test_patterns_from_real_repositories(tmp_path):
    """Constructs seen in public AI repositories (LangChain Deep Agents, MCP servers, CrewAI)."""
    root = tmp_path / "app"
    (root / "tools").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "scripts").mkdir()
    (root / "agent.py").write_text(
        "from managed_deepagents import define_deep_agent\nfrom tools.billing import refund_payment, lookup_rates\n"
        "agent = define_deep_agent(name='support_agent', tools=[refund_payment, lookup_rates], model='anthropic:claude-haiku-4-5')\n")
    (root / "tools" / "billing.py").write_text(
        "from langchain.tools import tool\n\n@tool\ndef refund_payment(order: str) -> str:\n    \"\"\"Refund a payment to the customer.\"\"\"\n\n"
        "@tool\ndef lookup_rates() -> str:\n    \"\"\"Look up plan prices. Covers pay-as-you-go rates and billing settings.\"\"\"\n")
    (root / "mcp_setup.py").write_text("servers = {\n    'docs': {'transport': 'http', 'url': 'http://docs.internal/mcp', 'timeout': 10},\n}\n")
    (root / "uv.lock").write_text('[[package]]\nname = "chromadb"\nversion = "0.5.0"\n')
    (root / "tests" / "test_client.py").write_text("import mistralai\n")
    (root / "scripts" / "release.mjs").write_text("const m = new RegExp('x').exec(text);\n")
    report = scan.run(root)
    assets = by_ref(report)
    agent = next(a for a in report["assets"] if a["type"] == "ai_agent")
    assert agent["name"].startswith("Agent support_agent") and agent["attributes"]["frameworks"] == ["deepagents"]
    tools = {t["name"]: t for t in agent["attributes"]["tools"]}
    assert set(tools) == {"refund_payment", "lookup_rates"} and tools["refund_payment"]["defined_in"] == "tools/billing.py"
    assert "payment" in tools["refund_payment"]["capabilities"] and tools["lookup_rates"]["capabilities"] == []  # "pay-as-you-go" is context
    assert not any(a["type"] == "ai_agent" and "billing" in a["identifier"] for a in report["assets"])  # tool module, not an agent
    repo_id = report["target"]["repository"]
    assert "claude-haiku-4-5" in assets[f"ai_provider:anthropic@{repo_id}"]["attributes"]["models"]
    assert "mcp_server:http://docs.internal/mcp" in assets
    assert assets[f"vector_database:chroma@{repo_id}"]["attributes"]["evidence"] == "transitive"
    assert assets[f"ai_provider:mistral@{repo_id}"]["attributes"]["evidence"] == "tests_only"
    assert not any(f["rule_id"] == "ai.code.llm_output_exec" for f in report["findings"])
