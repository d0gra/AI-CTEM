# AI security

AI systems are assets. An agent, an MCP server, a model file and a vector store sit in the same inventory as hosts and buckets, take part in the same relationships, and their findings go through the same risk, remediation and reporting paths. AI-specific attributes live in extension tables (`ai_assets`, `ai_agents`, `mcp_servers`, `ai_models`).

Taxonomies: OWASP Top 10 for LLM Applications (2025) is the primary classification on findings; MITRE ATLAS technique ids and NIST AI RMF subcategories are recorded where they apply.

## Discovery

`repository_analysis` reads a local checkout (never executes it) and records:

| Signal | How | Result |
| --- | --- | --- |
| Dependencies | `requirements*.txt`, `pyproject.toml`, `uv.lock`, `poetry.lock`, `package.json`, `package-lock.json` | AI technology asset per repository; pinned packages checked against OSV |
| Imports | Python and JS/TS import statements | Detection record with file path |
| Endpoints | Provider hostnames and well-known ports in source and config | Detection record |
| Configuration | Provider environment variable names | Detection record |
| Credentials | Provider key formats (Anthropic, OpenAI, Hugging Face, Google, NVIDIA, Pinecone, Replicate, Groq) | Critical finding; only the public prefix and location are stored; placeholders are ignored |
| MCP configuration | `.mcp.json`, `mcp.json`, `claude_desktop_config.json`, editor MCP files | MCP server assets and configuration findings |
| Model artifacts | 16 file extensions | Model assets with digest and format; serialization findings |

26 technologies are recognised (`backend/app/engines/ai/signatures.py`). `ai_endpoint_probe` finds unauthenticated OpenAI-compatible and Ollama endpoints by requesting model listings only. `nmap_scan` flags common AI service ports (Ollama, Jupyter, Qdrant, Milvus). `http_exposure` recognises Jupyter, MLflow, Open WebUI and Gradio consoles.

Cloud AI services (Bedrock, Vertex AI, Azure AI Foundry) are detected only through repository signals; there is no cloud-side AI inventory.

## Shadow AI

An organization maintains an approved-provider list (AI Security → Governance). Detected providers outside the list are marked unapproved and produce a finding; with no list, status stays *unknown*. Unowned AI assets and unapproved assets processing sensitive data are flagged by the posture review. The platform states its visibility limit in the UI: it sees analysed repositories, probed endpoints and registered assets, and nothing about employees' use of AI tools elsewhere.

## MCP

Static checks on client configuration: plaintext remote transport, no client authentication configured (tentative, confirm with the probe), literal credentials in `env`/`headers`/`args`, unpinned `npx`/`uvx`/`docker run` packages, elevated launch privileges, filesystem servers rooted at `/` or a home directory, auto-approved tools.

Live probe: `initialize` without credentials. A `401/403` records the server as authenticated. A successful handshake is a confirmed finding, after which tools, resources and prompts are *listed*. Tool metadata is checked for poisoning indicators (instruction override, concealment from the user, directive blocks, credential file paths, cross-tool instructions, exfiltration phrasing, invisible characters, oversized text). Indicators are reported with the matched excerpt for an analyst to judge. Capabilities (shell, code execution, filesystem write, payment, and others) are classified from tool names and descriptions and feed the agent least-privilege rules.

## Models

Pickle-based formats are disassembled with `pickletools` and never loaded. If the stream references callables from modules such as `os`, `subprocess`, `builtins.eval` or `socket`, the finding says that loading the file executes code, lists the references, and states that this does not establish intent. Pickle formats without such references still get a medium finding for the format itself. Provenance is unknown until a user records how it was verified; policies treat unknown as non-compliant. Backdoor and poisoning detection in model weights is not attempted.

## Posture review

`ai_posture_review` evaluates declared attributes: high-impact tools callable without approval; autonomous operation without oversight; untrusted input combined with unapproved high-impact tools (the precondition for injection-to-action); persistent memory fed by untrusted input; missing or privileged agent identity; unrestricted delegation; retrieval without document-level authorization; untrusted ingestion without provenance; missing tenant isolation; unauthenticated or unlimited endpoints. Findings have confidence *firm* and say they are based on declared configuration, not observed behaviour.

## Red team

Targets are LLM endpoint integrations. Two modes:

- **Harness** (model APIs): the platform supplies a system prompt containing a policy and a synthetic canary, so leakage and override are measurable.
- **Deployed** (custom HTTP applications): the application's own prompt is in effect. Tests that need a known secret run only when the operator supplies *forbidden markers* (canaries planted in a restricted document or another tenant).

| Profile | Tests |
| --- | --- |
| Prompt injection | PI-001 direct override, PI-002 claimed authority, PI-003 forged delimiters |
| Indirect prompt injection | IPI-001 document content, IPI-002 hidden markup |
| System prompt confidentiality | SPC-001 verbatim, SPC-002 transformed |
| Data leakage | DL-001 protected context data |
| Insecure output | IOH-001 active content, IOH-002 exfiltrating Markdown image |
| Agent tool authorization | AG-001 destructive call from untrusted content, AG-002 missing confirmation |
| RAG / multi-tenant | RAG-001, MT-001 (need planted canaries) |
| Resource consumption | RC-001 unbounded output |

Every result records test id, threat category, objective, preconditions, scope, procedure, execution status, observed behaviour, evidence (the exchanges), confidence, severity, reproducibility (n of m attempts), remediation and, on re-runs, a retest result.

Safety envelope, enforced in `engines/ai_redteam/runner.py`:

1. Written authorization with expiry (≤ 30 days), recorded in the audit log; runs are refused after expiry.
2. The target endpoint must be in authorized scope with active testing; checked at creation and at every run.
3. Hard request budget and per-minute rate limit.
4. Tool definitions come from the assessment; tool calls requested by the target are recorded and never executed.
5. Payloads only ask the target to echo a random token; leak tests use synthetic canaries.
6. Dry run lists what would be sent; cancellation is honoured between requests.
7. A run that could not execute every test does not close findings implicitly.

Limits: single-turn only; no multimodal input; no adaptive or optimisation-based attacks; detection of leakage covers plain, spaced, reversed and base64 forms only.

## AI attack paths

Relationship types `RETRIEVES_FROM`, `INVOKES_TOOL` and `PROCESSES_DATA` connect AI assets to data sources, tools and data. A data source exposed to the internet is an entry point; retrieval edges are traversable in reverse as indirect prompt injection (`AML.T0051.001`) and tool edges forward (`AML.T0053`). Requiring human approval for an agent's high-impact tools downgrades its tool-use steps to theoretical.

## AI-assisted analysis

Optional, off by default, enabled by an organization administrator. See the design constraints at the top of `backend/app/domains/analytics/service.py`: advisory only, grounded in platform records, schema-validated output, untrusted-input handling, evidence shared only with explicit authorization, credential redaction, monthly token budget and usage accounting. For Claude models the request uses the official SDK with server-side refusal fallback enabled.
