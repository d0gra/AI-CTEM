# aictem: repository and AI asset discovery

`aictem` inventories a repository from the inside and reports what it finds as assets, relationships and findings. It covers dependencies, container images, cloud resources, CI pipelines, committed secrets, and AI systems (model providers, frameworks, agents and their tools, RAG pipelines, vector stores, MCP servers and clients, and model files).

- **Works offline, anywhere.** The standard library is the only dependency, so it runs in any CI image with Python 3.11 or later.
- **Safe by design.** Model files are disassembled, never loaded. Secret values are never stored or printed; findings carry a prefix, the length and a fingerprint.
- **Accurate.** Agent, tool, import and risky-flag patterns only count when they appear in real code, not in strings or comments. AI usage seen only in tests is labelled as such.
- **Connects to the platform.** `--upload` sends the inventory to [CTEM Platform](https://github.com/d0gra/AI-CTEM) with an upload-only pipeline token. Results merge with the platform's own analysis, because identifiers and rule names match.

## Install

```bash
pipx install aictem        # or: uv tool install aictem
pip install aictem         # into the current environment
uvx aictem discover .      # or run it without installing
```

From a checkout of this repository: `pipx install ./cli`.

## Use

```bash
aictem discover                               # scan the current directory; terminal summary
aictem discover ~/code/app --all              # list every asset and finding
aictem discover . -f json -o inventory.json   # full report (also the upload format)
aictem discover . -f sarif -o aictem.sarif      # for GitHub code scanning and other SARIF dashboards
aictem discover . --approved-providers openai,anthropic   # other providers are reported as shadow AI
aictem discover . --vulns                     # look up known vulnerabilities in pinned packages (osv.dev)
aictem discover . --fail-on high              # exit 1 if a high or critical finding is present
```

Send the inventory to the platform. Create a token under **Integrations → CI/CD pipelines**:

```bash
export CTEM_URL=https://ctem.example.com CTEM_CI_TOKEN=ctem_ci_...
aictem discover . --upload --gate high        # exit 3 if the platform's gate fails
```

Inside GitHub Actions, GitLab CI, Jenkins, Azure Pipelines, CircleCI or Bitbucket, the upload records the provider and the pipeline URL automatically, together with the repository, branch and commit from git.

## What it finds

| Area | Sources | Assets | Findings (examples) |
| --- | --- | --- | --- |
| Dependencies | requirements, pyproject, Pipfile, poetry/uv locks, package.json, npm/pnpm/yarn locks, go.mod, Cargo, Gemfile.lock, composer, pom.xml, Gradle, .csproj | `package` (purl), `repository` | Known vulnerabilities with `--vulns`, or by the platform on upload |
| AI providers and serving | Imports, dependencies, endpoint URLs, environment variables, containers, IaC | `ai_provider`, `llm_endpoint` | Unapproved provider (shadow AI) |
| AI frameworks and agents | LangChain/LangGraph, LlamaIndex, Haystack, CrewAI, AutoGen, OpenAI Agents SDK, Pydantic AI, smolagents, Semantic Kernel, Google ADK, Strands, Vercel AI SDK, Mastra, function-calling tool schemas | `ai_framework`, `ai_agent` (with tools and capabilities) | High-impact tools without an approval step, disabled LangChain safety flags, model output passed to exec/eval |
| Retrieval | Vector store clients plus retrievers, loaders, splitters and embeddings | `rag_application`, `vector_database` | |
| MCP | Client configs (Claude Desktop, Cursor, VS Code, Windsurf, Claude Code and more) and servers implemented in the repository | `mcp_client`, `mcp_server` | Plaintext transport, literal credentials, unpinned packages, broad filesystem roots, privileged launch, auto-approved tools, tool-description poisoning |
| Models | Pickle, PyTorch, safetensors, ONNX, GGUF, Keras and more; Hugging Face model references | `ai_model` | Code-execution callables in pickle streams, unsafe formats, `trust_remote_code=True`, `torch.load` without `weights_only` |
| Containers | Dockerfile, Compose, Kubernetes manifests | `container_image`, `k8s_resource` | Root user, unpinned base image, privileged containers |
| Cloud (IaC) | Terraform, CloudFormation, including SageMaker, Bedrock, Vertex AI and Azure OpenAI | `storage`, `database`, `identity`, `llm_endpoint`, ... | Public buckets, publicly accessible databases |
| CI/CD | GitHub Actions and other pipeline files | (attributes) | Unpinned third-party actions, pull_request_target running PR code, write-all tokens |
| Secrets | AI provider keys, cloud and SaaS tokens, private keys | | Committed credential (value never stored) |

Exclude paths with `--exclude GLOB` or a `.aictemignore` file (one glob per line). Dependency folders such as `node_modules`, `.venv`, `dist` and `build` are always skipped.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success |
| 1 | `--fail-on` threshold reached |
| 2 | Usage or upload error |
| 3 | Upload succeeded, but the platform's `--gate` failed |

## Development

```bash
cd cli && uv run --with pytest pytest
```

MIT licensed.

## Releasing

Versions follow the project's `CHANGELOG.md`. A release is a tag: GitHub Actions runs the tests on
Python 3.11-3.13, builds the sdist and wheel, installs the built wheel and runs it, then publishes to
PyPI and opens a GitHub release.

```bash
# 1. set the new version in cli/pyproject.toml and note the changes in CHANGELOG.md, then commit
# 2. tag it; the tag must match the version, or the workflow stops before publishing
git tag cli-v0.2.0 && git push origin cli-v0.2.0
```

`workflow_dispatch` runs the same workflow without publishing, for checking a release before tagging.

### One-time PyPI setup

Publishing uses [trusted publishing](https://docs.pypi.org/trusted-publishers/), so no API token is
stored in the repository: GitHub proves the workflow's identity over OpenID Connect and PyPI issues a
short-lived token for that one upload. Before the first release, add the publisher on PyPI
(**Your projects -> aictem -> Publishing**, or **Publishing** under your account for a project that does
not exist yet):

| Field | Value |
| --- | --- |
| Owner | `d0gra` |
| Repository name | `AI-CTEM` |
| Workflow name | `release-cli.yml` |
| Environment name | `pypi` |

The environment is created by the first run, so nothing is needed on the GitHub side. To require an
approval before each upload, add a protection rule to that environment in the repository settings.
