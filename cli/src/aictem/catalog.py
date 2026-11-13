"""What the detectors look for. Keys match the CTEM platform's AI signatures so uploads merge."""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Tech:
    key: str
    name: str
    category: str  # provider | framework | vector_db | serving | mcp | registry
    pypi: tuple[str, ...] = ()
    npm: tuple[str, ...] = ()
    imports: tuple[str, ...] = ()  # Python module roots and JS/TS package specifiers
    hosts: tuple[str, ...] = ()  # substrings of API hostnames or ports
    env: tuple[str, ...] = ()
    go: tuple[str, ...] = ()  # Go module paths
    images: tuple[str, ...] = ()  # container image name prefixes
    agentic: bool = False
    rag: bool = False


T = Tech
TECHS: tuple[Tech, ...] = (
    # Hosted model providers
    T("openai", "OpenAI", "provider", ("openai",), ("openai",), ("openai",), ("api.openai.com",), ("OPENAI_API_KEY", "OPENAI_BASE_URL"),
      ("github.com/openai/openai-go", "github.com/sashabaranov/go-openai")),
    T("anthropic", "Anthropic", "provider", ("anthropic",), ("@anthropic-ai/sdk",), ("anthropic", "@anthropic-ai/sdk"), ("api.anthropic.com",),
      ("ANTHROPIC_API_KEY",), ("github.com/anthropics/anthropic-sdk-go",)),
    T("google_gemini", "Google Gemini", "provider", ("google-generativeai", "google-genai"), ("@google/generative-ai", "@google/genai"),
      ("google.generativeai", "google.genai", "@google/generative-ai", "@google/genai"), ("generativelanguage.googleapis.com",),
      ("GEMINI_API_KEY", "GOOGLE_GENAI_API_KEY", "GOOGLE_GENERATIVE_AI_API_KEY"), ("google.golang.org/genai", "github.com/google/generative-ai-go")),
    T("vertex_ai", "Google Vertex AI", "provider", ("google-cloud-aiplatform", "vertexai"), ("@google-cloud/vertexai",),
      ("vertexai", "google.cloud.aiplatform", "@google-cloud/vertexai"), ("aiplatform.googleapis.com",)),
    T("aws_bedrock", "AWS Bedrock", "provider", ("langchain-aws",), ("@aws-sdk/client-bedrock-runtime", "@aws-sdk/client-bedrock-agent-runtime"),
      ("@aws-sdk/client-bedrock-runtime", "@aws-sdk/client-bedrock-agent-runtime"), ("bedrock-runtime.", "bedrock-agent-runtime."),
      ("AWS_BEDROCK_MODEL_ID", "BEDROCK_MODEL_ID")),
    T("azure_openai", "Azure OpenAI / AI Foundry", "provider", ("azure-ai-inference", "azure-ai-projects", "azure-ai-agents"),
      ("@azure/openai", "@azure-rest/ai-inference"), ("azure.ai.inference", "azure.ai.projects", "azure.ai.agents", "@azure/openai"),
      (".openai.azure.com", ".services.ai.azure.com", ".inference.ai.azure.com"), ("AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT")),
    T("cohere", "Cohere", "provider", ("cohere",), ("cohere-ai",), ("cohere", "cohere-ai"), ("api.cohere.com", "api.cohere.ai"), ("COHERE_API_KEY", "CO_API_KEY")),
    T("mistral", "Mistral AI", "provider", ("mistralai",), ("@mistralai/mistralai",), ("mistralai", "@mistralai/mistralai"), ("api.mistral.ai",), ("MISTRAL_API_KEY",)),
    T("groq", "Groq", "provider", ("groq",), ("groq-sdk",), ("groq", "groq-sdk"), ("api.groq.com",), ("GROQ_API_KEY",)),
    T("together", "Together AI", "provider", ("together",), ("together-ai",), ("together", "together-ai"), ("api.together.xyz", "api.together.ai"), ("TOGETHER_API_KEY",)),
    T("fireworks", "Fireworks AI", "provider", ("fireworks-ai",), ("@fireworks-ai/sdk",), ("fireworks",), ("api.fireworks.ai",), ("FIREWORKS_API_KEY",)),
    T("deepseek", "DeepSeek", "provider", (), (), (), ("api.deepseek.com",), ("DEEPSEEK_API_KEY",)),
    T("xai", "xAI", "provider", ("xai-sdk",), ("@ai-sdk/xai",), ("xai_sdk",), ("api.x.ai",), ("XAI_API_KEY",)),
    T("openrouter", "OpenRouter", "provider", (), ("@openrouter/ai-sdk-provider",), (), ("openrouter.ai",), ("OPENROUTER_API_KEY",)),
    T("perplexity", "Perplexity", "provider", (), (), (), ("api.perplexity.ai",), ("PERPLEXITY_API_KEY", "PPLX_API_KEY")),
    T("replicate", "Replicate", "provider", ("replicate",), ("replicate",), ("replicate",), ("api.replicate.com",), ("REPLICATE_API_TOKEN",)),
    T("voyage", "Voyage AI", "provider", ("voyageai",), ("voyageai",), ("voyageai",), ("api.voyageai.com",), ("VOYAGE_API_KEY",)),
    T("nvidia_nim", "NVIDIA NIM", "serving", (), (), (), ("integrate.api.nvidia.com", "ai.api.nvidia.com"), ("NVIDIA_API_KEY", "NGC_API_KEY"),
      images=("nvcr.io/nim/",)),
    # Self-hosted serving
    T("ollama", "Ollama", "serving", ("ollama", "langchain-ollama"), ("ollama", "ollama-ai-provider"), ("ollama",), (":11434",), ("OLLAMA_HOST",),
      ("github.com/ollama/ollama",), ("ollama/ollama",)),
    T("vllm", "vLLM", "serving", ("vllm",), (), ("vllm",), (), (), images=("vllm/vllm-openai",)),
    T("tgi", "Hugging Face Text Generation Inference", "serving", ("text-generation",), (), ("text_generation",), (), (),
      images=("ghcr.io/huggingface/text-generation-inference",)),
    T("llama_cpp", "llama.cpp", "serving", ("llama-cpp-python",), ("node-llama-cpp",), ("llama_cpp", "node-llama-cpp"), (), (),
      images=("ghcr.io/ggerganov/llama.cpp", "ghcr.io/ggml-org/llama.cpp")),
    T("localai", "LocalAI", "serving", (), (), (), (), (), images=("localai/localai", "quay.io/go-skynet/local-ai")),
    T("open_webui", "Open WebUI", "serving", ("open-webui",), (), (), (), (), images=("ghcr.io/open-webui/open-webui",)),
    # Gateways and frameworks
    T("litellm", "LiteLLM gateway", "framework", ("litellm",), (), ("litellm",), (), ("LITELLM_MASTER_KEY",), images=("ghcr.io/berriai/litellm",)),
    T("langchain", "LangChain", "framework",
      ("langchain", "langchain-core", "langchain-community", "langgraph", "langchain-openai", "langchain-anthropic", "langchain-google-genai"),
      ("langchain", "@langchain/core", "@langchain/langgraph", "@langchain/openai", "@langchain/anthropic", "@langchain/community"),
      ("langchain", "langchain_core", "langchain_community", "langgraph", "langchain_openai", "langchain_anthropic",
       "@langchain/core", "@langchain/langgraph", "@langchain/openai", "@langchain/anthropic", "@langchain/community"),
      (), ("LANGCHAIN_API_KEY", "LANGSMITH_API_KEY"), ("github.com/tmc/langchaingo",), agentic=True),
    T("claude_agent_sdk", "Claude Agent SDK", "framework", ("claude-agent-sdk", "claude-code-sdk"), ("@anthropic-ai/claude-agent-sdk", "@anthropic-ai/claude-code"),
      ("claude_agent_sdk", "claude_code_sdk", "@anthropic-ai/claude-agent-sdk", "@anthropic-ai/claude-code"), agentic=True),
    T("llamaindex", "LlamaIndex", "framework", ("llama-index", "llama-index-core"), ("llamaindex",), ("llama_index", "llamaindex"), (),
      ("LLAMA_CLOUD_API_KEY",), rag=True),
    T("haystack", "Haystack", "framework", ("haystack-ai", "farm-haystack"), (), ("haystack",), (), (), rag=True),
    T("semantic_kernel", "Semantic Kernel", "framework", ("semantic-kernel",), ("semantic-kernel",), ("semantic_kernel",), agentic=True),
    T("autogen", "AutoGen", "framework", ("pyautogen", "autogen", "autogen-agentchat", "autogen-core", "ag2"), (),
      ("autogen", "autogen_agentchat", "autogen_core"), agentic=True),
    T("deepagents", "LangChain Deep Agents", "framework", ("deepagents", "managed-deepagents"), ("deepagents",),
      ("deepagents", "managed_deepagents"), agentic=True),
    T("crewai", "CrewAI", "framework", ("crewai", "crewai-tools"), (), ("crewai", "crewai_tools"), agentic=True),
    T("openai_agents", "OpenAI Agents SDK", "framework", ("openai-agents",), ("@openai/agents",), ("@openai/agents",), agentic=True),
    T("pydantic_ai", "Pydantic AI", "framework", ("pydantic-ai", "pydantic-ai-slim"), (), ("pydantic_ai",), agentic=True),
    T("smolagents", "smolagents", "framework", ("smolagents",), (), ("smolagents",), agentic=True),
    T("google_adk", "Google Agent Development Kit", "framework", ("google-adk",), ("@google/adk",), ("google.adk", "@google/adk"), agentic=True),
    T("strands", "Strands Agents", "framework", ("strands-agents",), (), ("strands",), agentic=True),
    T("dspy", "DSPy", "framework", ("dspy", "dspy-ai"), (), ("dspy",)),
    T("vercel_ai", "Vercel AI SDK", "framework", (), ("ai", "@ai-sdk/openai", "@ai-sdk/anthropic", "@ai-sdk/google"),
      ("@ai-sdk/openai", "@ai-sdk/anthropic", "@ai-sdk/google", "@ai-sdk/react"), agentic=True),
    T("mastra", "Mastra", "framework", (), ("@mastra/core",), ("@mastra/core",), agentic=True),
    T("mcp", "Model Context Protocol SDK", "mcp", ("mcp", "fastmcp", "langchain-mcp-adapters"), ("@modelcontextprotocol/sdk", "@langchain/mcp-adapters"),
      ("mcp", "fastmcp", "@modelcontextprotocol/sdk", "langchain_mcp_adapters", "@langchain/mcp-adapters"),
      go=("github.com/mark3labs/mcp-go", "github.com/modelcontextprotocol/go-sdk")),
    # Vector stores
    T("pinecone", "Pinecone", "vector_db", ("pinecone", "pinecone-client"), ("@pinecone-database/pinecone",), ("pinecone", "@pinecone-database/pinecone"),
      (".pinecone.io",), ("PINECONE_API_KEY",)),
    T("chroma", "Chroma", "vector_db", ("chromadb", "langchain-chroma"), ("chromadb",), ("chromadb",), (":8000/api/v1",), ("CHROMA_HOST",),
      images=("chromadb/chroma",)),
    T("qdrant", "Qdrant", "vector_db", ("qdrant-client", "langchain-qdrant"), ("@qdrant/js-client-rest",), ("qdrant_client", "@qdrant/js-client-rest"),
      (":6333", ".qdrant.io"), ("QDRANT_API_KEY", "QDRANT_URL"), images=("qdrant/qdrant",)),
    T("weaviate", "Weaviate", "vector_db", ("weaviate-client",), ("weaviate-client", "weaviate-ts-client"), ("weaviate",),
      (".weaviate.network", ".weaviate.cloud"), ("WEAVIATE_API_KEY", "WEAVIATE_URL"), images=("semitechnologies/weaviate", "cr.weaviate.io/")),
    T("milvus", "Milvus", "vector_db", ("pymilvus",), ("@zilliz/milvus2-sdk-node",), ("pymilvus",), (":19530",), ("MILVUS_URI",), images=("milvusdb/milvus",)),
    T("pgvector", "pgvector", "vector_db", ("pgvector",), ("pgvector",), ("pgvector",), images=("pgvector/pgvector",)),
    T("faiss", "FAISS", "vector_db", ("faiss-cpu", "faiss-gpu"), (), ("faiss",)),
    T("lancedb", "LanceDB", "vector_db", ("lancedb",), ("@lancedb/lancedb",), ("lancedb", "@lancedb/lancedb")),
    # Model hubs and registries
    T("huggingface", "Hugging Face", "registry", ("huggingface-hub", "transformers", "diffusers", "sentence-transformers"),
      ("@huggingface/inference", "@huggingface/hub", "@huggingface/transformers"),
      ("huggingface_hub", "transformers", "diffusers", "sentence_transformers", "@huggingface/inference", "@huggingface/transformers"),
      ("huggingface.co", "api-inference.huggingface.co"), ("HF_TOKEN", "HUGGINGFACEHUB_API_TOKEN", "HUGGING_FACE_HUB_TOKEN")),
    T("mlflow", "MLflow", "registry", ("mlflow",), (), ("mlflow",), (), ("MLFLOW_TRACKING_URI",), images=("ghcr.io/mlflow/mlflow",)),
)
BY_KEY = {t.key: t for t in TECHS}
# Framework integration packages that also mean the named provider is used (langchain-anthropic -> Anthropic).
INTEGRATIONS = {
    "claude-agent-sdk": "anthropic", "claude_agent_sdk": "anthropic", "@anthropic-ai/claude-agent-sdk": "anthropic",
    "langchain-openai": "openai", "langchain-anthropic": "anthropic", "langchain-google-genai": "google_gemini",
    "langchain-google-vertexai": "vertex_ai", "langchain-aws": "aws_bedrock", "langchain-mistralai": "mistral", "langchain-groq": "groq",
    "langchain-cohere": "cohere", "langchain-ollama": "ollama", "langchain-together": "together", "langchain-fireworks": "fireworks",
    "langchain-xai": "xai", "langchain-deepseek": "deepseek", "langchain-pinecone": "pinecone", "langchain-chroma": "chroma",
    "langchain-qdrant": "qdrant", "langchain-weaviate": "weaviate", "langchain-milvus": "milvus", "langchain-postgres": "pgvector",
    "llama-index-llms-openai": "openai", "llama-index-llms-anthropic": "anthropic", "llama-index-llms-ollama": "ollama",
    "llama-index-embeddings-openai": "openai", "llama-index-vector-stores-chroma": "chroma", "llama-index-vector-stores-qdrant": "qdrant",
    "llama-index-vector-stores-pinecone": "pinecone", "llama-index-vector-stores-postgres": "pgvector",
    "@langchain/openai": "openai", "@langchain/anthropic": "anthropic", "@langchain/google-genai": "google_gemini", "@langchain/ollama": "ollama",
    "@ai-sdk/openai": "openai", "@ai-sdk/anthropic": "anthropic", "@ai-sdk/google": "google_gemini", "@ai-sdk/mistral": "mistral",
    "@ai-sdk/amazon-bedrock": "aws_bedrock", "@ai-sdk/azure": "azure_openai", "@ai-sdk/groq": "groq",
    "langchain_openai": "openai", "langchain_anthropic": "anthropic", "langchain_google_genai": "google_gemini", "langchain_aws": "aws_bedrock",
    "langchain_mistralai": "mistral", "langchain_groq": "groq", "langchain_ollama": "ollama", "langchain_chroma": "chroma",
    "langchain_qdrant": "qdrant", "langchain_pinecone": "pinecone",
}
# "provider:model" identifiers used by init_chat_model and similar helpers.
MODEL_PREFIXES = {"openai": "openai", "anthropic": "anthropic", "google_genai": "google_gemini", "google_vertexai": "vertex_ai",
                  "google-vertex": "vertex_ai", "bedrock": "aws_bedrock", "bedrock_converse": "aws_bedrock", "mistralai": "mistral",
                  "groq": "groq", "ollama": "ollama", "azure_openai": "azure_openai", "cohere": "cohere", "fireworks": "fireworks",
                  "together": "together", "xai": "xai", "deepseek": "deepseek", "huggingface": "huggingface"}
PREFIXED_MODEL = re.compile(r"""["'](openai|anthropic|google_genai|google_vertexai|google-vertex|bedrock_converse|bedrock|mistralai|groq|ollama|"""
                            r"""azure_openai|cohere|fireworks|together|xai|deepseek|huggingface):(?=[\w.\-:]*[A-Za-z])([A-Za-z0-9][\w.\-:]{1,80})["']""")  # not host:port
PYPI_INDEX = {p.lower(): t for t in TECHS for p in t.pypi}
NPM_INDEX = {p.lower(): t for t in TECHS for p in t.npm}
GO_INDEX = {p: t for t in TECHS for p in t.go}
IMPORT_INDEX = {i: t for t in TECHS for i in t.imports}
ENV_INDEX = {e: t for t in TECHS for e in t.env}
IMAGE_INDEX = {i: t for t in TECHS for i in t.images}
ASSET_TYPE = {"provider": "ai_provider", "serving": "ai_provider", "framework": "ai_framework", "mcp": "ai_framework",
              "vector_db": "vector_database", "registry": "model_registry"}

# --- Secrets ---------------------------------------------------------------------------------------
# (rule, provider key or "", label, severity, pattern). Group 1 is a non-secret prefix kept in evidence.


@dataclass(frozen=True)
class SecretPattern:
    rule: str
    provider: str
    label: str
    severity: str
    pattern: re.Pattern = field(compare=False)


S = SecretPattern
SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    S("anthropic_api_key", "anthropic", "Anthropic API key", "critical", re.compile(r"\b(sk-ant-(?:api|admin)\d{2}-)[A-Za-z0-9_\-]{60,}")),
    S("openai_project_key", "openai", "OpenAI API key", "critical", re.compile(r"\b(sk-(?:proj|svcacct|admin)-)[A-Za-z0-9_\-]{40,}")),
    S("openai_api_key", "openai", "OpenAI API key (legacy format)", "critical", re.compile(r"\b(sk-)[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}")),
    S("huggingface_token", "huggingface", "Hugging Face token", "critical", re.compile(r"\b(hf_)[A-Za-z0-9]{34,}")),
    # Generic Google key (Maps, Firebase web config, Gemini, ...): not evidence of an AI provider, and often public by design.
    S("google_api_key", "", "Google API key", "medium", re.compile(r"\b(AIza)[0-9A-Za-z_\-]{35}\b")),
    S("nvidia_api_key", "nvidia_nim", "NVIDIA API key", "critical", re.compile(r"\b(nvapi-)[A-Za-z0-9_\-]{50,}")),
    S("pinecone_api_key", "pinecone", "Pinecone API key", "critical", re.compile(r"\b(pcsk_)[A-Za-z0-9_]{40,}")),
    S("replicate_token", "replicate", "Replicate API token", "critical", re.compile(r"\b(r8_)[A-Za-z0-9]{37}\b")),
    S("groq_api_key", "groq", "Groq API key", "critical", re.compile(r"\b(gsk_)[A-Za-z0-9]{48,}")),
    S("xai_api_key", "xai", "xAI API key", "critical", re.compile(r"\b(xai-)[A-Za-z0-9]{70,}")),
    S("aws_access_key", "", "AWS access key ID", "high", re.compile(r"\b((?:AKIA|ASIA))[0-9A-Z]{16}\b")),
    S("github_token", "", "GitHub token", "critical", re.compile(r"\b(gh[pousr]_)[A-Za-z0-9]{36,}\b|\b(github_pat_)[A-Za-z0-9_]{60,}")),
    S("gitlab_token", "", "GitLab token", "critical", re.compile(r"\b(glpat-)[A-Za-z0-9_\-]{20,}")),
    S("slack_token", "", "Slack token", "high", re.compile(r"\b(xox[baprs]-)[A-Za-z0-9\-]{10,}")),
    S("stripe_live_key", "", "Stripe live secret key", "critical", re.compile(r"\b((?:sk|rk)_live_)[A-Za-z0-9]{20,}")),
    S("npm_token", "", "npm access token", "high", re.compile(r"\b(npm_)[A-Za-z0-9]{36}\b")),
    S("sendgrid_key", "", "SendGrid API key", "high", re.compile(r"\b(SG\.)[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    S("private_key", "", "Private key", "critical", re.compile(r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)")),
)
# Values that are clearly placeholders, not credentials.
PLACEHOLDER = re.compile(r"(x{6,}|0{8,}|your[_-]?(api[_-]?)?key|example|placeholder|changeme|dummy|<[^>]+>|\.\.\.)", re.IGNORECASE)

# --- Model artifacts --------------------------------------------------------------------------------
MODEL_EXTENSIONS = {
    ".pkl": "pickle", ".pickle": "pickle", ".joblib": "pickle", ".pt": "pytorch", ".pth": "pytorch", ".ckpt": "pytorch",
    ".bin": "binary", ".h5": "hdf5", ".keras": "keras", ".onnx": "onnx", ".safetensors": "safetensors", ".gguf": "gguf",
    ".tflite": "tflite", ".mlmodel": "coreml",
}
MODEL_FILE_NAMES = {"saved_model.pb": "tensorflow"}  # other .pb files are usually protobuf descriptors, not models
CODE_EXECUTION_FORMATS = {"pickle", "pytorch"}
MIN_MODEL_BYTES = 32  # smaller files with these extensions are not models

# --- MCP ---------------------------------------------------------------------------------------------
MCP_CONFIG_NAMES = {".mcp.json", "mcp.json", "claude_desktop_config.json", "mcp_config.json", "mcp-config.json", "mcp_settings.json",
                    "cline_mcp_settings.json"}
MCP_CONFIG_PARENTS = {".cursor", ".vscode", ".claude", ".windsurf", ".gemini", ".roo", ".kiro", ".amazonq", ".codex", ".continue"}

# --- Agent tools --------------------------------------------------------------------------------------
CAPABILITY_MARKERS: dict[str, re.Pattern] = {
    "shell": re.compile(r"\b(shell|bash|exec(ute)?[_ ]?(command|cmd)|run[_ ]?(command|cmd|script)|terminal|subprocess)\b", re.IGNORECASE),
    "code_execution": re.compile(r"\b(eval|run[_ ]?(python|code|js)|code[_ ]?interpreter|execute[_ ]?code|python[_ ]?repl)\b", re.IGNORECASE),
    "filesystem_write": re.compile(r"\b(write|delete|remove|move|rename|create)[_ ]?(file|dir|directory|folder)|edit[_ ]?file\b", re.IGNORECASE),
    "database_write": re.compile(r"\b(execute[_ ]?sql|run[_ ]?query|insert[_ ]?(row|record)|update[_ ]?(row|record|table)|drop[_ ]?table)\b", re.IGNORECASE),
    "email_send": re.compile(r"\bsend[_ ]?(e?mail|message|sms|slack)\b", re.IGNORECASE),
    "payment": re.compile(r"\b(payments?|refunds?|refund[_ ]?\w+|pay[_ ]?(invoice|bill|out|vendor)|transfer[_ ]?funds|charge[_ ]?(card|customer)|"
                          r"purchase|issue[_ ]?invoice|process[_ ]?payment)\b", re.IGNORECASE),
    "deploy": re.compile(r"\b(deploy|release|kubectl|terraform[_ ]?apply|merge[_ ]?(pull|pr))\b", re.IGNORECASE),
    "iam_admin": re.compile(r"\b(create|delete|grant|revoke|attach)[_ ]?(user|role|policy|permission|access[_ ]?key)\b", re.IGNORECASE),
    "delete": re.compile(r"\b(delete|destroy|purge|wipe)[_ ]?\w*", re.IGNORECASE),
    "external_http": re.compile(r"\b(fetch[_ ]?(url|page|web)|http[_ ]?request|curl|browse|web[_ ]?(search|fetch)|download)\b", re.IGNORECASE),
}
HIGH_IMPACT = {"shell", "code_execution", "filesystem_write", "database_write", "email_send", "payment", "deploy", "iam_admin", "delete",
               "external_http"}

POISONING_INDICATORS: tuple[tuple[str, str, re.Pattern], ...] = (
    ("instruction_override", "Text instructs the model to ignore or override other instructions",
     re.compile(r"(ignore|disregard|forget|override)\s+(all\s+|any\s+)?(previous|prior|above|other|earlier|system)\s+(instructions?|rules?|prompts?)", re.IGNORECASE)),
    ("concealment", "Text instructs the model to hide its behaviour from the user",
     re.compile(r"(do\s+not|don'?t|never)\s+(tell|inform|mention|reveal|show|notify)\s+(this\s+)?(to\s+)?(the\s+)?(user|human)", re.IGNORECASE)),
    ("imperative_block", "Description contains a directive block addressed to the model",
     re.compile(r"<\s*(important|system|instructions?|secret|admin)\s*>|\[\s*(system|important)\s*\]", re.IGNORECASE)),
    ("sensitive_file_access", "Description directs access to credential or key material",
     re.compile(r"(~|\$HOME|/home/[^/\s]+|/root)/\.(ssh|aws|gnupg|kube)|id_rsa|/etc/(passwd|shadow)|credentials\.json", re.IGNORECASE)),
    ("exfiltration", "Description directs data to an external destination or hidden parameter",
     re.compile(r"(send|post|upload|forward|exfiltrate)\s+[^.]{0,60}to\s+https?://", re.IGNORECASE)),
)

# --- Infrastructure as code -------------------------------------------------------------------------
# resource type prefix -> (asset type, AI technology key or None)
# resource type -> (asset type, AI technology key or None). Types match exactly; an entry ending in "_" (Terraform) or "::"
# (CloudFormation) is a family prefix, used for AI services whose every resource is worth listing.
TERRAFORM_TYPES: tuple[tuple[str, str, str | None], ...] = (
    ("aws_sagemaker_endpoint", "llm_endpoint", None), ("aws_sagemaker_model", "ai_model", None),
    ("aws_bedrockagent_agent", "ai_agent", "aws_bedrock"), ("aws_bedrockagent_knowledge_base", "rag_application", "aws_bedrock"),
    ("aws_bedrock_", "cloud_resource", "aws_bedrock"), ("aws_bedrockagent_", "cloud_resource", "aws_bedrock"),
    ("google_vertex_ai_endpoint", "llm_endpoint", "vertex_ai"), ("google_vertex_ai_index", "vector_database", "vertex_ai"),
    ("google_vertex_ai_", "cloud_resource", "vertex_ai"),
    ("azurerm_cognitive_deployment", "llm_endpoint", "azure_openai"), ("azurerm_cognitive_account", "ai_provider", "azure_openai"),
    ("azurerm_machine_learning_workspace", "model_registry", None), ("azurerm_search_service", "vector_database", None),
    ("aws_s3_bucket", "storage", None), ("google_storage_bucket", "storage", None), ("azurerm_storage_account", "storage", None),
    ("aws_db_instance", "database", None), ("aws_rds_cluster", "database", None), ("aws_dynamodb_table", "database", None),
    ("google_sql_database_instance", "database", None), ("azurerm_postgresql_server", "database", None),
    ("azurerm_postgresql_flexible_server", "database", None), ("azurerm_mssql_server", "database", None), ("azurerm_mssql_database", "database", None),
    ("azurerm_cosmosdb_account", "database", None), ("aws_opensearch_domain", "database", None), ("aws_elasticache_cluster", "database", None),
    ("aws_elasticache_replication_group", "database", None), ("aws_redshift_cluster", "database", None),
    ("aws_lb", "load_balancer", None), ("aws_alb", "load_balancer", None), ("aws_elb", "load_balancer", None),
    ("google_compute_forwarding_rule", "load_balancer", None), ("azurerm_lb", "load_balancer", None), ("azurerm_application_gateway", "load_balancer", None),
    ("aws_iam_role", "identity", None), ("aws_iam_user", "identity", None), ("google_service_account", "identity", None),
    ("azurerm_user_assigned_identity", "identity", None),
    ("aws_instance", "host", None), ("google_compute_instance", "host", None), ("azurerm_linux_virtual_machine", "host", None),
    ("azurerm_windows_virtual_machine", "host", None),
    ("aws_eks_cluster", "cloud_resource", None), ("google_container_cluster", "cloud_resource", None), ("azurerm_kubernetes_cluster", "cloud_resource", None),
    ("aws_lambda_function", "cloud_resource", None), ("google_cloudfunctions_function", "cloud_resource", None),
    ("google_cloudfunctions2_function", "cloud_resource", None), ("google_cloud_run_service", "cloud_resource", None),
    ("google_cloud_run_v2_service", "cloud_resource", None), ("aws_ecs_service", "cloud_resource", None),
    ("aws_api_gateway_rest_api", "api", None), ("aws_apigatewayv2_api", "api", None),
)
CFN_TYPES: tuple[tuple[str, str, str | None], ...] = (
    ("AWS::SageMaker::Endpoint", "llm_endpoint", None), ("AWS::SageMaker::Model", "ai_model", None),
    ("AWS::Bedrock::Agent", "ai_agent", "aws_bedrock"), ("AWS::Bedrock::KnowledgeBase", "rag_application", "aws_bedrock"),
    ("AWS::Bedrock::", "cloud_resource", "aws_bedrock"), ("AWS::S3::Bucket", "storage", None), ("AWS::RDS::DBInstance", "database", None),
    ("AWS::RDS::DBCluster", "database", None), ("AWS::DynamoDB::Table", "database", None),
    ("AWS::ElasticLoadBalancingV2::LoadBalancer", "load_balancer", None), ("AWS::IAM::Role", "identity", None), ("AWS::IAM::User", "identity", None),
    ("AWS::EC2::Instance", "host", None), ("AWS::EKS::Cluster", "cloud_resource", None), ("AWS::Lambda::Function", "cloud_resource", None),
    ("AWS::Serverless::Function", "cloud_resource", None), ("AWS::ECS::Service", "cloud_resource", None), ("AWS::ApiGateway::RestApi", "api", None),
    ("AWS::ApiGatewayV2::Api", "api", None), ("AWS::OpenSearchService::Domain", "database", None),
)


def resource_type(kind: str, table) -> tuple[str, str | None] | None:
    """(asset type, technology) for an IaC resource type: exact entries first, then family prefixes."""
    for name, asset_type, tech in table:
        if kind == name:
            return asset_type, tech
    for name, asset_type, tech in table:
        if name.endswith(("_", "::")) and kind.startswith(name):
            return asset_type, tech
    return None


# Hosts whose URLs in code are documentation or package indexes, not services the code calls.
NON_SERVICE_DOMAINS = (
    "github.com", "githubusercontent.com", "gitlab.com", "stackoverflow.com", "wikipedia.org", "example.com", "example.org", "example.net",
    "schema.org", "w3.org", "json-schema.org", "npmjs.com", "npmjs.org", "pypi.org", "pythonhosted.org", "mozilla.org", "python.org",
    "shields.io", "creativecommons.org", "opensource.org", "unpkg.com", "jsdelivr.net", "twitter.com", "x.com", "youtube.com", "medium.com",
    "spdx.org", "readthedocs.io", "readthedocs.org", "apache.org", "gnu.org", "microsoft.com", "google.com", "apple.com",
)
NON_SERVICE_LABELS = ("docs", "doc", "schemas", "fonts", "img", "images", "cdn", "static", "assets", "www")


def is_reference_host(host: str) -> bool:
    """True for documentation, package-index and asset hosts: URLs to them are references, not services the code calls."""
    host = host.lower().split(":")[0]
    if any(host == d or host.endswith("." + d) for d in NON_SERVICE_DOMAINS):
        return True
    return host.split(".")[0] in NON_SERVICE_LABELS


# URL path or port markers of a self-hosted inference API.
INFERENCE_MARKERS = re.compile(r"(:11434\b|/v1/chat/completions|/v1/completions|/v1/embeddings|/api/generate|/api/chat\b|/generate_stream|/v1/models)")
MODEL_NAME = re.compile(
    r"""(?:model(?:_name|_id|Name|Id)?\s*[=:]\s*|"model"\s*:\s*)["']((?:gpt-|o[134]-|o[134]\b|claude-|gemini-|mistral-|mixtral|llama|codellama|"""
    r"""qwen|deepseek|phi-|command-r|grok-|text-embedding-|embed-|anthropic\.|amazon\.|meta\.)[\w.:\-/]*)["']""", re.IGNORECASE)
HF_MODEL_REF = re.compile(
    r"""(?:from_pretrained|hf_hub_download|snapshot_download|pipeline|SentenceTransformer|AutoModel\w*\.from_pretrained)\s*\(\s*"""
    r"""(?:[^)]*?(?:repo_id|model)\s*=\s*)?["']([A-Za-z0-9][\w.\-]*/[\w.\-]+)["']""")
