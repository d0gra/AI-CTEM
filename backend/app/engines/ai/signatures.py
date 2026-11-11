"""Detection signatures for AI providers, frameworks and infrastructure."""

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class AISignature:
    key: str
    name: str
    category: str  # provider | framework | vector_db | serving | mcp | registry
    pypi: tuple[str, ...] = ()
    npm: tuple[str, ...] = ()
    imports: tuple[str, ...] = ()  # python module roots / JS package names seen in import statements
    hosts: tuple[str, ...] = ()  # substrings of API hostnames
    env: tuple[str, ...] = ()
    extra: dict = field(default_factory=dict)


SIGNATURES: tuple[AISignature, ...] = (
    AISignature("openai", "OpenAI", "provider", ("openai",), ("openai",), ("openai",), ("api.openai.com",), ("OPENAI_API_KEY",)),
    AISignature("anthropic", "Anthropic", "provider", ("anthropic",), ("@anthropic-ai/sdk",), ("anthropic", "@anthropic-ai/sdk"),
                ("api.anthropic.com",), ("ANTHROPIC_API_KEY",)),
    AISignature("google_gemini", "Google Gemini", "provider", ("google-generativeai", "google-genai"), ("@google/generative-ai", "@google/genai"),
                ("google.generativeai", "google.genai", "@google/generative-ai", "@google/genai"), ("generativelanguage.googleapis.com",),
                ("GEMINI_API_KEY", "GOOGLE_API_KEY")),
    AISignature("aws_bedrock", "AWS Bedrock", "provider", (), ("@aws-sdk/client-bedrock-runtime",), ("@aws-sdk/client-bedrock-runtime",),
                ("bedrock-runtime.", "bedrock."), ("AWS_BEDROCK_MODEL_ID", "BEDROCK_MODEL_ID")),
    AISignature("azure_openai", "Azure OpenAI / AI Foundry", "provider", ("azure-ai-inference", "azure-ai-projects"), ("@azure/openai", "@azure-rest/ai-inference"),
                ("azure.ai.inference", "azure.ai.projects", "@azure/openai"), (".openai.azure.com", ".services.ai.azure.com", ".inference.ai.azure.com"),
                ("AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT")),
    AISignature("vertex_ai", "Google Vertex AI", "provider", ("google-cloud-aiplatform", "vertexai"), ("@google-cloud/vertexai",),
                ("vertexai", "google.cloud.aiplatform", "@google-cloud/vertexai"), ("aiplatform.googleapis.com",), ()),
    AISignature("huggingface", "Hugging Face", "registry", ("huggingface-hub", "transformers", "diffusers", "sentence-transformers"),
                ("@huggingface/inference", "@huggingface/hub"), ("huggingface_hub", "transformers", "diffusers", "sentence_transformers", "@huggingface/inference"),
                ("huggingface.co", "api-inference.huggingface.co"), ("HF_TOKEN", "HUGGINGFACEHUB_API_TOKEN", "HUGGING_FACE_HUB_TOKEN")),
    AISignature("ollama", "Ollama", "serving", ("ollama",), ("ollama",), ("ollama",), (":11434",), ("OLLAMA_HOST",)),
    AISignature("vllm", "vLLM", "serving", ("vllm",), (), ("vllm",), (), ()),
    AISignature("nvidia_nim", "NVIDIA NIM", "serving", (), (), (), ("integrate.api.nvidia.com", "ai.api.nvidia.com"), ("NVIDIA_API_KEY", "NGC_API_KEY")),
    AISignature("cohere", "Cohere", "provider", ("cohere",), ("cohere-ai",), ("cohere", "cohere-ai"), ("api.cohere.com", "api.cohere.ai"), ("COHERE_API_KEY",)),
    AISignature("mistral", "Mistral AI", "provider", ("mistralai",), ("@mistralai/mistralai",), ("mistralai", "@mistralai/mistralai"), ("api.mistral.ai",), ("MISTRAL_API_KEY",)),
    AISignature("litellm", "LiteLLM gateway", "framework", ("litellm",), (), ("litellm",), (), ("LITELLM_MASTER_KEY",)),
    AISignature("langchain", "LangChain", "framework", ("langchain", "langchain-core", "langchain-community", "langgraph", "langchain-openai", "langchain-anthropic"),
                ("langchain", "@langchain/core", "@langchain/langgraph", "@langchain/openai", "@langchain/anthropic"),
                ("langchain", "langchain_core", "langchain_community", "langgraph", "@langchain/core", "@langchain/langgraph"), (), ("LANGCHAIN_API_KEY", "LANGSMITH_API_KEY"),
                {"agentic": True}),
    AISignature("llamaindex", "LlamaIndex", "framework", ("llama-index", "llama-index-core"), ("llamaindex",), ("llama_index", "llamaindex"), (), ("LLAMA_CLOUD_API_KEY",), {"rag": True}),
    AISignature("semantic_kernel", "Semantic Kernel", "framework", ("semantic-kernel",), ("semantic-kernel",), ("semantic_kernel",), (), (), {"agentic": True}),
    AISignature("autogen", "AutoGen", "framework", ("pyautogen", "autogen", "autogen-agentchat", "autogen-core"), (), ("autogen", "autogen_agentchat", "autogen_core"), (), (), {"agentic": True}),
    AISignature("crewai", "CrewAI", "framework", ("crewai",), (), ("crewai",), (), (), {"agentic": True}),
    AISignature("mcp", "Model Context Protocol SDK", "mcp", ("mcp", "fastmcp"), ("@modelcontextprotocol/sdk",), ("mcp", "fastmcp", "@modelcontextprotocol/sdk"), (), ()),
    AISignature("pinecone", "Pinecone", "vector_db", ("pinecone", "pinecone-client"), ("@pinecone-database/pinecone",), ("pinecone", "@pinecone-database/pinecone"), (".pinecone.io",), ("PINECONE_API_KEY",)),
    AISignature("chroma", "Chroma", "vector_db", ("chromadb",), ("chromadb",), ("chromadb",), (), ()),
    AISignature("qdrant", "Qdrant", "vector_db", ("qdrant-client",), ("@qdrant/js-client-rest",), ("qdrant_client", "@qdrant/js-client-rest"), (":6333", ".qdrant.io"), ("QDRANT_API_KEY",)),
    AISignature("weaviate", "Weaviate", "vector_db", ("weaviate-client",), ("weaviate-client", "weaviate-ts-client"), ("weaviate",), (".weaviate.network", ".weaviate.cloud"), ("WEAVIATE_API_KEY",)),
    AISignature("milvus", "Milvus", "vector_db", ("pymilvus",), ("@zilliz/milvus2-sdk-node",), ("pymilvus",), (":19530",), ()),
    AISignature("pgvector", "pgvector", "vector_db", ("pgvector",), ("pgvector",), ("pgvector",), (), ()),
    AISignature("mlflow", "MLflow", "registry", ("mlflow",), (), ("mlflow",), (), ("MLFLOW_TRACKING_URI",)),
)
BY_KEY = {s.key: s for s in SIGNATURES}
PYPI_INDEX = {pkg.lower(): s for s in SIGNATURES for pkg in s.pypi}
NPM_INDEX = {pkg.lower(): s for s in SIGNATURES for pkg in s.npm}
ENV_INDEX = {env: s for s in SIGNATURES for env in s.env}

# (rule, provider key, human label, pattern). Group 1 is the non-secret prefix kept in evidence.
SECRET_PATTERNS: tuple[tuple[str, str, str, re.Pattern], ...] = (
    ("anthropic_api_key", "anthropic", "Anthropic API key", re.compile(r"\b(sk-ant-(?:api|admin)\d{2}-)[A-Za-z0-9_\-]{60,}")),
    ("openai_project_key", "openai", "OpenAI API key", re.compile(r"\b(sk-(?:proj|svcacct|admin)-)[A-Za-z0-9_\-]{40,}")),
    ("openai_api_key", "openai", "OpenAI API key (legacy format)", re.compile(r"\b(sk-)[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}")),
    ("huggingface_token", "huggingface", "Hugging Face token", re.compile(r"\b(hf_)[A-Za-z0-9]{34,}")),
    ("google_api_key", "google_gemini", "Google API key", re.compile(r"\b(AIza)[0-9A-Za-z_\-]{35}\b")),
    ("nvidia_api_key", "nvidia_nim", "NVIDIA API key", re.compile(r"\b(nvapi-)[A-Za-z0-9_\-]{50,}")),
    ("pinecone_api_key", "pinecone", "Pinecone API key", re.compile(r"\b(pcsk_)[A-Za-z0-9_]{40,}")),
    ("replicate_token", "replicate", "Replicate API token", re.compile(r"\b(r8_)[A-Za-z0-9]{37}\b")),
    ("groq_api_key", "groq", "Groq API key", re.compile(r"\b(gsk_)[A-Za-z0-9]{48,}")),
)

MODEL_EXTENSIONS = {
    ".pkl": "pickle", ".pickle": "pickle", ".joblib": "pickle", ".pt": "pytorch", ".pth": "pytorch", ".ckpt": "pytorch",
    ".bin": "binary", ".h5": "hdf5", ".keras": "keras", ".onnx": "onnx", ".safetensors": "safetensors", ".gguf": "gguf",
    ".pb": "tensorflow", ".tflite": "tflite", ".npy": "numpy", ".mlmodel": "coreml",
}
# Formats whose loaders can execute code embedded in the file.
CODE_EXECUTION_FORMATS = {"pickle", "pytorch"}

MCP_CONFIG_NAMES = {".mcp.json", "mcp.json", "claude_desktop_config.json", "mcp_config.json", "mcp-config.json"}
MCP_CONFIG_PARENTS = {".cursor", ".vscode", ".claude", ".windsurf"}
