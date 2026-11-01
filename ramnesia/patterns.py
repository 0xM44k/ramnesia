"""
RAMnesia detector definitions.

Each Detector describes one class of AI/agent artifact we look for in raw
memory bytes. Patterns are byte-regexes (memory is bytes, not text) with
bounded quantifiers to avoid catastrophic backtracking on garbage data.

Categories:
  secret   - credentials that leak: API keys, tokens, JWTs
  prompt   - conversation material: chat roles, chat-template markers
  mcp      - Model Context Protocol / JSON-RPC agent traffic
  model    - model names and provider endpoints (context, lower value)

Severity: high | medium | info
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Pattern


@dataclass(frozen=True)
class Detector:
    name: str
    category: str
    severity: str
    pattern: Pattern[bytes]
    description: str
    # optional redaction for sensitive hits (keeps forensic value, hides secret)
    redact: Optional[Callable[[bytes], bytes]] = None


def _mask(b: bytes, show_head: int = 6, show_tail: int = 4) -> bytes:
    """sk-ant-abcdef....wxyz -> keep head/tail, mask the middle."""
    if len(b) <= show_head + show_tail:
        return b[:1] + b"*" * (len(b) - 1)
    return b[:show_head] + b"..." + b[-show_tail:]


def _mask_after_eq(b: bytes) -> bytes:
    """KEY=secretvalue -> KEY=sec...ue (keep the variable name visible)."""
    if b"=" in b:
        k, _, v = b.partition(b"=")
        return k + b"=" + _mask(v.strip())
    return _mask(b)


# ---- secrets -------------------------------------------------------------
_SECRETS: List[Detector] = [
    Detector(
        "anthropic_api_key", "secret", "high",
        re.compile(rb"sk-ant-[A-Za-z0-9_\-]{20,120}"),
        "Anthropic API key", _mask,
    ),
    Detector(
        "openai_api_key", "secret", "high",
        # sk- not followed by ant- (that's Anthropic's), optional proj- prefix
        re.compile(rb"sk-(?!ant-)(?:proj-)?[A-Za-z0-9]{20,100}"),
        "OpenAI-style API key", _mask,
    ),
    Detector(
        "aws_access_key_id", "secret", "high",
        re.compile(rb"AKIA[0-9A-Z]{16}"),
        "AWS access key id", _mask,
    ),
    Detector(
        "google_api_key", "secret", "high",
        re.compile(rb"AIza[0-9A-Za-z_\-]{35}"),
        "Google API key", _mask,
    ),
    Detector(
        "github_token", "secret", "high",
        re.compile(rb"gh[pousr]_[A-Za-z0-9]{36,255}"),
        "GitHub token", _mask,
    ),
    Detector(
        "slack_token", "secret", "high",
        re.compile(rb"xox[baprs]-[A-Za-z0-9-]{10,100}"),
        "Slack token", _mask,
    ),
    Detector(
        "jwt", "secret", "high",
        re.compile(rb"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"),
        "JSON Web Token", _mask,
    ),
    Detector(
        "bearer_token", "secret", "high",
        re.compile(rb"[Bb]earer\s+[A-Za-z0-9._\-]{20,255}"),
        "Authorization bearer token", _mask,
    ),
    Detector(
        "huggingface_token", "secret", "high",
        re.compile(rb"hf_[A-Za-z0-9]{30,64}"),
        "Hugging Face access token", _mask,
    ),
    Detector(
        "gcp_service_account", "secret", "high",
        re.compile(rb'"type"\s*:\s*"service_account"'),
        "GCP service-account key JSON", None,
    ),
    Detector(
        "private_key_pem", "secret", "high",
        re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH |DSA |)PRIVATE KEY-----"),
        "PEM private key header", None,
    ),
    Detector(
        "llm_env_key", "secret", "high",
        re.compile(rb"(?:ANTHROPIC|OPENAI|OPENROUTER|GROQ|MISTRAL|COHERE|TOGETHER|HUGGINGFACE|HF|GOOGLE|GEMINI|AZURE_OPENAI)_API_KEY\s*=\s*[^\s\"']{8,200}"),
        "LLM provider API key in an env assignment", _mask_after_eq,
    ),
]

# ---- prompts / conversation ---------------------------------------------
_PROMPTS: List[Detector] = [
    Detector(
        "chat_role_json", "prompt", "medium",
        re.compile(rb'"role"\s*:\s*"(?:system|user|assistant|tool)"'),
        "Chat message role field (OpenAI/Anthropic messages format)",
    ),
    Detector(
        "chat_template_marker", "prompt", "medium",
        re.compile(rb"<\|im_start\|>|<\|im_end\|>|\[/?INST\]|<<SYS>>|<\|(?:user|assistant|system)\|>"),
        "Model chat-template delimiter (ChatML / Llama / etc.)",
    ),
    Detector(
        "system_prompt_opener", "prompt", "info",
        re.compile(rb"You are (?:a |an |the )?[A-Z][A-Za-z ]{3,40}"),
        "Likely system-prompt opener ('You are ...')",
    ),
]

# ---- MCP / agent traffic -------------------------------------------------
_MCP: List[Detector] = [
    Detector(
        "mcp_method", "mcp", "medium",
        re.compile(rb'"method"\s*:\s*"(?:tools/call|tools/list|resources/read|resources/list|prompts/get|prompts/list|initialize|notifications/[a-z/]+)"'),
        "MCP JSON-RPC method call",
    ),
    Detector(
        "jsonrpc_envelope", "mcp", "info",
        re.compile(rb'"jsonrpc"\s*:\s*"2\.0"'),
        "JSON-RPC 2.0 envelope (MCP transport)",
    ),
    Detector(
        "mcp_tool_name", "mcp", "info",
        re.compile(rb'"(?:tool_name|toolName|name)"\s*:\s*"[a-z][a-z0-9_\-]{2,40}"'),
        "Possible tool-call name field",
    ),
]

# ---- agent frameworks ----------------------------------------------------
_AGENT: List[Detector] = [
    Detector(
        "react_trace", "agent", "medium",
        re.compile(rb"(?:Thought:|Action:|Action Input:|Observation:|Final Answer:)\s"),
        "ReAct agent reasoning trace",
    ),
    Detector(
        "agent_framework", "agent", "info",
        re.compile(rb"langchain(?:_core|_community)?|crew_?ai|CrewAgentExecutor|autogen|AssistantAgent|llama_index|AgentExecutor"),
        "Agent framework identifier",
    ),
    Detector(
        "conversation_turn", "agent", "info",
        re.compile(rb"(?:Human|Assistant|System|AI):\s"),
        "Transcript-style conversation turn",
    ),
]

# ---- model / endpoint / local runtime ------------------------------------
_MODEL: List[Detector] = [
    Detector(
        "provider_endpoint", "model", "info",
        re.compile(rb"api\.(?:openai|anthropic|mistral|groq|together|cohere|deepseek|x)\.(?:com|ai)"),
        "LLM provider API endpoint",
    ),
    Detector(
        "model_name", "model", "info",
        # Long identifiers are distinctive enough on a word boundary. Short
        # o-series names (o1, o3) are not: two characters match random filler
        # in bulk, so they count only in a model context - a "model" field,
        # a model= assignment, or a quoted value on its own.
        re.compile(
            rb"(?<![A-Za-z0-9])(?:gpt-4[a-z0-9.\-]*|gpt-3\.5[a-z0-9.\-]*"
            rb"|claude-[a-z0-9.\-]+|llama-?[0-9][a-z0-9.\-]*"
            rb"|mistral-[a-z0-9.\-]+|gemini-[a-z0-9.\-]+"
            rb"|deepseek-[a-z0-9.\-]+|qwen[0-9][a-z0-9.\-]*)"
            rb"|(?:\"model\"\s*:\s*\"|\bmodel\s*[=:]\s*\"?|(?<=\")(?=o[13](?:-|\")))"
            rb"o[13](?:-(?:mini|preview|deep-research))?(?![A-Za-z0-9])"
        ),
        "Model identifier string",
    ),
    Detector(
        "gguf_magic", "model", "info",
        re.compile(rb"GGUF"),
        "GGUF model-file magic (llama.cpp/Ollama weights in memory)",
    ),
    Detector(
        "local_runtime", "model", "info",
        re.compile(rb"llama\.cpp|llama_model_loader|llama_new_context|n_ctx\b|ollama|lm-?studio|koboldcpp"),
        "Local inference runtime marker",
    ),
    Detector(
        "gguf_metadata", "model", "info",
        re.compile(
            rb"general\.(?:name|architecture|quantization_version)"
            rb"|tokenizer\.chat_template"
            rb"|tokenizer\.ggml\.(?:model|tokens|pre)"
            rb"|[a-z0-9_]+\.context_length"
            rb"|[a-z0-9_]+\.block_count"
            rb"|[a-z0-9_]+\.embedding_length"
        ),
        "GGUF model metadata key (llama.cpp/Ollama)",
    ),
]

ALL_DETECTORS: List[Detector] = _SECRETS + _PROMPTS + _MCP + _AGENT + _MODEL

CATEGORIES = ("secret", "prompt", "mcp", "agent", "model")


def detectors_for(categories: Optional[List[str]] = None) -> List[Detector]:
    if not categories:
        return list(ALL_DETECTORS)
    cats = set(categories)
    return [d for d in ALL_DETECTORS if d.category in cats]
