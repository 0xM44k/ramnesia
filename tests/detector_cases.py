"""One set of positive and negative fixtures per detector.

Governance rule: every detector in ramnesia.patterns.ALL_DETECTORS must have at
least one POSITIVE (must fire) and one NEGATIVE (must not fire) case here.
tests/test_governance.py enforces this, so adding a detector without fixtures
fails the suite.

Secret-shaped strings are assembled at import time from fragments so that no
token-like literal sits in the repository (secret scanners would flag it).
"""
A36 = b"A" * 36

POSITIVE = {
    "anthropic_api_key": [b"sk-ant-" + b"api03-" + b"Q" * 30],
    "openai_api_key": [b"sk-" + b"Q" * 40, b"sk-proj-" + b"Q" * 40],
    "aws_access_key_id": [b"AKIA" + b"IOSFODNN7EXAMPLE"],
    "google_api_key": [b"AIza" + b"Q" * 35],
    "github_token": [b"gh" + b"p_" + A36, b"gh" + b"s_" + A36],
    "slack_token": [b"xox" + b"b-" + b"1234567890-abcdefghij"],
    "jwt": [b"eyJ" + b"hbGciOiJIUzI1NiJ9." + b"eyJzdWIiOiIxMjM0NTYifQ." + b"abcdefghijKLMNOP"],
    "bearer_token": [b"Authorization: Bearer " + b"Q" * 30],
    "huggingface_token": [b"hf" + b"_" + b"Q" * 34],
    "gcp_service_account": [b'{"type": "service_account", "project_id": "p"}', b'"type":"service_account"'],
    "private_key_pem": [b"-----BEGIN RSA PRIVATE KEY-----", b"-----BEGIN PRIVATE KEY-----", b"-----BEGIN OPENSSH PRIVATE KEY-----"],
    "llm_env_key": [b"ANTHROPIC_API" + b"_KEY=" + b"Q" * 20, b"export OPENAI_API" + b"_KEY = " + b"Q" * 20],
    "chat_role_json": [b'{"role": "user", "content": "hi"}', b'"role":"assistant"'],
    "chat_template_marker": [b"<|im_start|>system", b"[INST] hello [/INST]", b"<<SYS>>"],
    "system_prompt_opener": [b"You are a helpful assistant", b"You are the Security Analyst"],
    "mcp_method": [b'{"method": "tools/call"}', b'"method":"notifications/initialized"'],
    "jsonrpc_envelope": [b'{"jsonrpc": "2.0", "id": 1}'],
    "mcp_tool_name": [b'"name": "read_file"', b'"toolName":"search-web"'],
    "react_trace": [b"Thought: I should look\n", b"Action Input: ls\n", b"Final Answer: done"],
    "agent_framework": [b"import langchain_core", b"CrewAgentExecutor", b"llama_index"],
    "conversation_turn": [b"Human: hello", b"Assistant: hi there"],
    "provider_endpoint": [b"https://api.openai.com/v1", b"api.anthropic.com", b"api.x.ai"],
    "model_name": [b"gpt-4o", b"claude-sonnet-4-5", b'"model": "o1-mini"', b"model=o3", b"deepseek-r1"],
    "gguf_magic": [b"GGUF\x03\x00\x00\x00"],
    "local_runtime": [b"llama.cpp", b"ollama serve", b"llama_model_loader: loaded"],
    "gguf_metadata": [b"general.architecture", b"llama.context_length", b"tokenizer.chat_template"],
}

NEGATIVE = {
    "anthropic_api_key": [b"sk-ant-short", b"ant-api03-" + b"Q" * 30],
    "openai_api_key": [b"sk-ant-" + b"api03-" + b"Q" * 30, b"sk-short", b"task-" + b"Q" * 5],
    "aws_access_key_id": [b"AKIA" + b"Q" * 15, b"akia" + b"IOSFODNN7EXAMPLE", b"ASIA" + b"IOSFODNN7EXAMPLE", b"AKIA" + b"IOSFODNN7EXAMPL" + b"e"],
    "google_api_key": [b"AIza" + b"Q" * 10, b"aiza" + b"Q" * 35],
    "github_token": [b"gh" + b"p_" + b"A" * 10, b"gh" + b"x_" + A36],
    "slack_token": [b"xox" + b"z-" + b"1234567890-abcdefghij", b"xox" + b"b-abc"],
    "jwt": [b"eyJ" + b"abc.def", b"notajwt.eyJ", b"eyJ" + b"short.short.short"],
    "bearer_token": [b"bearer of bad news", b"Bearer short"],
    "huggingface_token": [b"hf" + b"_short", b"shf" + b"x" * 40],
    "gcp_service_account": [b'{"type": "authorized_user"}', b'"type": "serviceaccount"'],
    "private_key_pem": [b"-----BEGIN PUBLIC KEY-----", b"-----BEGIN CERTIFICATE-----"],
    "llm_env_key": [b"ANTHROPIC_API" + b"_KEY=", b"ANTHROPIC_API" + b"_KEY=abc", b"SOME_API" + b"_KEY=" + b"Q" * 20],
    "chat_role_json": [b'{"role": "admin"}', b'"roles": ["user"]'],
    "chat_template_marker": [b"<|im_stop|>", b"[INSTALL]", b"[INSTRUCTION]"],
    "system_prompt_opener": [b"You are here", b"you are a helper", b"You are 5 years old"],
    "mcp_method": [b'{"method": "GET"}', b'"method": "tools/other"'],
    "jsonrpc_envelope": [b'{"jsonrpc": "1.0"}', b'"jsonrpc"'],
    "mcp_tool_name": [b'"name": "Read"', b'"name": "ab"', b'"name": "has space"'],
    "react_trace": [b"Thoughtful: yes", b"Action:", b"Observations are noted"],
    "agent_framework": [b"language chain", b"auto gen"],
    "conversation_turn": [b"Humane: no", b"Assistants: many", b"Human:"],
    "provider_endpoint": [b"api.example.com", b"openai.com/docs", b"api.openai.org"],
    "model_name": [b"ratio 3 o1 and o3 done", b"xo1y xo3y", b"xgpt-4", b"claude"],
    "gguf_magic": [b"gguf", b"GGUe", b"GGU"],
    "local_runtime": [b"llama", b"n_ctxt", b"cola"],
    "gguf_metadata": [b"general.public", b"context_length", b"tokenizer.other"],
}
