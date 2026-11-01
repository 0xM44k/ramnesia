# RAMnesia v0.4.0

**Carve AI/agent artifacts out of memory.** First public release.

RAMnesia scans a memory dump — or, on Linux, a live process via `/proc` — and
recovers the traces an LLM agent leaves in RAM: prompts, API keys/tokens, MCP
tool-call traffic, model/endpoint strings, and whole conversations. To my
knowledge it's the first tool that treats **the AI agent itself as the forensic
subject** rather than pointing an LLM at forensic output.

## Highlights
- **25 detectors** across 5 categories — `secret` (Anthropic/OpenAI/AWS/GCP/HF/
  GitHub/Slack keys, JWTs, bearer tokens, PEM keys, `*_API_KEY=` env vars),
  `prompt`, `mcp` (JSON-RPC `tools/call` etc.), `agent` (ReAct traces, LangChain/
  CrewAI/AutoGen, Human/AI turns), `model` (endpoints, model names, GGUF/Ollama).
- **Conversation recovery** (`ramnesia recover`) — lifts full readable prompt/
  reply blocks out of the heap, not just single matches.
- **Timeline reconstruction** (`ramnesia timeline`) — splits blocks into ordered
  turns (system/user/assistant/tool, ReAct) with per-event confidence.
- **llama.cpp / Ollama recovery** (`ramnesia llama`) — GGUF metadata
  (model name, architecture, `tokenizer.chat_template`, context length) + context
  text near the runtime.
- **Live Linux scanning** (`ramnesia live <pid>`) — no image needed.
- **Volatility 3 plugin** — scan every process in a full memory image.
- **Shareable HTML report** (`--html`) — findings + timeline + recovered chats,
  secrets redacted, secret context withheld from the file, text blurred by default.
- **Entropy filter** (`--min-entropy`) to cut secret false positives.

## Install
```bash
pip install -e .            # core (stdlib only)
pip install -e .[volatility]  # + Volatility 3 plugin
```

## Quick start
```bash
python samples/make_sample.py sample_dump.bin
ramnesia scan sample_dump.bin --recover --html report.html
ramnesia timeline sample_dump.bin
sudo ramnesia live <PID>    # Linux: scan a running agent/Ollama/python process
```

## Honest limits
- Timelines order by **heap offset** (allocation-order proxy) — RAM has no
  timestamps; each turn carries a confidence.
- The raw **KV-cache is numeric tensors**, so `llama` recovers the context text
  and GGUF metadata, not the KV tensors themselves.
- Pre-1.0: detector set and APIs may change between minor versions.

## Verified
14/14 tests pass (reproduced 2026-10-28). On synthetic dumps generated in that pass: 37 findings across 5 categories (secret 10, prompt 6, mcp 3, agent 6, model 12, reproduced on three dumps), a 9-turn reconstructed timeline, and GGUF metadata and context recovered. The 58-finding figure in the original notes did not reproduce and is withdrawn. RAMnesia was written by Maak (https://github.com/0xM44k).

**Authorized use only** — see `SECURITY.md`. MIT licensed.