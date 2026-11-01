# Changelog

All notable changes to RAMnesia are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow SemVer.

## [0.4.0] - 2026-10-24
### Added
- **Timeline reconstruction** (`ramnesia timeline`): splits recovered blocks into
  turns (system/user/assistant/tool, ReAct, Human/AI) and orders them by heap
  offset with a per-event confidence.
- **llama.cpp / Ollama recovery** (`ramnesia llama`): extracts GGUF metadata
  (model name, architecture, context length, `tokenizer.chat_template`) and the
  context text buffer near the runtime.
- GGUF-metadata detector.
- HTML report now renders the reconstructed timeline.
- Packaging: LICENSE, CHANGELOG, CI workflow, `.gitignore`, PyPI metadata.

## [0.3.0] - 2026-10-24
### Added
- Detectors expanded to 25 (Hugging Face / GCP / PEM keys, `*_API_KEY=` env
  assignments, ReAct + agent-framework traces, Human/AI turns, GGUF/Ollama).
- Conversation recovery (`ramnesia recover`): carves readable prompt/reply blocks.
- Self-contained HTML report (`--html`) with redaction + blur toggle.

## [0.2.0] - 2026-10-24
### Added
- Live Linux process scanning (`ramnesia live <pid>`) via `/proc/<pid>/mem`.
- Shannon-entropy filter (`--min-entropy`) to cut secret false positives.

## [0.1.0] - 2026-10-24
### Added
- Core detector engine, overlap-safe chunk scanner, JSON + console reports.
- `ramnesia scan`, `ramnesia detectors`.
- Volatility 3 plugin scaffold.
- Synthetic-dump generator and test suite.
