# Changelog

All notable changes to RAMnesia are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/); versions follow SemVer.

## [0.5.0] - 2026-11-01
### Added
- **Detector governance.** Every detector now needs a positive and a negative
  fixture (`tests/detector_cases.py`), exercised through the real scanner. The
  detector set is locked in `tests/detectors.lock.json`; changing a pattern,
  severity or category, or adding or removing a detector, fails the suite until
  the lock is regenerated (`python tools/detector_lock.py --write`) and the new
  fingerprint is recorded in this file. The newest version here must equal the
  package version.
- A set fingerprint (SHA-256 over every detector's name, category, severity and
  pattern) in `ramnesia detectors`, the console report and the JSON report
  (`detector_set`, `version`), so a report names the patterns that produced it.
### Changed
- `system_prompt_opener` now matches an article followed by any wording
  ("You are a helpful assistant"); the old pattern needed a capital letter right
  after the article and missed the usual phrasing. On 231 MB of mixed text it
  gave 35 hits against 10, about 5 of them licence or package-manager prose.
  Severity stays `info`.

Detector set `6828740618885117` (26 detectors). Previous set `4d04c4e265ff92b7`.

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
