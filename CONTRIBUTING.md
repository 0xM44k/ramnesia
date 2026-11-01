# Contributing to RAMnesia

Thanks for your interest! RAMnesia is a focused, dependency-light tool — the
core engine is standard-library only, and contributions should keep it that way
where possible.

## Dev setup
```bash
git clone https://github.com/0xM44k/ramnesia
cd ramnesia
pip install -e .[dev]
pytest -q
```

## Adding a detector
Detectors live in `ramnesia/patterns.py`. Add a `Detector(name, category,
severity, pattern, description, redact=None)`:
- use **bounded** byte-regex quantifiers (`{20,120}`, not `+`) to avoid
  catastrophic backtracking on garbage memory,
- set `category` to one of `secret | prompt | mcp | agent | model`,
- give secrets a `redact` function so values never print in full,
- add a planted example to `samples/make_sample.py` and assert it in `tests/`.

## Conventions
- Keep the core free of third-party deps (Volatility is an optional extra).
- Every new command/flag gets a line in `README.md` and `CHANGELOG.md`.
- Run `pytest -q` before opening a PR; CI runs it on 3.10–3.12.

## Scope
RAMnesia is a defensive forensics tool. Contributions that turn it toward
unauthorised data extraction won't be accepted — see `SECURITY.md`.
