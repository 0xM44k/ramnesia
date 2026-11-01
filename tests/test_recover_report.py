"""Tests for v0.3: new detectors, conversation recovery, HTML safety."""
from __future__ import annotations

from ramnesia.scanner import scan_bytes
from ramnesia.recover import recover_bytes
from ramnesia.report_html import html_report
from samples.make_sample import PLANTS


def _blob() -> bytes:
    import os
    parts = []
    for p in PLANTS:
        parts.append(os.urandom(512))
        parts.append(b"\x00" + p + b"\x00")
    return b"".join(parts)


def test_new_detectors_fire():
    names = {f.detector for f in scan_bytes(_blob())}
    for expected in ("huggingface_token", "llm_env_key", "react_trace",
                     "local_runtime", "gguf_magic", "conversation_turn"):
        assert expected in names, f"missing {expected}: got {sorted(names)}"


def test_env_key_redacted_keeps_name():
    findings = [f for f in scan_bytes(_blob()) if f.detector == "llm_env_key"]
    assert findings
    m = findings[0].match
    assert "API_KEY=" in m and "..." in m          # name visible, value masked
    assert "anotherFAKEkey" not in m                # real value not leaked


def test_recovery_lifts_conversation_text():
    convs = recover_bytes(_blob())
    joined = " ".join(c.text for c in convs)
    assert "scan this host" in joined or "helpful security assistant" in joined
    assert "Observation" in joined or "Thought" in joined


def test_html_does_not_leak_secret_context():
    findings = scan_bytes(_blob())
    out = html_report(findings, "unit-test", recovered=recover_bytes(_blob()))
    assert "<table" in out and "RAMnesia" in out
    # a secret's raw surrounding context must not be embedded in the HTML
    assert "sk-ant-api03-anotherFAKEkey" not in out
    assert "hidden (secret)" in out
