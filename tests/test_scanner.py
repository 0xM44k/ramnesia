"""Tests: plant known artifacts in noise, assert the engine finds them all
and that secrets come back redacted (never leaked verbatim in output)."""
from __future__ import annotations

import os

from ramnesia.scanner import scan_bytes, scan_file
from samples.make_sample import PLANTS, make


def _blob() -> bytes:
    import os as _os
    parts = []
    for p in PLANTS:
        parts.append(_os.urandom(1024))
        parts.append(b"\x00" + p + b"\x00")
    return b"".join(parts)


def test_detects_each_category():
    findings = scan_bytes(_blob())
    cats = {f.category for f in findings}
    assert {"secret", "prompt", "mcp", "model"} <= cats, cats


def test_specific_detectors_fire():
    findings = scan_bytes(_blob())
    names = {f.detector for f in findings}
    for expected in ("anthropic_api_key", "openai_api_key", "aws_access_key_id",
                     "jwt", "chat_role_json", "mcp_method", "provider_endpoint",
                     "model_name", "chat_template_marker"):
        assert expected in names, f"missing detector: {expected} (got {sorted(names)})"


def test_secrets_are_redacted():
    findings = scan_bytes(_blob())
    # the real Anthropic test key body must never appear verbatim in output
    leaked = [f for f in findings if "fake-anthropic-key" in f.match]
    assert not leaked, "a secret was emitted un-redacted"
    secrets = [f for f in findings if f.category == "secret"]
    assert secrets and all(f.redacted for f in secrets)


def test_offsets_are_real(tmp_path):
    path = os.path.join(tmp_path, "d.bin")
    make(path, noise_kb=128)
    findings = scan_file(path)
    assert findings
    with open(path, "rb") as fh:
        raw = fh.read()
    # every reported offset should land inside the file
    assert all(0 <= f.offset < len(raw) for f in findings)


def test_short_model_names_need_context():
    # o1/o3 standing in prose or noise are not model evidence.
    assert not [f for f in scan_bytes(b"ratio 3 o1 and o3 done") if f.detector == "model_name"]
    assert not [f for f in scan_bytes(b"xo1y xo3y") if f.detector == "model_name"]
    # In a model field they are.
    hits = scan_bytes(b'{"model": "o1-mini", "messages": []} model=o3')
    assert [f for f in hits if f.detector == "model_name"], hits


def test_clean_random_dump_has_no_model_name_findings():
    import random
    noise = random.Random(20261028).randbytes(256 * 1024)
    hits = [f for f in scan_bytes(noise) if f.detector == "model_name"]
    assert hits == [], [(f.match, f.offset) for f in hits[:5]]
