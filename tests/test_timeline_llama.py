"""Tests for v0.4: timeline reconstruction and llama.cpp/GGUF recovery."""
from __future__ import annotations

from ramnesia.recover import recover_bytes
from ramnesia.timeline import reconstruct
from ramnesia.llamacpp import recover_bytes_llama
from samples.make_sample import PLANTS


def _blob() -> bytes:
    import os
    parts = []
    for p in PLANTS:
        parts.append(os.urandom(400))
        parts.append(b"\x00" + p + b"\x00")
    return b"".join(parts)


def test_timeline_orders_and_classifies():
    events = reconstruct(recover_bytes(_blob()))
    assert events, "no timeline events"
    # seq is monotonic and offsets are non-decreasing (heap-order proxy)
    assert [e.seq for e in events] == sorted(e.seq for e in events)
    offs = [e.offset for e in events]
    assert offs == sorted(offs)
    roles = {e.role for e in events}
    assert "user" in roles and ("assistant" in roles or "system" in roles)


def test_timeline_splits_json_messages():
    events = reconstruct(recover_bytes(_blob()))
    texts = " ".join(e.text for e in events)
    assert "scan this host" in texts        # the user turn from the gpt-4o block
    assert "helpful security assistant" in texts  # the system turn


def test_llama_extracts_gguf_metadata():
    rec = recover_bytes_llama(_blob())
    keys = {m.key for m in rec.metadata}
    assert "general.name" in keys, keys
    name = [m.value for m in rec.metadata if m.key == "general.name"][0]
    assert "Llama" in name
    assert any(k.endswith("context_length") for k in keys)


def test_llama_context_near_runtime():
    rec = recover_bytes_llama(_blob())
    assert rec.context, "no context blocks recovered near runtime markers"
