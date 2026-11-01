"""
llama.cpp / Ollama context recovery.

What's actually recoverable from a local-inference process's memory:
  * GGUF model metadata the loader keeps resident — model name, architecture,
    context length, and (gold) the tokenizer.chat_template string
  * the prompt / context text buffer sitting near the runtime

Honest note: the raw KV-cache is numeric key/value tensors, not tokens, so you
can't read the prompt straight out of it. What RAMnesia recovers is the context
*text* buffer and the GGUF metadata, which together reconstruct what the model
was loaded with and what it was asked — the forensically useful part.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, asdict, field
from typing import Dict, List

from .recover import Conversation, recover_bytes

_RUNTIME = re.compile(rb"llama\.cpp|llama_model_loader|llama_new_context|ollama|koboldcpp|lm-?studio|GGUF")
_GGUF_KEY = re.compile(
    rb"(general\.(?:name|architecture|quantization_version)"
    rb"|tokenizer\.chat_template"
    rb"|tokenizer\.ggml\.model"
    rb"|[a-z0-9_]+\.context_length"
    rb"|[a-z0-9_]+\.block_count"
    rb"|[a-z0-9_]+\.embedding_length)"
)
NEAR = 64 * 1024          # a context block counts as "llama" if within this of a marker
VALUE_WINDOW = 4096       # how far after a key to look for its value
DEFAULT_CHUNK = 8 * 1024 * 1024


@dataclass
class GgufMeta:
    key: str
    value: str
    offset: int

    def to_dict(self) -> Dict:
        return asdict(self)


@dataclass
class LlamaRecovery:
    metadata: List[GgufMeta] = field(default_factory=list)
    context: List[Conversation] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {"metadata": [m.to_dict() for m in self.metadata],
                "context": [c.to_dict() for c in self.context]}


def _printable_run(data: bytes, start: int, limit: int) -> str:
    out = bytearray()
    i = start
    end = min(len(data), start + limit)
    while i < end:
        b = data[i]
        if b in (9, 10, 13) or 32 <= b < 127:
            out.append(b)
        elif out:
            break
        i += 1
    return out.decode("utf-8", "replace").strip()


def extract_metadata(data: bytes, base_offset: int = 0) -> List[GgufMeta]:
    out: List[GgufMeta] = []
    seen = set()
    for m in _GGUF_KEY.finditer(data):
        key = m.group(1).decode("latin-1")
        # value usually follows after a short length/type gap; grab next printable run
        val = _printable_run(data, m.end(), VALUE_WINDOW)
        # strip the key itself if it bled into the run
        if val.startswith(key):
            val = val[len(key):].strip()
        val = val[:600]
        k = (key, base_offset + m.start())
        if k in seen:
            continue
        seen.add(k)
        out.append(GgufMeta(key=key, value=val, offset=base_offset + m.start()))
    return out


def recover_bytes_llama(data: bytes, base_offset: int = 0) -> LlamaRecovery:
    markers = [m.start() for m in _RUNTIME.finditer(data)]
    meta = extract_metadata(data, base_offset)
    context: List[Conversation] = []
    if markers:
        for c in recover_bytes(data):
            local = c.offset  # recover_bytes called with base 0 here
            if any(abs(local - mk) <= NEAR for mk in markers):
                context.append(Conversation(offset=base_offset + c.offset, length=c.length, text=c.text))
    return LlamaRecovery(metadata=meta, context=context)


def recover_file_llama(path: str, chunk_size: int = DEFAULT_CHUNK, progress=None) -> LlamaRecovery:
    size = os.path.getsize(path)
    overlap = NEAR + VALUE_WINDOW
    agg = LlamaRecovery()
    seen_meta, seen_ctx = set(), set()
    with open(path, "rb") as fh:
        pos, carry = 0, b""
        while True:
            buf = fh.read(chunk_size)
            if not buf:
                break
            window = carry + buf
            base = pos - len(carry)
            r = recover_bytes_llama(window, base_offset=base)
            for m in r.metadata:
                if (m.key, m.offset) not in seen_meta:
                    seen_meta.add((m.key, m.offset)); agg.metadata.append(m)
            for c in r.context:
                if c.offset not in seen_ctx:
                    seen_ctx.add(c.offset); agg.context.append(c)
            pos += len(buf)
            carry = window[-overlap:] if len(window) > overlap else window
            if progress:
                progress(min(pos, size), size)
    agg.metadata.sort(key=lambda m: m.offset)
    agg.context.sort(key=lambda c: c.offset)
    return agg
