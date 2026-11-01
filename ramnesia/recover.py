"""
Conversation recovery.

Beyond flagging that a chat artifact exists, this carves the *readable block*
around it — the actual prompt / reply text sitting in the process heap. It
anchors on chat markers (role fields, ChatML/Llama templates, ReAct traces,
Human:/Assistant: turns) and expands outward across printable bytes to lift the
surrounding message, which is what makes RAMnesia a recovery tool and not just a
grep.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

# anchors that signal "a conversation lives here"
_ANCHORS = re.compile(
    rb'"role"\s*:\s*"(?:system|user|assistant|tool)"'
    rb'|<\|im_start\|>|<\|(?:user|assistant|system)\|>|\[/?INST\]|<<SYS>>'
    rb'|(?:Thought:|Action:|Observation:|Final Answer:)\s'
    rb'|(?:Human|Assistant|System|AI):\s'
    rb'|You are (?:a |an |the )?[A-Z]'
)

MAX_BLOCK = 4096          # bytes to expand each direction
MIN_BLOCK = 24           # ignore trivially short runs
DEFAULT_CHUNK = 8 * 1024 * 1024


def _is_text(byte: int) -> bool:
    return byte in (9, 10, 13) or 32 <= byte < 127


@dataclass
class Conversation:
    offset: int
    length: int
    text: str

    def to_dict(self) -> Dict:
        return asdict(self)


def recover_bytes(data: bytes, base_offset: int = 0,
                  max_block: int = MAX_BLOCK) -> List[Conversation]:
    out: List[Conversation] = []
    claimed_to = -1   # right edge of the last block, to avoid overlap spam
    for m in _ANCHORS.finditer(data):
        if m.start() <= claimed_to:
            continue
        # expand left
        lo = m.start()
        left_limit = max(0, m.start() - max_block)
        while lo > left_limit and _is_text(data[lo - 1]):
            lo -= 1
        # expand right
        hi = m.end()
        right_limit = min(len(data), m.end() + max_block)
        while hi < right_limit and _is_text(data[hi]):
            hi += 1
        block = data[lo:hi]
        if len(block) < MIN_BLOCK:
            continue
        text = block.decode("utf-8", "replace").strip()
        # collapse runs of control/space for readability
        text = re.sub(r"[ \t]{3,}", "  ", text)
        out.append(Conversation(offset=base_offset + lo, length=len(block), text=text))
        claimed_to = hi
    return out


def recover_file(path: str, max_block: int = MAX_BLOCK,
                 chunk_size: int = DEFAULT_CHUNK, progress=None) -> List[Conversation]:
    size = os.path.getsize(path)
    overlap = max_block * 2
    seen = set()
    out: List[Conversation] = []
    with open(path, "rb") as fh:
        pos = 0
        carry = b""
        while True:
            buf = fh.read(chunk_size)
            if not buf:
                break
            window = carry + buf
            window_base = pos - len(carry)
            for c in recover_bytes(window, base_offset=window_base, max_block=max_block):
                if c.offset in seen:
                    continue
                seen.add(c.offset)
                out.append(c)
            pos += len(buf)
            carry = window[-overlap:] if len(window) > overlap else window
            if progress:
                progress(min(pos, size), size)
    out.sort(key=lambda c: c.offset)
    return out
