"""
Timeline reconstruction.

Recovered conversation blocks are split into individual *turns* (system / user /
assistant / tool, ReAct Thought-Action-Observation, Human/AI), then ordered.

Honest caveat: RAM has no timestamps. We order by heap offset, which is a decent
proxy for allocation order, and preserve within-block turn order. Each event
carries a confidence so an analyst knows how much to trust the sequence.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, asdict
from typing import Dict, List

from .recover import Conversation

# JSON  "role":"user","content":"..."
_JSON_TURN = re.compile(
    r'"role"\s*:\s*"(system|user|assistant|tool)"\s*,\s*"content"\s*:\s*"((?:[^"\\]|\\.){0,2000})"',
    re.S,
)
# ChatML  <|im_start|>role ... <|im_end|>
_CHATML = re.compile(r"<\|im_start\|>\s*(system|user|assistant)?\s*(.*?)(?:<\|im_end\|>|$)", re.S)
# transcript lines  Human:/Assistant:/System:/AI:
_TRANSCRIPT = re.compile(r"(?m)^(Human|Assistant|System|AI|User)\s*:\s*(.*)$")
# ReAct steps
_REACT = re.compile(r"(Thought|Action|Action Input|Observation|Final Answer)\s*:\s*(.+?)(?=(?:Thought|Action|Observation|Final Answer)\s*:|$)", re.S)

_KIND = {
    "system": ("system", "prompt"), "user": ("user", "prompt"), "human": ("user", "prompt"),
    "assistant": ("assistant", "reply"), "ai": ("assistant", "reply"),
    "tool": ("tool", "tool"), "observation": ("tool", "tool"),
    "thought": ("assistant", "reasoning"), "action": ("assistant", "tool-call"),
    "action input": ("assistant", "tool-call"), "final answer": ("assistant", "reply"),
}


@dataclass
class TimelineEvent:
    seq: int
    offset: int
    role: str
    kind: str
    text: str
    confidence: str   # high | medium | low

    def to_dict(self) -> Dict:
        return asdict(self)


def _clean(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()[:1000]


def _split_block(c: Conversation):
    """Yield (local_index, role_label, text, confidence) for turns in one block."""
    t = c.text
    found = False
    for i, m in enumerate(_JSON_TURN.finditer(t)):
        found = True
        yield i, m.group(1), m.group(2), "high"
    if found:
        return
    for i, m in enumerate(_CHATML.finditer(t)):
        seg = _clean(m.group(2))
        if seg:
            found = True
            yield i, (m.group(1) or "user"), seg, "high"
    if found:
        return
    tr = list(_TRANSCRIPT.finditer(t))
    if tr:
        for i, m in enumerate(tr):
            yield i, m.group(1), m.group(2), "medium"
        return
    rc = list(_REACT.finditer(t))
    if rc:
        for i, m in enumerate(rc):
            yield i, m.group(1), m.group(2), "medium"
        return
    # unknown: whole block as one low-confidence event
    yield 0, "unknown", t, "low"


def reconstruct(recovered: List[Conversation]) -> List[TimelineEvent]:
    staged = []  # (offset, local_index, role_label, text, conf)
    for c in recovered:
        for idx, label, text, conf in _split_block(c):
            staged.append((c.offset, idx, label, text, conf))
    staged.sort(key=lambda x: (x[0], x[1]))
    events: List[TimelineEvent] = []
    for seq, (offset, _idx, label, text, conf) in enumerate(staged):
        role, kind = _KIND.get(label.lower(), (label.lower(), "message"))
        events.append(TimelineEvent(
            seq=seq, offset=offset, role=role, kind=kind,
            text=_clean(text), confidence=conf,
        ))
    return events
