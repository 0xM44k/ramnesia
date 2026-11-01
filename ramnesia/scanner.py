"""
Core scanning engine.

Scans raw bytes (a memory dump file, or memory handed in by the Volatility
plugin) for the detectors in patterns.py. Works in overlapping chunks so a
match straddling a chunk boundary is not missed, and de-duplicates by
(detector, absolute offset).
"""
from __future__ import annotations

import math
import os
from collections import Counter
from dataclasses import dataclass, asdict
from typing import Dict, Iterable, Iterator, List, Optional

from .patterns import Detector, detectors_for

DEFAULT_CHUNK = 8 * 1024 * 1024      # 8 MiB
MAX_MATCH_LEN = 4096                  # overlap guard; longest match we expect
CONTEXT = 48                         # bytes of context each side


def shannon_entropy(b: bytes) -> float:
    """Bits-per-byte Shannon entropy. Real keys/tokens score high (~4-6);
    repetitive dictionary words and structured JSON score low. Used to drop
    low-entropy false positives from secret detectors."""
    if not b:
        return 0.0
    counts = Counter(b)
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@dataclass
class Finding:
    detector: str
    category: str
    severity: str
    offset: int
    match: str          # decoded (redacted if sensitive)
    context: str        # printable surrounding bytes
    redacted: bool

    def to_dict(self) -> Dict:
        return asdict(self)


def _printable(b: bytes) -> str:
    return "".join(chr(c) if 32 <= c < 127 else "." for c in b)


def scan_bytes(
    data: bytes,
    detectors: Optional[List[Detector]] = None,
    base_offset: int = 0,
    context: int = CONTEXT,
    min_entropy: Optional[float] = None,
) -> List[Finding]:
    """Scan an in-memory buffer. base_offset lets the Volatility plugin report
    real virtual addresses. min_entropy (bits/byte) drops low-entropy secret
    matches as likely false positives."""
    dets = detectors or detectors_for()
    out: List[Finding] = []
    for det in dets:
        for m in det.pattern.finditer(data):
            raw = m.group(0)
            if min_entropy and det.category == "secret" and shannon_entropy(raw) < min_entropy:
                continue
            redacted = False
            shown = raw
            if det.redact is not None:
                shown = det.redact(raw)
                redacted = True
            lo = max(0, m.start() - context)
            hi = min(len(data), m.end() + context)
            out.append(Finding(
                detector=det.name,
                category=det.category,
                severity=det.severity,
                offset=base_offset + m.start(),
                match=shown.decode("latin-1", "replace"),
                context=_printable(data[lo:hi]),
                redacted=redacted,
            ))
    return out


def scan_file(
    path: str,
    categories: Optional[List[str]] = None,
    chunk_size: int = DEFAULT_CHUNK,
    context: int = CONTEXT,
    max_findings: Optional[int] = None,
    min_entropy: Optional[float] = None,
    progress=None,
) -> List[Finding]:
    """Stream a dump file through the scanner with overlapping windows."""
    dets = detectors_for(categories)
    size = os.path.getsize(path)
    seen = set()
    findings: List[Finding] = []
    overlap = MAX_MATCH_LEN
    with open(path, "rb") as fh:
        pos = 0
        carry = b""
        while True:
            buf = fh.read(chunk_size)
            if not buf:
                break
            window = carry + buf
            window_base = pos - len(carry)
            for f in scan_bytes(window, dets, base_offset=window_base, context=context, min_entropy=min_entropy):
                key = (f.detector, f.offset)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(f)
                if max_findings and len(findings) >= max_findings:
                    return findings
            pos += len(buf)
            carry = window[-overlap:] if len(window) > overlap else window
            if progress:
                progress(min(pos, size), size)
    findings.sort(key=lambda f: f.offset)
    return findings


def summarize(findings: Iterable[Finding]) -> Dict[str, Dict[str, int]]:
    """Counts by category and by detector."""
    by_cat: Dict[str, int] = {}
    by_det: Dict[str, int] = {}
    for f in findings:
        by_cat[f.category] = by_cat.get(f.category, 0) + 1
        by_det[f.detector] = by_det.get(f.detector, 0) + 1
    return {"by_category": by_cat, "by_detector": by_det}
