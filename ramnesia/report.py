"""Reporting: JSON for pipelines, coloured console for humans."""
from __future__ import annotations

import json
from typing import Dict, List

from .scanner import Finding, summarize

_SEV_COLOR = {"high": "\033[91m", "medium": "\033[93m", "info": "\033[90m"}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_ACCENT = "\033[96m"


def to_json(findings: List[Finding], source: str) -> str:
    payload = {
        "tool": "RAMnesia",
        "source": source,
        "summary": summarize(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2)


def to_console(findings: List[Finding], source: str, color: bool = True) -> str:
    def c(code: str, s: str) -> str:
        return f"{code}{s}{_RESET}" if color else s

    lines: List[str] = []
    lines.append(c(_ACCENT + _BOLD, "RAMnesia") + c(_BOLD, f"  —  AI/agent memory forensics"))
    lines.append(f"source: {source}")
    summ = summarize(findings)
    lines.append("")
    lines.append(c(_BOLD, f"{len(findings)} findings") + "   " +
                 "  ".join(f"{k}={v}" for k, v in sorted(summ['by_category'].items())))
    lines.append("")
    for f in findings:
        sev = _SEV_COLOR.get(f.severity, "") if color else ""
        tag = f"[{f.severity.upper():6}]"
        lines.append(f"{c(sev, tag)} {c(_BOLD, f.detector)}  @ 0x{f.offset:x}  ({f.category})")
        lines.append(f"        match : {f.match}")
        lines.append(f"        near  : {f.context}")
    if not findings:
        lines.append("  (no AI/agent artifacts found)")
    return "\n".join(lines)
