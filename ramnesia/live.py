"""
Live process memory scanning on Linux via /proc/<pid>/maps + /proc/<pid>/mem.

This is the quickest way to test RAMnesia on *real* memory: point it at a
running AI/agent process (an Ollama server, a python LLM client, your MCP
gateway) and it carves artifacts out of its live address space — no full
memory image or Volatility needed.

Requires Linux and permission to read the target's memory:
  * run as the same user as the target, OR as root (sudo), AND
  * ptrace scope must allow it: `cat /proc/sys/kernel/yama/ptrace_scope`
    (0 = allowed for same-user; otherwise use sudo).

Not available on Windows/macOS (no /proc) — the CLI reports that cleanly.
"""
from __future__ import annotations

import os
import sys
from typing import List, Optional

from .patterns import Detector, detectors_for
from .scanner import Finding, scan_bytes

# cap any single region read so a giant mapping can't exhaust memory
MAX_REGION = 256 * 1024 * 1024
READ_CHUNK = 8 * 1024 * 1024


def available() -> bool:
    return sys.platform.startswith("linux") and os.path.isdir("/proc")


def _parse_maps(pid: int):
    """Yield (start, end, perms, path) for readable, non-file-backed-noise regions."""
    with open(f"/proc/{pid}/maps", "r") as fh:
        for line in fh:
            parts = line.split()
            if len(parts) < 5:
                continue
            addrs, perms = parts[0], parts[1]
            path = parts[5] if len(parts) >= 6 else ""
            if "r" not in perms:
                continue
            # skip obvious device/special mappings
            if path in ("[vvar]", "[vdso]", "[vsyscall]"):
                continue
            lo_s, hi_s = addrs.split("-")
            yield int(lo_s, 16), int(hi_s, 16), perms, path


def scan_pid(
    pid: int,
    categories: Optional[List[str]] = None,
    min_entropy: Optional[float] = None,
    context: int = 48,
    max_findings: Optional[int] = None,
    heap_stack_only: bool = False,
    progress=None,
) -> List[Finding]:
    if not available():
        raise RuntimeError("live scanning requires Linux with /proc")
    dets = detectors_for(categories)
    regions = list(_parse_maps(pid))
    if heap_stack_only:
        regions = [r for r in regions if r[3] in ("[heap]", "[stack]", "")]
    findings: List[Finding] = []
    seen = set()
    total = len(regions)
    with open(f"/proc/{pid}/mem", "rb", 0) as mem:
        for idx, (lo, hi, _perms, _path) in enumerate(regions):
            size = min(hi - lo, MAX_REGION)
            read = 0
            while read < size:
                take = min(READ_CHUNK, size - read)
                try:
                    mem.seek(lo + read)
                    data = mem.read(take)
                except (OSError, ValueError, OverflowError):
                    break
                if not data:
                    break
                for f in scan_bytes(data, dets, base_offset=lo + read,
                                    context=context, min_entropy=min_entropy):
                    key = (f.detector, f.offset)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(f)
                    if max_findings and len(findings) >= max_findings:
                        return findings
                read += take
            if progress:
                progress(idx + 1, total)
    findings.sort(key=lambda f: f.offset)
    return findings
