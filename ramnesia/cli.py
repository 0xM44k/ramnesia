"""
RAMnesia command line.

  python -m ramnesia.cli scan dump.raw
  python -m ramnesia.cli scan dump.raw --only secret,mcp --json out.json
  python -m ramnesia.cli detectors
"""
from __future__ import annotations

import argparse
import sys

from . import __version__
from .patterns import ALL_DETECTORS, CATEGORIES
from .report import to_console, to_json
from .report_html import html_report
from .recover import recover_file
from .scanner import scan_file
from .timeline import reconstruct
from .llamacpp import recover_file_llama


def _progress(done: int, total: int) -> None:
    pct = (done / total * 100) if total else 100
    sys.stderr.write(f"\rscanning... {pct:5.1f}%")
    sys.stderr.flush()
    if done >= total:
        sys.stderr.write("\r" + " " * 24 + "\r")


def cmd_scan(args: argparse.Namespace) -> int:
    cats = args.only.split(",") if args.only else None
    if cats:
        bad = [c for c in cats if c not in CATEGORIES]
        if bad:
            print(f"unknown category: {', '.join(bad)} (valid: {', '.join(CATEGORIES)})", file=sys.stderr)
            return 2
    findings = scan_file(
        args.dump,
        categories=cats,
        context=args.context,
        max_findings=args.max,
        min_entropy=args.min_entropy,
        progress=None if args.quiet else _progress,
    )
    recovered = recover_file(args.dump) if args.recover else []
    tline = reconstruct(recovered) if recovered else []
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(html_report(findings, args.dump, recovered, tline))
        print(f"wrote {args.html}", file=sys.stderr)
    if args.json:
        data = to_json(findings, args.dump)
        if args.json == "-":
            print(data)
        else:
            with open(args.json, "w", encoding="utf-8") as fh:
                fh.write(data)
            print(f"wrote {args.json} ({len(findings)} findings)", file=sys.stderr)
    if not args.json:
        print(to_console(findings, args.dump, color=not args.no_color))
        if args.recover:
            print(f"\nrecovered conversations: {len(recovered)}")
            for c in recovered[:5]:
                snippet = c.text[:200].replace("\n", " ")
                print(f"  @ 0x{c.offset:x}  {snippet}")
    return 1 if any(f.severity == "high" for f in findings) else 0


def cmd_recover(args: argparse.Namespace) -> int:
    recovered = recover_file(args.dump, max_block=args.max_block,
                             progress=None if args.quiet else _progress)
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(html_report([], args.dump, recovered))
        print(f"wrote {args.html}", file=sys.stderr)
    if args.json:
        import json as _json
        data = _json.dumps({"tool": "RAMnesia", "source": args.dump,
                            "recovered": [c.to_dict() for c in recovered]}, indent=2)
        if args.json == "-":
            print(data)
        else:
            with open(args.json, "w", encoding="utf-8") as fh:
                fh.write(data)
            print(f"wrote {args.json} ({len(recovered)} blocks)", file=sys.stderr)
    if not args.json:
        print(f"recovered {len(recovered)} conversation block(s) from {args.dump}\n")
        for c in recovered:
            print(f"--- 0x{c.offset:x}  ({c.length}B) ---")
            print(c.text[:600])
            print()
    return 0


def cmd_live(args: argparse.Namespace) -> int:
    from . import live as livemod
    if not livemod.available():
        print("live scanning requires Linux with /proc (not available here)", file=sys.stderr)
        return 2
    cats = args.only.split(",") if args.only else None
    try:
        findings = livemod.scan_pid(
            args.pid,
            categories=cats,
            min_entropy=args.min_entropy,
            context=args.context,
            max_findings=args.max,
            heap_stack_only=args.heap_stack,
            progress=None if args.quiet else _progress,
        )
    except PermissionError:
        print(f"permission denied reading PID {args.pid} — run with sudo, or check "
              f"/proc/sys/kernel/yama/ptrace_scope", file=sys.stderr)
        return 2
    except FileNotFoundError:
        print(f"no such process: {args.pid}", file=sys.stderr)
        return 2
    src = f"pid:{args.pid}"
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(html_report(findings, src, []))
        print(f"wrote {args.html}", file=sys.stderr)
    if args.json:
        data = to_json(findings, src)
        if args.json == "-":
            print(data)
        else:
            with open(args.json, "w", encoding="utf-8") as fh:
                fh.write(data)
            print(f"wrote {args.json} ({len(findings)} findings)", file=sys.stderr)
    else:
        print(to_console(findings, src, color=not args.no_color))
    return 1 if any(f.severity == "high" for f in findings) else 0


def cmd_timeline(args: argparse.Namespace) -> int:
    recovered = recover_file(args.dump, progress=None if args.quiet else _progress)
    events = reconstruct(recovered)
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(html_report([], args.dump, recovered, events))
        print(f"wrote {args.html}", file=sys.stderr)
    if args.json:
        import json as _json
        data = _json.dumps({"tool": "RAMnesia", "source": args.dump,
                            "timeline": [e.to_dict() for e in events]}, indent=2)
        if args.json == "-":
            print(data)
        else:
            with open(args.json, "w", encoding="utf-8") as fh:
                fh.write(data)
            print(f"wrote {args.json} ({len(events)} events)", file=sys.stderr)
    if not args.json:
        print(f"reconstructed {len(events)} turn(s) (ordered by heap offset)\n")
        for e in events:
            print(f"#{e.seq:<3} {e.role:>9} | {e.kind:<10} 0x{e.offset:x} [{e.confidence}]")
            print(f"       {e.text[:180]}")
    return 0


def cmd_llama(args: argparse.Namespace) -> int:
    rec = recover_file_llama(args.dump, progress=None if args.quiet else _progress)
    if args.json:
        import json as _json
        data = _json.dumps({"tool": "RAMnesia", "source": args.dump, **rec.to_dict()}, indent=2)
        if args.json == "-":
            print(data)
        else:
            with open(args.json, "w", encoding="utf-8") as fh:
                fh.write(data)
            print(f"wrote {args.json}", file=sys.stderr)
        return 0
    print(f"GGUF metadata ({len(rec.metadata)}):")
    for m in rec.metadata:
        print(f"  {m.key:28} = {m.value[:120]}   @ 0x{m.offset:x}")
    print(f"\ncontext blocks near runtime ({len(rec.context)}):")
    for c in rec.context:
        print(f"  @ 0x{c.offset:x}  {c.text[:160]}")
    return 0


def cmd_detectors(_args: argparse.Namespace) -> int:
    for d in ALL_DETECTORS:
        print(f"{d.category:7} {d.severity:6} {d.name:22} {d.description}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ramnesia", description="Carve AI/agent artifacts out of memory.")
    p.add_argument("--version", action="version", version=f"RAMnesia {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="scan a memory dump file")
    s.add_argument("dump", help="path to a raw memory dump / process dump")
    s.add_argument("--only", help=f"comma list of categories: {', '.join(CATEGORIES)}")
    s.add_argument("--json", metavar="PATH", help="write JSON report ('-' for stdout)")
    s.add_argument("--context", type=int, default=48, help="context bytes each side (default 48)")
    s.add_argument("--max", type=int, default=None, help="stop after N findings")
    s.add_argument("--min-entropy", type=float, default=None,
                   help="drop secret matches below this bits/byte (e.g. 3.0) to cut false positives")
    s.add_argument("--html", metavar="PATH", help="write a self-contained HTML report")
    s.add_argument("--recover", action="store_true", help="also carve readable conversation blocks")
    s.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    s.add_argument("--quiet", action="store_true", help="no progress meter")
    s.set_defaults(func=cmd_scan)

    r = sub.add_parser("recover", help="carve readable conversation blocks from a dump")
    r.add_argument("dump", help="path to a memory dump")
    r.add_argument("--json", metavar="PATH", help="write JSON ('-' for stdout)")
    r.add_argument("--html", metavar="PATH", help="write a self-contained HTML report")
    r.add_argument("--max-block", type=int, default=4096, help="max bytes to expand each side")
    r.add_argument("--quiet", action="store_true", help="no progress meter")
    r.set_defaults(func=cmd_recover)

    t = sub.add_parser("timeline", help="reconstruct an ordered conversation timeline")
    t.add_argument("dump", help="path to a memory dump")
    t.add_argument("--json", metavar="PATH", help="write JSON ('-' for stdout)")
    t.add_argument("--html", metavar="PATH", help="write a self-contained HTML report")
    t.add_argument("--quiet", action="store_true", help="no progress meter")
    t.set_defaults(func=cmd_timeline)

    la = sub.add_parser("llama", help="recover llama.cpp/Ollama context + GGUF metadata")
    la.add_argument("dump", help="path to a memory dump")
    la.add_argument("--json", metavar="PATH", help="write JSON ('-' for stdout)")
    la.add_argument("--quiet", action="store_true", help="no progress meter")
    la.set_defaults(func=cmd_llama)

    l = sub.add_parser("live", help="scan a running process's memory (Linux /proc)")
    l.add_argument("pid", type=int, help="target process id")
    l.add_argument("--only", help=f"comma list of categories: {', '.join(CATEGORIES)}")
    l.add_argument("--json", metavar="PATH", help="write JSON report ('-' for stdout)")
    l.add_argument("--context", type=int, default=48, help="context bytes each side")
    l.add_argument("--max", type=int, default=None, help="stop after N findings")
    l.add_argument("--min-entropy", type=float, default=None, help="drop low-entropy secret matches")
    l.add_argument("--html", metavar="PATH", help="write a self-contained HTML report")
    l.add_argument("--heap-stack", action="store_true", help="only scan heap/stack/anon regions (faster)")
    l.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    l.add_argument("--quiet", action="store_true", help="no progress meter")
    l.set_defaults(func=cmd_live)

    d = sub.add_parser("detectors", help="list detectors")
    d.set_defaults(func=cmd_detectors)
    return p


def main(argv=None) -> int:
    # make console output robust across platforms (Windows cp1252 can't encode
    # arbitrary memory bytes otherwise)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
