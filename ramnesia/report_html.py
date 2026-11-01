"""
Self-contained HTML report (dark, on-brand). Safe to share:
  * secret matches are already redacted, AND
  * raw context bytes for secret findings are NOT written into the DOM, so the
    key never ends up in the file even blurred.
Recovered conversation text can be blurred with a toggle (default on).
"""
from __future__ import annotations

import datetime
import html
from typing import List, Optional

from .scanner import Finding, summarize
from .recover import Conversation

_SEV = {"high": "#FF6B6B", "medium": "#FBBF24", "info": "#60A5FA"}


def _esc(s: str) -> str:
    return html.escape(s, quote=True)


def _role_color(role: str) -> str:
    return {"system": "#9EE6FF", "user": "#43E8D2", "assistant": "#FF6AD5",
            "tool": "#FBBF24"}.get(role, "#8B7BFF")


def html_report(findings: List[Finding], source: str,
                recovered: Optional[List[Conversation]] = None,
                timeline=None) -> str:
    recovered = recovered or []
    timeline = timeline or []
    summ = summarize(findings)
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    cats = summ["by_category"]
    chips = "".join(
        f'<span class="chip c-{c}">{c}<b>{n}</b></span>'
        for c, n in sorted(cats.items())
    )

    rows = []
    for f in findings:
        is_secret = f.category == "secret"
        ctx = "<span class='muted'>— hidden (secret) —</span>" if is_secret else _esc(f.context)
        rows.append(
            f"<tr class='sev-{f.severity}'>"
            f"<td><span class='badge' style='color:{_SEV.get(f.severity,'#aaa')}'>{f.severity}</span></td>"
            f"<td class='mono'>{_esc(f.detector)}</td>"
            f"<td class='mono muted'>{_esc(f.category)}</td>"
            f"<td class='mono'>0x{f.offset:x}</td>"
            f"<td class='mono match'>{_esc(f.match)}</td>"
            f"<td class='mono ctx'>{ctx}</td>"
            f"</tr>"
        )
    rows_html = "\n".join(rows) or "<tr><td colspan='6' class='muted'>no findings</td></tr>"

    tl_html = ""
    if timeline:
        steps = "".join(
            f"<div class='tl-step'><div class='tl-dot' style='background:{_role_color(e.role)}'></div>"
            f"<div class='tl-body'><div class='tl-meta mono'>#{e.seq} · {_esc(e.role)} · {_esc(e.kind)} "
            f"· 0x{e.offset:x} · <span class='muted'>{_esc(e.confidence)}</span></div>"
            f"<div class='tl-text blurable'>{_esc(e.text[:400])}</div></div></div>"
            for e in timeline
        )
        tl_html = f"""
        <section>
          <div class='sec-head'><h2>Reconstructed timeline <span class='muted'>({len(timeline)} turns)</span></h2>
            <label class='toggle'><input type='checkbox' id='blur2' checked> blur text</label></div>
          <p class='muted' style='margin:0 0 12px;font-size:.8rem'>Ordered by heap offset (allocation-order proxy; RAM has no timestamps).</p>
          <div class='timeline'>{steps}</div>
        </section>"""

    conv_html = ""
    if recovered:
        cards = "".join(
            f"<div class='conv'><div class='conv-off mono'>0x{c.offset:x} · {c.length}B</div>"
            f"<pre class='blurable'>{_esc(c.text)}</pre></div>"
            for c in recovered
        )
        conv_html = f"""
        <section>
          <div class='sec-head'><h2>Recovered conversations <span class='muted'>({len(recovered)})</span></h2>
            <label class='toggle'><input type='checkbox' id='blur' checked> blur sensitive text</label></div>
          {cards}
        </section>"""

    return f"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>RAMnesia report — {_esc(source)}</title>
<style>
:root{{--bg:#05080F;--panel:#0C1221;--fg:#EAEEF8;--muted:#79839B;--border:#1b2440;
--cyan:#43E8D2;--violet:#8B7BFF;--pink:#FF6AD5;--mono:'JetBrains Mono',ui-monospace,Consolas,monospace}}
*{{box-sizing:border-box}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;
padding:28px;background-image:radial-gradient(60% 50% at 10% 0%,rgba(67,232,210,.08),transparent 60%),radial-gradient(50% 40% at 100% 0%,rgba(139,123,255,.1),transparent 60%)}}
h1{{font-size:1.5rem;margin:0 0 2px;background:linear-gradient(115deg,var(--cyan),var(--violet),var(--pink));-webkit-background-clip:text;background-clip:text;color:transparent}}
h2{{font-size:1.1rem;margin:0}}
.sub{{color:var(--muted);font-family:var(--mono);font-size:.8rem;margin-bottom:20px}}
.chips{{display:flex;gap:8px;flex-wrap:wrap;margin:16px 0}}
.chip{{font-family:var(--mono);font-size:.78rem;border:1px solid var(--border);border-radius:999px;padding:5px 12px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em}}
.chip b{{margin-left:8px;color:var(--fg)}}
.c-secret b{{color:var(--pink)}} .c-prompt b{{color:var(--cyan)}} .c-mcp b{{color:var(--violet)}} .c-agent b{{color:#9EE6FF}}
section{{background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:18px;margin:18px 0}}
.sec-head{{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap}}
table{{width:100%;border-collapse:collapse;font-size:.84rem}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}}
th{{color:var(--muted);font-weight:500;font-family:var(--mono);font-size:.72rem;text-transform:uppercase;letter-spacing:.08em}}
.mono{{font-family:var(--mono)}} .muted{{color:var(--muted)}}
.match{{color:var(--pink)}} .ctx{{color:var(--muted);max-width:420px;overflow-wrap:anywhere}}
.badge{{font-family:var(--mono);font-size:.7rem;text-transform:uppercase;font-weight:600}}
tr.sev-high td{{background:rgba(255,107,107,.05)}}
.toggle{{font-family:var(--mono);font-size:.78rem;color:var(--muted);display:flex;align-items:center;gap:8px;cursor:pointer}}
.conv{{border:1px solid var(--border);border-radius:10px;margin:10px 0;overflow:hidden}}
.conv-off{{background:#0a1020;color:var(--muted);font-size:.72rem;padding:6px 12px;border-bottom:1px solid var(--border)}}
.conv pre{{margin:0;padding:12px;white-space:pre-wrap;overflow-wrap:anywhere;font-family:var(--mono);font-size:.82rem;color:var(--fg)}}
.blur{{filter:blur(5px);transition:filter .15s}} .blur:hover{{filter:none}}
.timeline{{position:relative;padding-left:6px}}
.tl-step{{display:flex;gap:12px;padding:6px 0;position:relative}}
.tl-step::before{{content:"";position:absolute;left:5px;top:0;bottom:0;width:1px;background:var(--border)}}
.tl-dot{{width:11px;height:11px;border-radius:50%;margin-top:4px;flex:none;z-index:1;box-shadow:0 0 10px -1px currentColor}}
.tl-meta{{font-size:.72rem;color:var(--muted)}}
.tl-text{{font-size:.86rem;margin-top:3px;overflow-wrap:anywhere}}
footer{{color:var(--muted);font-family:var(--mono);font-size:.72rem;margin-top:24px}}
</style></head><body>
<h1>RAMnesia</h1>
<div class="sub">AI/agent memory forensics · source: {_esc(source)} · {ts} · {len(findings)} findings</div>
<div class="chips">{chips}</div>
<section>
  <div class="sec-head"><h2>Findings</h2></div>
  <div style="overflow-x:auto"><table>
    <tr><th>Sev</th><th>Detector</th><th>Cat</th><th>Offset</th><th>Match</th><th>Context</th></tr>
    {rows_html}
  </table></div>
</section>
{tl_html}
{conv_html}
<footer>Generated by RAMnesia — secrets redacted; secret context withheld from this file.</footer>
<script>
(function(){{
  var boxes=[document.getElementById('blur'),document.getElementById('blur2')].filter(Boolean);
  function apply(){{
    var on=boxes.some(function(b){{return b.checked;}});
    document.querySelectorAll('.blurable').forEach(function(e){{e.classList.toggle('blur', on);}});
  }}
  boxes.forEach(function(b){{b.addEventListener('change',apply);}});
  apply();
}})();
</script>
</body></html>"""
