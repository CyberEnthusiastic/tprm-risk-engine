"""HTML report renderer (zero-deps)."""
from __future__ import annotations

import html
import os
import time

_TIER_COLOR = {"CRITICAL": "#ff3b30", "HIGH": "#ff9500",
               "MEDIUM": "#ffcc00", "LOW": "#34d399"}


def render_html(report: dict, out_path: str) -> str:
    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(report.get("ts", time.time())))
    rows = []
    for v in report["vendors"]:
        tier = v["tier"]
        rows.append(f"""
        <tr>
          <td><strong>{html.escape(v['vendor'])}</strong></td>
          <td><span class="tier" style="background:{_TIER_COLOR.get(tier, '#888')}">{tier}</span></td>
          <td class="score">{v['overall_score']}</td>
          <td>
            <ul class="findings">
              {''.join(f'<li><strong>{html.escape(f["label"])}</strong>: '
                       f'score {f["score"]} (weight {f["weight"]})</li>'
                       for f in v["top_findings"])}
            </ul>
          </td>
        </tr>""")

    weights_rows = "\n".join(
        f'<li><span>{html.escape(k)}</span><span>{v}%</span></li>'
        for k, v in report.get("weights", {}).items()
    )

    page = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>TPRM Risk Report</title>
<style>
:root{{--bg:#0b0f14;--p:#11161d;--b:#1f2937;--t:#e5e7eb;--m:#9ca3af;--a:#60a5fa}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--t);font-family:ui-sans-serif,-apple-system,Segoe UI,Roboto,sans-serif;padding:32px}}
h1{{font-size:22px;margin-bottom:4px}} h2{{font-size:14px;margin:20px 0 10px;color:var(--m)}}
.meta{{color:var(--m);font-size:13px;margin-bottom:20px}}
.tiles{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}}
.tile{{background:var(--p);border:1px solid var(--b);padding:16px;border-radius:8px}}
.tile .v{{font-size:28px;font-weight:700;color:var(--a)}}
.tile .l{{font-size:11px;color:var(--m);text-transform:uppercase;letter-spacing:1px;margin-top:4px}}
table{{width:100%;border-collapse:collapse;background:var(--p);border:1px solid var(--b);border-radius:8px;overflow:hidden}}
th,td{{padding:12px 14px;border-bottom:1px solid var(--b);vertical-align:top;text-align:left;font-size:13px}}
th{{background:#0a0d12;color:var(--m);font-size:11px;text-transform:uppercase;letter-spacing:1px}}
.tier{{display:inline-block;padding:3px 8px;border-radius:3px;color:#000;font-weight:700;font-size:11px;letter-spacing:1px}}
.score{{font-family:ui-monospace,Menlo,monospace;font-size:18px;font-weight:700}}
.findings{{list-style:none;padding:0}} .findings li{{margin-bottom:4px;color:var(--m);font-size:12px}}
.findings strong{{color:var(--t)}}
.weights{{background:var(--p);border:1px solid var(--b);padding:14px 18px;border-radius:8px;margin-top:24px}}
.weights ul{{list-style:none;display:grid;grid-template-columns:repeat(2,1fr);gap:6px 24px}}
.weights li{{display:flex;justify-content:space-between;color:var(--m);font-size:12px}}
.weights li span:last-child{{color:var(--a);font-weight:700}}
</style></head>
<body>
<h1>TPRM Risk Report</h1>
<div class="meta">Generated {ts} · {len(report['vendors'])} vendors scored</div>
<div class="tiles">
  <div class="tile"><div class="v">{report['tiers'].get('CRITICAL', 0)}</div><div class="l">Critical</div></div>
  <div class="tile"><div class="v">{report['tiers'].get('HIGH', 0)}</div><div class="l">High</div></div>
  <div class="tile"><div class="v">{report['tiers'].get('MEDIUM', 0)}</div><div class="l">Medium</div></div>
  <div class="tile"><div class="v">{report['tiers'].get('LOW', 0)}</div><div class="l">Low</div></div>
</div>
<table>
  <thead><tr><th>Vendor</th><th>Tier</th><th>Score</th><th>Top findings</th></tr></thead>
  <tbody>{''.join(rows)}</tbody>
</table>
<div class="weights">
  <h2>Dimension weights</h2>
  <ul>{weights_rows}</ul>
</div>
</body></html>"""

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(page)
    return out_path
