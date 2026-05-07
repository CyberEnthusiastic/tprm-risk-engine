#!/usr/bin/env python3
"""
TPRM Risk Scoring Engine — vendor risk scoring across 12 dimensions with
SOC 2 report ingestion, weighted aggregation, and prioritized findings.

  $ python risk_engine.py --vendors samples/vendors.json \
                          --soc2-dir samples/soc2/ --html report.html

Outputs:
  - Per-vendor 0-100 risk score with dimension breakdown
  - Tier classification (CRITICAL / HIGH / MEDIUM / LOW)
  - Prioritized findings: which dimensions are dragging the score
  - Optional HTML report
  - CI-friendly --fail-on threshold

Zero deps — Python 3.8+ stdlib only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter

# UTF-8 stdout for Windows hosts.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except (AttributeError, ValueError):
    pass

from dimensions import DEFAULT_WEIGHTS, LABELS, SCORERS
from soc2_parser import SOC2Summary, load as load_soc2
from report_generator import render_html


# ─── Tiering ────────────────────────────────────────────────────────────────
def tier_for(score: int) -> str:
    if score >= 75: return "CRITICAL"
    if score >= 55: return "HIGH"
    if score >= 35: return "MEDIUM"
    return "LOW"


# ─── Scoring ────────────────────────────────────────────────────────────────
def score_vendor(vendor: dict, soc2: dict, weights: dict[str, int]) -> dict:
    """Return per-vendor scoring report including dimension breakdown."""
    by_dim: dict[str, dict] = {}
    weighted_sum = 0
    total_weight = 0

    for dim, scorer in SCORERS.items():
        s = scorer(vendor, soc2)
        w = weights.get(dim, DEFAULT_WEIGHTS[dim])
        by_dim[dim] = {"label": LABELS[dim], "score": s, "weight": w,
                       "contribution": s * w}
        weighted_sum += s * w
        total_weight += w

    overall = round(weighted_sum / max(1, total_weight))
    findings = sorted(
        by_dim.values(),
        key=lambda d: (-d["contribution"], -d["score"]),
    )[:5]

    return {
        "vendor": vendor.get("name") or vendor.get("vendor", "<unknown>"),
        "tier": tier_for(overall),
        "overall_score": overall,
        "dimensions": by_dim,
        "top_findings": findings,
        "soc2": soc2 or None,
    }


# ─── Pipeline ───────────────────────────────────────────────────────────────
def load_weights(path: str | None) -> dict[str, int]:
    if not path or not os.path.exists(path):
        return dict(DEFAULT_WEIGHTS)
    with open(path, "r", encoding="utf-8") as fh:
        cfg = json.load(fh)
    weights = {**DEFAULT_WEIGHTS, **{k: int(v) for k, v in cfg.items()}}
    s = sum(weights.values())
    if s != 100:
        weights = {k: int(round(v * 100 / s)) for k, v in weights.items()}
        # Rounding may leave the sum at 99 or 101 — close the gap on the
        # largest weight so the total is always exactly 100.
        diff = 100 - sum(weights.values())
        if diff:
            top = max(weights, key=weights.get)
            weights[top] += diff
    return weights


def collect_soc2(soc2_dir: str | None) -> dict[str, dict]:
    """Load SOC 2 summaries from a directory; key by vendor name (lowercased)."""
    out: dict[str, dict] = {}
    if not soc2_dir or not os.path.isdir(soc2_dir):
        return out
    for fname in sorted(os.listdir(soc2_dir)):
        path = os.path.join(soc2_dir, fname)
        if os.path.isfile(path) and fname.lower().endswith((".json", ".md", ".txt")):
            try:
                summary = load_soc2(path)
            except Exception:
                continue
            key = (summary.vendor or os.path.splitext(fname)[0]).strip().lower()
            out[key] = summary.as_dict()
    return out


def run(vendors_path: str, soc2_dir: str | None, weights_path: str | None) -> dict:
    with open(vendors_path, "r", encoding="utf-8") as fh:
        vendors = json.load(fh)
    if isinstance(vendors, dict) and "vendors" in vendors:
        vendors = vendors["vendors"]

    soc2_index = collect_soc2(soc2_dir)
    weights = load_weights(weights_path)
    reports = []
    for v in vendors:
        key = (v.get("name") or v.get("vendor", "")).strip().lower()
        soc2 = soc2_index.get(key, {})
        reports.append(score_vendor(v, soc2, weights))

    reports.sort(key=lambda r: -r["overall_score"])
    return {
        "ts": int(time.time()),
        "weights": weights,
        "tiers": dict(Counter(r["tier"] for r in reports)),
        "vendors": reports,
    }


# ─── Output ─────────────────────────────────────────────────────────────────
_RESET = "\033[0m"
_COL = {"CRITICAL": "\033[1;91m", "HIGH": "\033[1;33m",
        "MEDIUM": "\033[1;36m", "LOW": "\033[0;90m",
        "DIM": "\033[2m", "OK": "\033[1;92m", "TITLE": "\033[1;94m"}


def _c(key, s):
    if not sys.stdout.isatty() and not os.environ.get("FORCE_COLOR"):
        return s
    return f"{_COL.get(key, '')}{s}{_RESET}"


def print_report(report: dict) -> None:
    print(_c("TITLE", "=" * 70))
    print(_c("TITLE", "  TPRM Risk Scoring Engine"))
    print(_c("TITLE", "=" * 70))
    print(f"[*] Vendors    : {len(report['vendors'])}")
    print(f"[*] By tier    : {report['tiers']}")
    print()

    for v in report["vendors"]:
        tier = v["tier"]
        print(f"{_c(tier, '[' + tier.ljust(8) + ']')} "
              f"{v['vendor']:30}  score = {v['overall_score']:3}/100")
        for f in v["top_findings"]:
            print(f"    {_c('DIM', '↳')} {f['label']:25}  "
                  f"score={f['score']:3}  weight={f['weight']:3}  "
                  f"contribution={f['contribution']}")
        print()


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Score vendors across 12 risk dimensions.")
    p.add_argument("--vendors", required=True, help="Path to vendors JSON")
    p.add_argument("--soc2-dir", help="Directory of SOC 2 summary files (.json/.md)")
    p.add_argument("--weights", help="Path to weights JSON (overrides defaults)")
    p.add_argument("--json", help="Write full report JSON to this path")
    p.add_argument("--html", help="Write HTML report to this path")
    p.add_argument("--fail-on", default="never",
                   choices=["never", "low", "medium", "high", "critical"],
                   help="Exit non-zero when any vendor reaches this tier or worse")
    args = p.parse_args(argv)

    report = run(args.vendors, args.soc2_dir, args.weights)
    print_report(report)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        print(_c("DIM", f"   -> wrote {args.json}"))

    if args.html:
        path = render_html(report, args.html)
        print(_c("DIM", f"   -> wrote {path}"))

    if args.fail_on != "never":
        cutoff = ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(args.fail_on.upper())
        worst = max((["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(v["tier"])
                     for v in report["vendors"]), default=0)
        if worst >= cutoff:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
