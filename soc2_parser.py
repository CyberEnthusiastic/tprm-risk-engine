"""
SOC 2 report ingestion.

Real SOC 2 reports are PDFs from auditors. Parsing them perfectly is
out of scope (and would need a PDF dependency). Instead:

  1. Accept a structured JSON summary that an analyst extracts once, OR
  2. Accept a Markdown extract (we parse common headings + bullet lists
     from a `pdftotext` / OCR conversion).

Both paths produce the same canonical SOC2Summary shape used by the
risk engine. The Markdown parser is best-effort — it is meant to save
analyst time on the most common report layouts (Big 4 / regional
auditors), not to be a forensic PDF tool.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class SOC2Summary:
    vendor: str = ""
    report_type: str = ""        # "Type I" | "Type II"
    audit_age_months: int = 0
    period_start: str = ""
    period_end: str = ""
    auditor: str = ""
    scope: list[str] = field(default_factory=list)   # e.g. ["security", "availability"]
    exceptions: list[str] = field(default_factory=list)
    carve_outs: list[str] = field(default_factory=list)
    subservice_orgs: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "vendor": self.vendor, "report_type": self.report_type,
            "audit_age_months": self.audit_age_months,
            "period_start": self.period_start, "period_end": self.period_end,
            "auditor": self.auditor, "scope": list(self.scope),
            "exceptions": list(self.exceptions),
            "carve_outs": list(self.carve_outs),
            "subservice_orgs": list(self.subservice_orgs),
        }


# ─── JSON ingestion ─────────────────────────────────────────────────────────
def from_json(path: str) -> SOC2Summary:
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return SOC2Summary(**{k: v for k, v in data.items() if hasattr(SOC2Summary, k)
                          or k in {"vendor", "report_type", "audit_age_months", "period_start",
                                   "period_end", "auditor", "scope", "exceptions",
                                   "carve_outs", "subservice_orgs"}})


# ─── Markdown / pdftotext ingestion ─────────────────────────────────────────
_TYPE_RE = re.compile(r"\bSOC\s*2\s*Type\s*(I{1,2})\b", re.I)
_PERIOD_RE = re.compile(r"period\s+(?:from\s+)?([A-Z][a-z]+\s+\d{1,2},?\s+\d{4})\s+(?:to|through)\s+([A-Z][a-z]+\s+\d{1,2},?\s+\d{4})", re.I)
_AUDITOR_RE = re.compile(r"(Deloitte|PwC|EY|KPMG|BDO|RSM|Grant Thornton|Schellman|Coalfire|A-LIGN|Linford|Crowe|MOSS Adams)", re.I)
_HEADING_RE = re.compile(r"^\s*#+\s*(.+?)\s*$", re.M)
_BULLET_RE = re.compile(r"^\s*[-*•]\s+(.+?)\s*$", re.M)


def from_markdown(path: str) -> SOC2Summary:
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()

    s = SOC2Summary()
    s.vendor = os.path.splitext(os.path.basename(path))[0].replace("_", " ").title()

    m = _TYPE_RE.search(text)
    if m:
        s.report_type = "Type II" if m.group(1).upper() == "II" else "Type I"

    m = _PERIOD_RE.search(text)
    if m:
        s.period_start = m.group(1)
        s.period_end = m.group(2)
        # Compute audit age from period_end if we can parse it.
        s.audit_age_months = _months_since(m.group(2))

    m = _AUDITOR_RE.search(text)
    if m:
        s.auditor = m.group(1)

    # Collect bullets under known headings.
    buckets: dict[str, list[str]] = {}
    current = None
    for line in text.splitlines():
        h = _HEADING_RE.match(line)
        if h:
            current = h.group(1).strip().lower()
            buckets.setdefault(current, [])
            continue
        b = _BULLET_RE.match(line)
        if b and current:
            buckets[current].append(b.group(1).strip())

    for k, v in buckets.items():
        if "exception" in k:           s.exceptions.extend(v)
        elif "carve" in k:             s.carve_outs.extend(v)
        elif "subservice" in k:        s.subservice_orgs.extend(v)
        elif "scope" in k or "criteria" in k:
            s.scope.extend(_normalize_scope(v))

    return s


_SCOPE_KEYWORDS = {
    "security": ["security", "common criteria", "cc"],
    "availability": ["availability", "uptime"],
    "processing_integrity": ["processing integrity"],
    "confidentiality": ["confidentiality"],
    "privacy": ["privacy"],
}


def _normalize_scope(items: list[str]) -> list[str]:
    out: set[str] = set()
    for it in items:
        s = it.lower()
        for canonical, kws in _SCOPE_KEYWORDS.items():
            if any(kw in s for kw in kws):
                out.add(canonical)
    return sorted(out)


def _months_since(end_date_str: str) -> int:
    """Best-effort month diff between today and end_date_str."""
    import datetime
    months = 0
    try:
        # Try a few common formats.
        for fmt in ("%B %d, %Y", "%B %d %Y"):
            try:
                end = datetime.datetime.strptime(end_date_str, fmt).date()
                today = datetime.date.today()
                months = (today.year - end.year) * 12 + (today.month - end.month)
                return max(0, months)
            except ValueError:
                continue
    except Exception:  # pragma: no cover
        pass
    return 0


# ─── Auto-dispatch ──────────────────────────────────────────────────────────
def load(path: str) -> SOC2Summary:
    if path.lower().endswith((".json",)):
        return from_json(path)
    return from_markdown(path)
