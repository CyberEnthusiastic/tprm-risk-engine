"""
The 12 vendor risk dimensions, each with a default weight and a scoring
heuristic. Weights are normalized so they sum to 100 — change them via
config without breaking the engine.

Each dimension's `score(vendor, soc2)` returns 0-100 (higher = WORSE risk).
The engine aggregates with a weighted average.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

# Default weights — edit weights.json to override per-program risk appetite.
DEFAULT_WEIGHTS = {
    "data_sensitivity":      14,  # PII / PHI / regulated data?
    "access_scope":          12,  # admin, prod, source code, secrets?
    "criticality":           10,  # business-critical, customer-facing?
    "soc2_assurance":         9,  # SOC 2 Type II, recent, no carve-outs?
    "encryption":             8,  # in transit + at rest, key management
    "iam_controls":           8,  # MFA, SSO, least privilege
    "incident_history":       8,  # breach history, MTTD/MTTR
    "subprocessor_risk":      7,  # 4th-party dependencies disclosed
    "geo_risk":               6,  # data residency / sanctions
    "financial_health":       6,  # solvency, going concern
    "termination_resilience": 6,  # data deletion, transition assistance
    "monitoring_visibility":  6,  # logs/SIEM forwarding, audit access
}
assert sum(DEFAULT_WEIGHTS.values()) == 100, "Weights must sum to 100"


# ─── Helpers ────────────────────────────────────────────────────────────────
def _bucket(value: str, mapping: dict[str, int], default: int = 50) -> int:
    return mapping.get((value or "").strip().lower(), default)


# ─── Per-dimension scorers ──────────────────────────────────────────────────
def score_data_sensitivity(v: dict, _soc2: dict) -> int:
    return _bucket(v.get("data_sensitivity"), {
        "phi": 100, "pii": 80, "financial": 80, "internal": 50, "public": 10,
    })


def score_access_scope(v: dict, _soc2: dict) -> int:
    scope = (v.get("access_scope") or "").lower()
    s = 0
    if "prod" in scope:        s += 40
    if "admin" in scope:       s += 30
    if "source" in scope or "code" in scope: s += 15
    if "secrets" in scope:     s += 25
    return min(100, s)


def score_criticality(v: dict, _soc2: dict) -> int:
    return _bucket(v.get("criticality"), {
        "tier-0": 100, "tier-1": 80, "tier-2": 50, "tier-3": 25,
    })


def score_soc2_assurance(_v: dict, soc2: dict) -> int:
    if not soc2:
        return 90  # No SOC 2 at all
    rtype = (soc2.get("report_type") or "").lower()
    age = soc2.get("audit_age_months", 99)
    exceptions = soc2.get("exceptions") or []
    carve_outs = soc2.get("carve_outs") or []

    s = 0
    if rtype != "type ii":   s += 30
    if age > 12:             s += 20
    if age > 18:             s += 15
    s += min(20, len(exceptions) * 5)
    if any("subservice" in str(c).lower() for c in carve_outs): s += 10
    return min(100, s)


def score_encryption(v: dict, _soc2: dict) -> int:
    enc = v.get("encryption") or {}
    s = 0
    if not enc.get("in_transit"):       s += 40
    if not enc.get("at_rest"):          s += 35
    if not enc.get("customer_managed_keys"): s += 15
    if not enc.get("key_rotation"):     s += 10
    return min(100, s)


def score_iam_controls(v: dict, _soc2: dict) -> int:
    iam = v.get("iam") or {}
    s = 0
    if not iam.get("mfa_required"):    s += 40
    if not iam.get("sso"):             s += 25
    if not iam.get("rbac"):            s += 15
    if (iam.get("admin_count") or 0) > 5: s += 10
    if not iam.get("offboarding_24h"): s += 10
    return min(100, s)


def score_incident_history(v: dict, _soc2: dict) -> int:
    hist = v.get("incidents") or {}
    breaches = hist.get("breaches_5y") or 0
    open_issues = hist.get("open_issues") or 0
    mttd = hist.get("mttd_hours") or 0
    s = 0
    s += min(60, breaches * 25)
    s += min(20, open_issues * 5)
    s += min(20, max(0, mttd - 24) // 12 * 5)
    return min(100, s)


def score_subprocessor_risk(v: dict, _soc2: dict) -> int:
    subs = v.get("subprocessors") or {}
    if not subs.get("disclosed"):
        return 70
    high_risk = subs.get("high_risk_count") or 0
    return min(100, high_risk * 25 + (0 if subs.get("notification_30d") else 15))


def score_geo_risk(v: dict, _soc2: dict) -> int:
    geo = v.get("geo") or {}
    countries = [c.lower() for c in (geo.get("processing_countries") or [])]
    s = 0
    high_risk = {"cn", "ru", "ir", "kp", "by"}
    s += sum(20 for c in countries if c in high_risk)
    if not geo.get("data_residency_enforced"): s += 20
    return min(100, s)


def score_financial_health(v: dict, _soc2: dict) -> int:
    fin = v.get("financial") or {}
    return _bucket(fin.get("rating"), {
        "going-concern":        100,
        "below-investment":      80,
        "investment-grade":      30,
        "publicly-traded-stable":15,
        "fortune-500":            5,
    })


def score_termination_resilience(v: dict, _soc2: dict) -> int:
    t = v.get("termination") or {}
    s = 0
    if not t.get("data_deletion_certified"): s += 40
    if not t.get("transition_assistance_clause"): s += 30
    if (t.get("data_export_format") or "").lower() not in ("json", "csv", "open"): s += 30
    return min(100, s)


def score_monitoring_visibility(v: dict, _soc2: dict) -> int:
    m = v.get("monitoring") or {}
    s = 0
    if not m.get("siem_forward"):          s += 40
    if not m.get("audit_log_access"):      s += 30
    if not m.get("uptime_published"):      s += 20
    if not m.get("status_page"):           s += 10
    return min(100, s)


SCORERS: dict[str, Callable[[dict, dict], int]] = {
    "data_sensitivity":      score_data_sensitivity,
    "access_scope":          score_access_scope,
    "criticality":           score_criticality,
    "soc2_assurance":        score_soc2_assurance,
    "encryption":            score_encryption,
    "iam_controls":          score_iam_controls,
    "incident_history":      score_incident_history,
    "subprocessor_risk":     score_subprocessor_risk,
    "geo_risk":              score_geo_risk,
    "financial_health":      score_financial_health,
    "termination_resilience":score_termination_resilience,
    "monitoring_visibility": score_monitoring_visibility,
}

# Display labels
LABELS = {k: k.replace("_", " ").title() for k in SCORERS}
