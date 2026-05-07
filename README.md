# TPRM Vendor Risk Scoring Engine

> **Vendor risk scoring across 12 dimensions with SOC 2 report ingestion, weighted aggregation, and prioritized findings.**
> Drop-in for security teams scaling third-party risk reviews from days to minutes.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![SOC 2](https://img.shields.io/badge/SOC%202-Type%20II%20aware-1F4E79)](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2)
[![NIST](https://img.shields.io/badge/NIST-aligned-7B42BC)](https://www.nist.gov/cyberframework)

---

## What it does

Scores vendors across **12 risk dimensions** with configurable weights,
ingests SOC 2 Type II report summaries (JSON or Markdown extracted from
PDF), and produces a tiered risk register with the 5 worst contributing
findings per vendor.

```
======================================================================
  TPRM Risk Scoring Engine
======================================================================
[*] Vendors    : 4
[*] By tier    : {'CRITICAL': 1, 'MEDIUM': 2, 'LOW': 1}

[CRITICAL] ScrappyAnalytics                 score = 78/100
    ↳ Iam Controls               score=100  weight=  8  contribution=800
    ↳ Termination Resilience     score=100  weight=  6  contribution=600
    ↳ Data Sensitivity           score= 80  weight= 14  contribution=1120
    ↳ Access Scope               score=100  weight= 12  contribution=1200
    ↳ Soc2 Assurance             score= 90  weight=  9  contribution=810

[MEDIUM  ] AWS                              score = 36/100
    ↳ Data Sensitivity           score=100  weight= 14  contribution=1400
    ↳ Access Scope               score= 95  weight= 12  contribution=1140
    ↳ Criticality                score=100  weight= 10  contribution=1000
    ...

[LOW     ] Salesforce                       score = 32/100
    ...
```

---

## The 12 dimensions

Default weights sum to 100. Override per program risk-appetite by passing
`--weights weights.json` — the engine renormalizes if your weights don't
sum to 100.

| # | Dimension | Default weight | What it measures |
|---|---|---:|---|
| 1 | Data sensitivity | 14 | PHI / PII / financial / public |
| 2 | Access scope | 12 | prod / admin / source code / secrets |
| 3 | Criticality | 10 | tier-0 → tier-3 (impact if compromised) |
| 4 | SOC 2 assurance | 9 | Type II + recent + clean opinion |
| 5 | Encryption | 8 | in transit, at rest, CMK, rotation |
| 6 | IAM controls | 8 | MFA, SSO, RBAC, offboarding |
| 7 | Incident history | 8 | breaches in 5 years, MTTD, open issues |
| 8 | Subprocessor risk | 7 | 4th-party disclosure + notification |
| 9 | Geo risk | 6 | data residency, sanctioned countries |
| 10 | Financial health | 6 | solvency, public listing |
| 11 | Termination resilience | 6 | data deletion certification, export format |
| 12 | Monitoring visibility | 6 | SIEM forwarding, audit-log access |
| **Total** | | **100** | |

Each dimension's score is 0-100 (higher = worse risk). The engine returns
a weighted average per vendor, then buckets to a tier:

| Tier | Score range |
|---|---|
| CRITICAL | 75-100 |
| HIGH | 55-74 |
| MEDIUM | 35-54 |
| LOW | 0-34 |

---

## Why you want this

- **Defensible scoring.** Every score has a number, a weight, a contribution. You can show the CISO exactly *why* ScrappyAnalytics is critical and AWS isn't — no black box.
- **Inherent vs control risk separation.** Data sensitivity and criticality are inherent (you can't reduce them). IAM controls and encryption are mitigations. The engine respects this — a tier-0 PHI vendor with perfect controls floors at MEDIUM, not LOW. That's correct.
- **SOC 2 reports as inputs, not blockers.** Drop the SOC 2 report (JSON summary or markdown extract) into a directory; the engine factors it automatically. Type I gets penalized vs Type II. Carve-outs and exceptions add risk weight.
- **Reproducible.** No live API calls, no SaaS dependency, no rate limits. Run it in an air-gapped environment with confidence — same input → same output.
- **Zero dependencies.** Python 3.8+ stdlib only. Drops into any CI runner.

---

## Quickstart

```bash
git clone https://github.com/CyberEnthusiastic/tprm-risk-engine.git
cd tprm-risk-engine

# Bundled samples — 4 vendors with mixed risk levels:
python risk_engine.py --vendors samples/vendors.json \
                      --soc2-dir samples/soc2 --html report.html

# Real run with custom weights:
python risk_engine.py --vendors prod_vendors.json --soc2-dir ./soc2/ \
                      --weights weights.json --json out.json --html out.html

# CI gate — fail the pipeline on any CRITICAL vendor:
python risk_engine.py --vendors vendors.json --fail-on critical
```

---

## Vendor JSON shape

```json
{
  "name": "Salesforce",
  "data_sensitivity": "PII",
  "access_scope": "prod admin",
  "criticality": "tier-0",
  "encryption": {"in_transit": true, "at_rest": true,
                 "customer_managed_keys": false, "key_rotation": true},
  "iam": {"mfa_required": true, "sso": true, "rbac": true,
          "admin_count": 4, "offboarding_24h": true},
  "incidents": {"breaches_5y": 0, "open_issues": 1, "mttd_hours": 18},
  "subprocessors": {"disclosed": true, "high_risk_count": 0,
                    "notification_30d": true},
  "geo": {"processing_countries": ["US"], "data_residency_enforced": true},
  "financial": {"rating": "publicly-traded-stable"},
  "termination": {"data_deletion_certified": true,
                  "transition_assistance_clause": true,
                  "data_export_format": "JSON"},
  "monitoring": {"siem_forward": true, "audit_log_access": true,
                 "uptime_published": true, "status_page": true}
}
```

Anything you don't have, omit. Missing dimensions get a conservative
default (50/100 — "we don't know" → medium risk).

---

## SOC 2 ingestion

Two paths:

**1. JSON summary** (fastest, when an analyst has already triaged the report):

```json
{
  "vendor": "Salesforce",
  "report_type": "Type II",
  "audit_age_months": 4,
  "period_start": "January 1, 2024",
  "period_end": "December 31, 2024",
  "auditor": "KPMG",
  "scope": ["security", "availability", "confidentiality"],
  "exceptions": [],
  "carve_outs": [],
  "subservice_orgs": ["AWS"]
}
```

**2. Markdown extract** (drop a `pdftotext` conversion of the PDF):

```markdown
# QuickbillSaaS SOC 2 Type II Report

Audit period: January 1, 2024 through June 30, 2024.
Auditor: A-LIGN.

## Scope
- Common Criteria (Security)
- Availability

## Exceptions
- A privileged user account was not deactivated within 24 hours
- One change deployed without approval ticket

## Carve-outs
- Subservice organization: AWS (carved out)
```

The Markdown parser extracts: report type, period, auditor, scope,
exceptions, carve-outs, and subservice orgs from common heading +
bullet patterns. It is best-effort — for low-quality PDFs or unusual
layouts, fall back to the JSON summary path.

---

## Weights configuration

```json
{
  "data_sensitivity": 18,
  "iam_controls": 12,
  "soc2_assurance": 12
}
```

Pass with `--weights weights.json`. You only specify the keys you want
to override; the rest stay at default. The engine renormalizes the
total to exactly 100.

---

## CLI

```
usage: risk_engine.py [-h] --vendors PATH [--soc2-dir DIR] [--weights PATH]
                      [--json PATH] [--html PATH]
                      [--fail-on {never,low,medium,high,critical}]
```

| Flag | Purpose |
|---|---|
| `--vendors PATH` | Vendors JSON file |
| `--soc2-dir DIR` | Directory of SOC 2 summary files (.json/.md) |
| `--weights PATH` | Custom weight override JSON |
| `--json PATH` | Write full report JSON for downstream tools |
| `--html PATH` | Write self-contained HTML report |
| `--fail-on LEVEL` | Exit non-zero when any vendor reaches this tier or worse |

---

## Architecture

```
risk_engine.py     ── CLI, scoring, tiering, output
dimensions.py      ── 12 dimension scorers + default weights
soc2_parser.py     ── JSON + Markdown SOC 2 ingestion
report_generator.py── HTML report
samples/
  vendors.json     ── 4-vendor mixed-risk fixture
  soc2/            ── 3 SOC 2 summaries (JSON + MD)
tests/
  test_engine.py   ── 10 unit tests, runs in <100ms
```

---

## Running the tests

```bash
python -m unittest discover tests
```

10 tests covering: dimension count and weight sum, IAM scoring extremes,
SOC 2 absence vs clean Type II, Markdown parser (heading + bullet
extraction), JSON parser, tier bucketing, end-to-end scoring of the
sample vendors, and weight normalization.

---

## License

MIT — see [LICENSE](./LICENSE).
