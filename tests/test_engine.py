"""Smoke + correctness tests. Run: python -m unittest discover tests"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from dimensions import DEFAULT_WEIGHTS, SCORERS, score_iam_controls, score_soc2_assurance  # noqa: E402
from risk_engine import run, score_vendor, tier_for, load_weights  # noqa: E402
from soc2_parser import from_markdown, from_json  # noqa: E402


class TestDimensions(unittest.TestCase):
    def test_weight_count_and_sum(self):
        self.assertEqual(len(DEFAULT_WEIGHTS), 12)
        self.assertEqual(sum(DEFAULT_WEIGHTS.values()), 100)

    def test_iam_no_mfa_no_sso_high_risk(self):
        v = {"iam": {"mfa_required": False, "sso": False, "rbac": False,
                     "admin_count": 10, "offboarding_24h": False}}
        s = score_iam_controls(v, {})
        self.assertGreaterEqual(s, 80)

    def test_iam_strong_low_risk(self):
        v = {"iam": {"mfa_required": True, "sso": True, "rbac": True,
                     "admin_count": 3, "offboarding_24h": True}}
        s = score_iam_controls(v, {})
        self.assertEqual(s, 0)

    def test_soc2_missing_high_risk(self):
        self.assertEqual(score_soc2_assurance({}, {}), 90)

    def test_soc2_clean_low_risk(self):
        soc2 = {"report_type": "Type II", "audit_age_months": 3,
                "exceptions": [], "carve_outs": []}
        self.assertEqual(score_soc2_assurance({}, soc2), 0)


class TestSoc2Parser(unittest.TestCase):
    def test_md_parser_extracts_type_and_exceptions(self):
        s = from_markdown(os.path.join(ROOT, "samples", "soc2", "quickbillsaas.md"))
        self.assertEqual(s.report_type, "Type II")
        self.assertEqual(s.auditor, "A-LIGN")
        self.assertGreaterEqual(len(s.exceptions), 2)
        self.assertIn("security", s.scope)
        self.assertIn("availability", s.scope)

    def test_json_parser(self):
        s = from_json(os.path.join(ROOT, "samples", "soc2", "salesforce.json"))
        self.assertEqual(s.report_type, "Type II")
        self.assertEqual(s.auditor, "KPMG")


class TestEngine(unittest.TestCase):
    def test_tier_buckets(self):
        self.assertEqual(tier_for(80), "CRITICAL")
        self.assertEqual(tier_for(60), "HIGH")
        self.assertEqual(tier_for(40), "MEDIUM")
        self.assertEqual(tier_for(20), "LOW")

    def test_e2e_run(self):
        report = run(
            os.path.join(ROOT, "samples", "vendors.json"),
            os.path.join(ROOT, "samples", "soc2"),
            None,
        )
        self.assertEqual(len(report["vendors"]), 4)
        names = {v["vendor"] for v in report["vendors"]}
        self.assertIn("ScrappyAnalytics", names)
        self.assertIn("AWS", names)

        scrappy = next(v for v in report["vendors"] if v["vendor"] == "ScrappyAnalytics")
        aws = next(v for v in report["vendors"] if v["vendor"] == "AWS")
        # ScrappyAnalytics should be much higher risk than AWS.
        self.assertGreater(scrappy["overall_score"], aws["overall_score"] + 30)
        self.assertEqual(scrappy["tier"], "CRITICAL")
        # AWS handles PHI on tier-0, so the floor is naturally MEDIUM even
        # with perfect controls — that's correct, not a bug.
        self.assertIn(aws["tier"], ("LOW", "MEDIUM"))

    def test_load_weights_normalizes(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as fh:
            json.dump({"data_sensitivity": 200}, fh)
            path = fh.name
        weights = load_weights(path)
        self.assertEqual(sum(weights.values()), 100)


if __name__ == "__main__":
    unittest.main()
