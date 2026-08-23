import unittest
import os
import sys
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from src.dataset_parser import parse_and_inspect_dataset
from src.ai_advisor import analyze_vulnerability_with_ai
from src.simulator import run_remediation_simulation, compute_best_first_fix
from src.data_loader import load_organizations, load_vulnerabilities

class TestUploadedDatasetIntegration(unittest.TestCase):
    """
    End-to-End integration tests for:
    1. CSV/JSON Upload & Normalization
    2. Active Dataset AI Advisor Analysis
    3. No Silent Fallback to Baseline
    4. Active Dataset What-If Simulation
    5. Organization Switching Synchronization
    6. Reset to Bundled Baseline
    """

    def setUp(self):
        self.organizations, _ = load_organizations()
        self.baseline_vulns, _, _, _, _ = load_vulnerabilities()
        self.org1 = next(o for o in self.organizations if o["org_id"] == "ORG-001")
        self.org2 = next(o for o in self.organizations if o["org_id"] == "ORG-002")

        # Custom CSV content with new CVEs not in baseline
        self.custom_csv = """cve_id,product_name,cvss_base_score,cisa_kev,first_epss
CVE-CUSTOM-101,Identity Provider SaaS,9.8,TRUE,0.925
CVE-CUSTOM-102,Core Banking Framework,8.4,FALSE,0.450
CVE-CUSTOM-103,Cloud Database Engine,9.1,TRUE,0.880
"""

    def test_end_to_end_uploaded_dataset_flow(self):
        # 1. Parse and inspect custom CSV
        inspection = parse_and_inspect_dataset(self.custom_csv, "enterprise_feed.csv")
        self.assertTrue(inspection["is_valid"])
        self.assertEqual(len(inspection["valid_records"]), 3)
        
        active_vulns = inspection["valid_records"]
        dataset_source = "Uploaded Dataset (enterprise_feed.csv)"
        
        # 2. AI Advisor Analysis on Custom Uploaded CVE
        ai_res = analyze_vulnerability_with_ai(
            org_id="ORG-001",
            cve_id="CVE-CUSTOM-101",
            product_name="Identity Provider SaaS",
            active_vulnerabilities=active_vulns,
            dataset_source=dataset_source
        )
        self.assertNotIn("error", ai_res)
        self.assertEqual(ai_res["cve_id"], "CVE-CUSTOM-101")
        self.assertEqual(ai_res["product_name"], "Identity Provider SaaS")
        self.assertEqual(ai_res["deterministic_rank"], 1)
        self.assertEqual(ai_res["dataset_source"], dataset_source)
        
        # 3. No Silent Fallback Test: Requesting baseline CVE-2023-1262 must fail
        fallback_check = analyze_vulnerability_with_ai(
            org_id="ORG-001",
            cve_id="CVE-2023-1262",
            product_name="Identity Provider SaaS",
            active_vulnerabilities=active_vulns,
            dataset_source=dataset_source
        )
        self.assertEqual(fallback_check.get("status"), "not_found")
        self.assertIn("error", fallback_check)
        self.assertIn("enterprise_feed.csv", fallback_check.get("dataset_source", ""))
        
        # 4. What-If Simulator on Custom Uploaded Dataset
        sim_res = run_remediation_simulation(
            self.org1,
            active_vulns,
            [{"cve_id": "CVE-CUSTOM-101", "product_name": "Identity Provider SaaS"}]
        )
        self.assertEqual(sim_res["baseline_matched_count"], 2) # ORG-001 matches 101 and 102
        self.assertEqual(sim_res["simulated_matched_count"], 1) # Only 102 remains
        self.assertEqual(sim_res["after_top_5"][0]["cve_id"], "CVE-CUSTOM-102")
        self.assertEqual(sim_res["after_top_5"][0]["rank"], 1)
        
        # 5. Best First Fix on Custom Uploaded Dataset
        best_fix = compute_best_first_fix(self.org1, active_vulns)
        self.assertTrue(best_fix["has_recommendation"])
        self.assertEqual(best_fix["recommended_cve"], "CVE-CUSTOM-101")
        
        # 6. Organization Switching on Custom Uploaded Dataset
        # ORG-002 matches CVE-CUSTOM-103 (Cloud Database Engine)
        ai_res_org2 = analyze_vulnerability_with_ai(
            org_id="ORG-002",
            cve_id="CVE-CUSTOM-103",
            product_name="Cloud Database Engine",
            active_vulnerabilities=active_vulns,
            dataset_source=dataset_source
        )
        self.assertNotIn("error", ai_res_org2)
        self.assertEqual(ai_res_org2["org_id"], "ORG-002")
        self.assertEqual(ai_res_org2["cve_id"], "CVE-CUSTOM-103")
        self.assertEqual(ai_res_org2["deterministic_rank"], 1)

    def test_json_uploaded_dataset_flow(self):
        custom_json = json.dumps([
            {
                "cve_identifier": "CVE-JSON-500",
                "software_name": "Identity Provider SaaS",
                "cvss_score": 9.9,
                "known_exploited": True,
                "epss_probability": 0.99
            }
        ])
        inspection = parse_and_inspect_dataset(custom_json, "custom.json")
        self.assertTrue(inspection["is_valid"])
        self.assertEqual(len(inspection["valid_records"]), 1)
        
        active_vulns = inspection["valid_records"]
        ai_res = analyze_vulnerability_with_ai(
            org_id="ORG-001",
            cve_id="CVE-JSON-500",
            product_name="Identity Provider SaaS",
            active_vulnerabilities=active_vulns,
            dataset_source="Uploaded Dataset (custom.json)"
        )
        self.assertNotIn("error", ai_res)
        self.assertEqual(ai_res["cve_id"], "CVE-JSON-500")

    def test_reset_restores_bundled_baseline(self):
        """Verify baseline vulnerabilities are completely intact and accessible after reset."""
        self.assertTrue(len(self.baseline_vulns) >= 500)
        baseline_cve = analyze_vulnerability_with_ai(
            org_id="ORG-001",
            cve_id="CVE-2023-1262",
            active_vulnerabilities=self.baseline_vulns,
            dataset_source="Bundled Baseline Dataset (data/vulnerabilities.csv)"
        )
        self.assertNotIn("error", baseline_cve)
        self.assertEqual(baseline_cve["cve_id"], "CVE-2023-1262")

if __name__ == "__main__":
    unittest.main()
