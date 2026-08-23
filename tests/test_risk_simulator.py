import unittest
import os
import sys
import copy

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from src.data_loader import load_organizations, load_vulnerabilities
from src.matcher import match_products_for_organization
from src.ranking import rank_vulnerabilities, get_top_n_vulnerabilities
from src.simulator import run_remediation_simulation, compute_best_first_fix

class TestRiskSimulator(unittest.TestCase):
    """
    Validates What-If Risk Simulator, non-mutating in-memory execution,
    exact (cve_id, product_name) targeting, large dataset scaling, and comparative Best First Fix calculation.
    """

    def setUp(self):
        self.organizations, _ = load_organizations()
        self.vulnerabilities, _, _, _, _ = load_vulnerabilities()
        self.org1 = next(o for o in self.organizations if o["org_id"] == "ORG-001")
        self.org2 = next(o for o in self.organizations if o["org_id"] == "ORG-002")

    def test_simulation_does_not_mutate_original_dataset(self):
        """Rule 5 / Test F: Verify the input vulnerability list is completely unchanged after simulation."""
        vulns_copy = copy.deepcopy(self.vulnerabilities)
        len_before = len(self.vulnerabilities)
        
        sim_res = run_remediation_simulation(
            self.org1,
            self.vulnerabilities,
            [{"cve_id": "CVE-2023-1262", "product_name": "Identity Provider SaaS"}]
        )
        
        # Check that original list length and elements are identical
        self.assertEqual(len(self.vulnerabilities), len_before)
        self.assertEqual(self.vulnerabilities, vulns_copy)

    def test_simulation_zero_remediations_baseline_state(self):
        """Verify 0-remediation selection outputs baseline state with informative explanation."""
        sim_res = run_remediation_simulation(
            self.org1,
            self.vulnerabilities,
            []
        )
        self.assertEqual(sim_res["remediated_count"], 0)
        self.assertEqual(len(sim_res["before_top_5"]), len(sim_res["after_top_5"]))
        self.assertIn("Baseline state with 0 simulated remediations", sim_res["explanation"])

    def test_exact_cve_and_product_targeting(self):
        """Rule 5 / Test G: Verify remediating a CVE on Product A does NOT remove the same CVE on Product B."""
        synthetic_vulns = [
            {
                "cve_id": "CVE-2024-DUAL",
                "product_name": "Core Banking Framework", # Product A (Critical for ORG-001)
                "cvss_base_score": 8.0,
                "cisa_kev": True,
                "first_epss": 0.5
            },
            {
                "cve_id": "CVE-2024-DUAL",
                "product_name": "Identity Provider SaaS", # Product B (Critical for ORG-001)
                "cvss_base_score": 8.0,
                "cisa_kev": True,
                "first_epss": 0.5
            }
        ]
        
        # Remediate only Product A
        sim_res = run_remediation_simulation(
            self.org1,
            synthetic_vulns,
            [{"cve_id": "CVE-2024-DUAL", "product_name": "Core Banking Framework"}]
        )
        
        self.assertEqual(sim_res["baseline_matched_count"], 2)
        self.assertEqual(sim_res["simulated_matched_count"], 1)
        
        # Product B must still exist in simulated Top 5
        after_cves = [f"{v['cve_id']}-{v['product_name']}" for v in sim_res["after_top_5"]]
        self.assertIn("CVE-2024-DUAL-Identity Provider SaaS", after_cves)
        self.assertNotIn("CVE-2024-DUAL-Core Banking Framework", after_cves)

    def test_top_5_before_after_and_rank_shifts(self):
        """Rule 7 / Test E: Verify that removing Rank #1 shifts subsequent vulnerabilities up in the ~540 record baseline."""
        sim_res = run_remediation_simulation(
            self.org1,
            self.vulnerabilities,
            [{"cve_id": "CVE-2023-1262", "product_name": "Identity Provider SaaS"}] # Baseline Rank #1
        )
        
        before_cves = [v["cve_id"] for v in sim_res["before_top_5"]]
        after_cves = [v["cve_id"] for v in sim_res["after_top_5"]]
        
        # Baseline top 5 for ORG-001
        self.assertEqual(before_cves[0], "CVE-2023-1262")
        self.assertEqual(before_cves[1], "CVE-2025-1728")
        
        # In simulated results, CVE-2025-1728 should now be Rank #1
        self.assertEqual(after_cves[0], "CVE-2025-1728")
        self.assertNotIn("CVE-2023-1262", after_cves)
        
        # Check newly promoted 5th entrant
        self.assertTrue(len(sim_res["new_entrants"]) > 0)
        self.assertEqual(sim_res["new_entrants"][0]["rank"], 5)
        
        # Check rank shifts count
        self.assertTrue(len(sim_res["rank_shifts"]) >= 4)

    def test_simulator_with_uploaded_dataset(self):
        """Rule 5 / Test D: Simulator works seamlessly on custom uploaded normalized datasets."""
        custom_vulns = [
            {
                "cve_id": "CVE-UP-1",
                "product_name": "Core Banking Framework",
                "cvss_base_score": 9.5,
                "cisa_kev": True,
                "first_epss": 0.90
            },
            {
                "cve_id": "CVE-UP-2",
                "product_name": "Core Banking Framework",
                "cvss_base_score": 8.0,
                "cisa_kev": False,
                "first_epss": 0.50
            },
            {
                "cve_id": "CVE-UP-3",
                "product_name": "Identity Provider SaaS",
                "cvss_base_score": 7.0,
                "cisa_kev": False,
                "first_epss": 0.30
            }
        ]
        
        sim_res = run_remediation_simulation(
            self.org1,
            custom_vulns,
            [{"cve_id": "CVE-UP-1", "product_name": "Core Banking Framework"}]
        )
        
        self.assertEqual(sim_res["baseline_matched_count"], 3)
        self.assertEqual(sim_res["simulated_matched_count"], 2)
        self.assertEqual(sim_res["after_top_5"][0]["cve_id"], "CVE-UP-2")
        self.assertEqual(sim_res["after_top_5"][0]["rank"], 1)

    def test_best_first_fix_candidate_engine_evaluation(self):
        """Rule 4 / Test H: Verify Best First Fix executes comparative engine runs and produces structured recommendation."""
        best_fix = compute_best_first_fix(self.org1, self.vulnerabilities, candidate_limit=5)
        
        self.assertTrue(best_fix["has_recommendation"])
        self.assertEqual(best_fix["recommended_cve"], "CVE-2023-1262")
        self.assertEqual(best_fix["recommended_product"], "Identity Provider SaaS")
        self.assertEqual(best_fix["baseline_rank"], 1)
        self.assertAlmostEqual(best_fix["risk_score_removed"], 0.881328, places=5)
        self.assertIn("CVE-2023-1262", best_fix["rationale"])
        self.assertEqual(len(best_fix["all_candidate_evaluations"]), 5)

    def test_simulator_organization_switching(self):
        """Rule 8 / Test I: Simulator updates baseline and simulation for newly selected organization."""
        sim_res_org2 = run_remediation_simulation(
            self.org2,
            self.vulnerabilities,
            []
        )
        self.assertEqual(sim_res_org2["org_id"], "ORG-002")
        self.assertEqual(sim_res_org2["org_name"], "Agile Cloud Tech Startup")
        self.assertTrue(len(sim_res_org2["before_top_5"]) > 0)

if __name__ == "__main__":
    unittest.main()
