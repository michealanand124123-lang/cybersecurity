import unittest
import os
import sys

# Ensure repository root is in sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from src.data_loader import load_organizations, load_vulnerabilities, load_practitioner
from src.matcher import match_products_for_organization
from src.ranking import rank_vulnerabilities, get_top_n_vulnerabilities
from src.validation import compare_with_practitioner

class TestDeterministicIntegrity(unittest.TestCase):
    """
    Guarantees that deterministic scoring, ranking, matching,
    and validation remain 100% authoritative and unchanged.
    """

    def setUp(self):
        self.organizations, _ = load_organizations()
        self.vulnerabilities, _, _, _, _ = load_vulnerabilities()
        self.practitioners, _ = load_practitioner()

    def test_organization_weight_modifiers_integrity(self):
        """Verify organization weights match specifications."""
        org_map = {o["org_id"]: o for o in self.organizations}
        
        # ORG-001 (Global Retail Bank)
        org1 = org_map["ORG-001"]
        self.assertEqual(org1["weight_modifiers"]["cvss_weight"], 0.3)
        self.assertEqual(org1["weight_modifiers"]["cisa_kev_weight"], 0.45)
        self.assertEqual(org1["weight_modifiers"]["first_epss_weight"], 0.25)
        self.assertEqual(org1["critical_products"], ["Core Banking Framework", "Identity Provider SaaS"])

        # ORG-002 (Agile Cloud Tech Startup)
        org2 = org_map["ORG-002"]
        self.assertEqual(org2["weight_modifiers"]["cvss_weight"], 0.2)
        self.assertEqual(org2["weight_modifiers"]["cisa_kev_weight"], 0.2)
        self.assertEqual(org2["weight_modifiers"]["first_epss_weight"], 0.6)
        self.assertEqual(org2["critical_products"], ["Cloud Database Engine", "Web Application Firewall"])

        # ORG-003 (Municipal Utility Provider)
        org3 = org_map["ORG-003"]
        self.assertEqual(org3["weight_modifiers"]["cvss_weight"], 0.5)
        self.assertEqual(org3["weight_modifiers"]["cisa_kev_weight"], 0.4)
        self.assertEqual(org3["weight_modifiers"]["first_epss_weight"], 0.1)
        self.assertEqual(org3["critical_products"], ["Embedded IoT Gateway", "Enterprise Router OS"])

    def test_org001_top_5_exact_ordering_and_scores(self):
        """Assert exact Top 5 order and risk scores for ORG-001."""
        org1 = next(o for o in self.organizations if o["org_id"] == "ORG-001")
        m_rep = match_products_for_organization(org1, self.vulnerabilities)
        ranked = rank_vulnerabilities(org1, m_rep["matched_vulnerabilities"])
        top_5 = get_top_n_vulnerabilities(ranked, 5)

        expected_cves = [
            "CVE-2023-1262",
            "CVE-2025-1728",
            "CVE-2023-8330",
            "CVE-2024-1699",
            "CVE-2025-7287"
        ]
        actual_cves = [v["cve_id"] for v in top_5]
        self.assertEqual(actual_cves, expected_cves, "Top 5 ordering for ORG-001 must be identical")

        expected_scores = [0.881328, 0.853745, 0.842463, 0.807305, 0.797185]
        for v, exp_score in zip(top_5, expected_scores):
            self.assertAlmostEqual(v["risk_score"], exp_score, places=5)

    def test_org002_top_5_exact_ordering_and_scores(self):
        """Assert exact Top 5 order and risk scores for ORG-002."""
        org2 = next(o for o in self.organizations if o["org_id"] == "ORG-002")
        m_rep = match_products_for_organization(org2, self.vulnerabilities)
        ranked = rank_vulnerabilities(org2, m_rep["matched_vulnerabilities"])
        top_5 = get_top_n_vulnerabilities(ranked, 5)

        expected_cves = [
            "CVE-2023-9945",
            "CVE-2025-5380",
            "CVE-2024-2122",
            "CVE-2026-1769",
            "CVE-2025-7668"
        ]
        actual_cves = [v["cve_id"] for v in top_5]
        self.assertEqual(actual_cves, expected_cves, "Top 5 ordering for ORG-002 must be identical")

        expected_scores = [0.897938, 0.875074, 0.842910, 0.838828, 0.829144]
        for v, exp_score in zip(top_5, expected_scores):
            self.assertAlmostEqual(v["risk_score"], exp_score, places=5)

    def test_org003_top_5_exact_ordering_and_scores(self):
        """Assert exact Top 5 order and risk scores for ORG-003."""
        org3 = next(o for o in self.organizations if o["org_id"] == "ORG-003")
        m_rep = match_products_for_organization(org3, self.vulnerabilities)
        ranked = rank_vulnerabilities(org3, m_rep["matched_vulnerabilities"])
        top_5 = get_top_n_vulnerabilities(ranked, 5)

        expected_cves = [
            "CVE-2025-3368",
            "CVE-2023-7303",
            "CVE-2026-5887",
            "CVE-2025-9666",
            "CVE-2025-7949"
        ]
        actual_cves = [v["cve_id"] for v in top_5]
        self.assertEqual(actual_cves, expected_cves, "Top 5 ordering for ORG-003 must be identical")

        expected_scores = [0.936983, 0.867322, 0.865613, 0.846747, 0.837517]
        for v, exp_score in zip(top_5, expected_scores):
            self.assertAlmostEqual(v["risk_score"], exp_score, places=5)

    def test_practitioner_validation_integrity(self):
        """Assert practitioner validation comparison yields identical rank differences."""
        comp_report = compare_with_practitioner(self.organizations, self.practitioners)
        
        # Check ORG-001 comparison
        org1_comp = comp_report["ORG-001"]["comparison"]
        cve_diffs_org1 = {item["cve_id"]: item["calculated_rank"] - item["practitioner_rank"] for item in org1_comp}
        expected_diffs_org1 = {
            "CVE-2025-1111": 0,
            "CVE-2024-3333": -1,
            "CVE-2025-4444": 1,
            "CVE-2026-2222": 0,
            "CVE-2024-5555": 0
        }
        self.assertEqual(cve_diffs_org1, expected_diffs_org1)

        # Check ORG-003 is unsupported gracefully
        self.assertFalse(comp_report["ORG-003"]["supported"])

if __name__ == "__main__":
    unittest.main()
