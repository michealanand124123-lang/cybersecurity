import unittest
import os
import sys

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from src.ai_advisor import (
    get_ai_service_status,
    get_authoritative_vuln_context,
    analyze_vulnerability_with_ai,
    generate_executive_summary_with_ai
)

class TestAiIntegration(unittest.TestCase):
    """
    Validates Featherless AI explainability layer integration,
    active session dataset ingestion, provenance tracking, and strict fallback isolation.
    """

    def test_ai_status_sanitization(self):
        """Ensure get_ai_service_status never exposes API keys or secrets."""
        status = get_ai_service_status()
        self.assertIn("configured", status)
        self.assertIn("provider", status)
        self.assertIn("status", status)
        self.assertEqual(status["provider"], "Featherless AI")
        # Ensure no api_key or secret field exists in the response
        self.assertNotIn("api_key", status)
        self.assertNotIn("key", status)
        self.assertNotIn("secret", status)

    def test_authoritative_context_retrieval(self):
        """Verify authoritative context is derived strictly by org_id and cve_id."""
        context = get_authoritative_vuln_context("ORG-001", "CVE-2023-1262")
        self.assertIsNotNone(context, "Must find authoritative record for CVE-2023-1262")
        self.assertEqual(context["org_id"], "ORG-001")
        self.assertEqual(context["org_name"], "Global Retail Bank")
        self.assertEqual(context["matched_product"], "Identity Provider SaaS")
        self.assertEqual(context["cve_id"], "CVE-2023-1262")
        self.assertEqual(context["official_rank"], 1)
        self.assertAlmostEqual(context["official_risk_score"], 0.881328, places=5)
        self.assertEqual(context["cvss_base_score"], 7.5)
        self.assertTrue(context["cisa_kev"])
        self.assertAlmostEqual(context["first_epss"], 0.82531, places=5)
        self.assertAlmostEqual(context["cvss_contribution"], 0.2250, places=4)
        self.assertAlmostEqual(context["kev_contribution"], 0.4500, places=4)
        self.assertAlmostEqual(context["epss_contribution"], 0.2063, places=4)

    def test_frontend_cannot_override_product(self):
        """Verify frontend-supplied fake product is ignored in favor of authoritative backend match."""
        # Supply a fake product name that doesn't match
        context = get_authoritative_vuln_context("ORG-001", "CVE-2023-1262", product_name="Fake Injected Product")
        self.assertIsNotNone(context)
        # Must resolve to the true authoritative product
        self.assertEqual(context["matched_product"], "Identity Provider SaaS")
        self.assertAlmostEqual(context["official_risk_score"], 0.881328, places=5)

    def test_vulnerability_analysis_schema_and_integrity(self):
        """Verify analyze_vulnerability_with_ai returns all required sections and preserves official scores."""
        result = analyze_vulnerability_with_ai("ORG-001", "CVE-2023-1262")
        self.assertNotIn("error", result)
        self.assertEqual(result["cve_id"], "CVE-2023-1262")
        self.assertEqual(result["org_id"], "ORG-001")
        self.assertEqual(result["deterministic_rank"], 1)
        self.assertAlmostEqual(result["deterministic_risk_score"], 0.881328, places=5)
        
        # Verify required explanation components
        analysis = result.get("analysis", {})
        self.assertIn("why_prioritized", analysis)
        self.assertIn("score_contribution_explanation", analysis)
        self.assertIn("organization_context", analysis)
        self.assertIn("ranking_context", analysis)
        self.assertIn("recommended_review", analysis)
        self.assertIn("data_limitations", analysis)
        self.assertIn("summary", analysis)

        # Check data limitations mentions unrecorded fields
        self.assertIn("Not provided in the available dataset", analysis["data_limitations"])

    def test_invalid_cve_not_found(self):
        """Verify non-existent CVE returns a clean not_found response."""
        result = analyze_vulnerability_with_ai("ORG-001", "CVE-9999-0000")
        self.assertEqual(result.get("status"), "not_found")
        self.assertIn("error", result)

    def test_ai_advisor_with_uploaded_custom_dataset(self):
        """
        Rule 2 / Test A: AI Advisor must successfully analyze custom CVEs
        from an uploaded in-memory dataset that do not exist in the bundled baseline.
        """
        custom_uploaded_vulns = [
            {
                "cve_id": "CVE-CUSTOM-9999",
                "product_name": "Identity Provider SaaS",
                "cvss_base_score": 9.4,
                "cisa_kev": True,
                "first_epss": 0.95
            },
            {
                "cve_id": "CVE-CUSTOM-8888",
                "product_name": "Core Banking Framework",
                "cvss_base_score": 8.0,
                "cisa_kev": False,
                "first_epss": 0.40
            }
        ]
        
        result = analyze_vulnerability_with_ai(
            org_id="ORG-001",
            cve_id="CVE-CUSTOM-9999",
            product_name="Identity Provider SaaS",
            active_vulnerabilities=custom_uploaded_vulns,
            dataset_source="Uploaded Dataset (custom_feed.csv)"
        )
        
        self.assertNotIn("error", result)
        self.assertEqual(result["cve_id"], "CVE-CUSTOM-9999")
        self.assertEqual(result["product_name"], "Identity Provider SaaS")
        self.assertEqual(result["deterministic_rank"], 1)
        self.assertEqual(result["total_matched"], 2)
        self.assertEqual(result["dataset_source"], "Uploaded Dataset (custom_feed.csv)")
        
        # Numerical integrity check: CVSS 9.4 * 0.3 + KEV 1.0 * 0.45 + EPSS 0.95 * 0.25 = 0.282 + 0.45 + 0.2375 = 0.9695
        expected_score = round((9.4 / 10.0) * 0.30 + 1.0 * 0.45 + 0.95 * 0.25, 6)
        self.assertAlmostEqual(result["deterministic_risk_score"], expected_score, places=5)

    def test_ai_advisor_rejects_baseline_cve_when_uploaded_dataset_active(self):
        """
        Rule 3 / Test B: No Silent Fallback!
        If a custom dataset is active and the user requests a baseline CVE that is NOT
        in the custom dataset, return 'not_found' rather than silently loading the baseline.
        """
        custom_uploaded_vulns = [
            {
                "cve_id": "CVE-CUSTOM-9999",
                "product_name": "Identity Provider SaaS",
                "cvss_base_score": 9.4,
                "cisa_kev": True,
                "first_epss": 0.95
            }
        ]
        
        # Request baseline CVE-2023-1262 which is NOT in the custom uploaded list
        result = analyze_vulnerability_with_ai(
            org_id="ORG-001",
            cve_id="CVE-2023-1262",
            product_name="Identity Provider SaaS",
            active_vulnerabilities=custom_uploaded_vulns,
            dataset_source="Uploaded Dataset (isolated.csv)"
        )
        
        self.assertEqual(result.get("status"), "not_found")
        self.assertIn("error", result)
        self.assertIn("isolated.csv", result.get("dataset_source", ""))
        self.assertIn("not found in active dataset", result["error"])

    def test_ai_advisor_organization_switching(self):
        """
        Rule 8 / Test I: Switching organization with the same active dataset
        correctly updates matched critical products, weights, and ranking.
        """
        custom_uploaded_vulns = [
            {
                "cve_id": "CVE-SWITCH-001",
                "product_name": "Cloud Database Engine",
                "cvss_base_score": 9.0,
                "cisa_kev": True,
                "first_epss": 0.80
            }
        ]
        
        # ORG-002 is Agile Cloud Tech Startup whose critical product includes Cloud Database Engine
        result = analyze_vulnerability_with_ai(
            org_id="ORG-002",
            cve_id="CVE-SWITCH-001",
            product_name="Cloud Database Engine",
            active_vulnerabilities=custom_uploaded_vulns,
            dataset_source="Uploaded Dataset (tech.csv)"
        )
        
        self.assertNotIn("error", result)
        self.assertEqual(result["org_id"], "ORG-002")
        self.assertEqual(result["org_name"], "Agile Cloud Tech Startup")
        self.assertEqual(result["deterministic_rank"], 1)

    def test_executive_summary_structure(self):
        """Verify executive summary generation for an organization."""
        result = generate_executive_summary_with_ai("ORG-001")
        self.assertNotIn("error", result)
        self.assertEqual(result["org_id"], "ORG-001")
        self.assertEqual(len(result["top_5_cves"]), 5)
        self.assertIn("executive_summary", result)

if __name__ == "__main__":
    unittest.main()
