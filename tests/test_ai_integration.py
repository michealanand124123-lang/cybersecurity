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
    authoritative data ingestion, schema completeness, and fallback behavior.
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
        """Verify analyze_vulnerability_with_ai returns all 8 required sections and preserves official scores."""
        result = analyze_vulnerability_with_ai("ORG-001", "CVE-2023-1262")
        self.assertNotIn("error", result)
        self.assertEqual(result["cve_id"], "CVE-2023-1262")
        self.assertEqual(result["org_id"], "ORG-001")
        self.assertEqual(result["deterministic_rank"], 1)
        self.assertAlmostEqual(result["deterministic_risk_score"], 0.881328, places=5)
        
        # Verify required 8 explanation components
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

    def test_executive_summary_structure(self):
        """Verify executive summary generation for an organization."""
        result = generate_executive_summary_with_ai("ORG-001")
        self.assertNotIn("error", result)
        self.assertEqual(result["org_id"], "ORG-001")
        self.assertEqual(len(result["top_5_cves"]), 5)
        self.assertIn("executive_summary", result)

if __name__ == "__main__":
    unittest.main()
