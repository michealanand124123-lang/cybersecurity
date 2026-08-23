import unittest
import os
import sys
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.append(BASE_DIR)

from src.dataset_parser import parse_and_inspect_dataset, classify_dataset, detect_column_mappings

class TestUploadAndSchemaDetection(unittest.TestCase):
    """
    Validates auto-upload parsing, schema detection, column mapping,
    strict data quality isolation without zero-defaulting, and duplicate handling.
    """

    def test_csv_upload_with_alternative_column_names(self):
        """Verify automatic detection and mapping of alternative column aliases in CSV."""
        sample_csv = (
            "CVE,affected_product,cvss_score,known_exploited,epss_probability\n"
            "CVE-2024-1001,Core Banking Framework,8.8,true,0.6521\n"
            "CVE-2024-1002,Identity Provider SaaS,7.2,false,0.1245\n"
        )
        res = parse_and_inspect_dataset(sample_csv, "test_alt_columns.csv")
        self.assertTrue(res["is_valid"])
        self.assertEqual(res["dataset_type"], "vulnerability_dataset")
        self.assertEqual(res["total_records"], 2)
        self.assertEqual(len(res["valid_records"]), 2)
        
        # Check mapped record fields
        first = res["valid_records"][0]
        self.assertEqual(first["cve_id"], "CVE-2024-1001")
        self.assertEqual(first["product_name"], "Core Banking Framework")
        self.assertEqual(first["cvss_base_score"], 8.8)
        self.assertTrue(first["cisa_kev"])
        self.assertAlmostEqual(first["first_epss"], 0.6521, places=4)

    def test_json_upload_parsing(self):
        """Verify JSON array and object structures are parsed and normalized."""
        sample_json = json.dumps({
            "vulnerabilities": [
                {
                    "vulnerability_id": "CVE-2025-9999",
                    "technology": "Cloud Database Engine",
                    "cvss_base": 9.5,
                    "in_kev": True,
                    "epss": 0.8872
                }
            ]
        })
        res = parse_and_inspect_dataset(sample_json, "test_vulns.json")
        self.assertTrue(res["is_valid"])
        self.assertEqual(len(res["valid_records"]), 1)
        self.assertEqual(res["valid_records"][0]["cve_id"], "CVE-2025-9999")
        self.assertEqual(res["valid_records"][0]["product_name"], "Cloud Database Engine")

    def test_strict_quality_validation_no_zero_defaulting(self):
        """
        Verify missing or out-of-bound fields are marked invalid and excluded,
        NEVER silently coerced to 0.0.
        """
        csv_with_errors = (
            "cve_id,product_name,cvss_base_score,cisa_kev,first_epss\n"
            "CVE-2024-0001,Valid Product,8.0,true,0.5\n"
            "CVE-2024-0002,,7.0,false,0.3\n" # Missing product
            "CVE-2024-0003,Product B,,false,0.3\n" # Missing CVSS
            "CVE-2024-0004,Product C,14.5,false,0.3\n" # Out of bound CVSS (>10)
            "CVE-2024-0005,Product D,6.0,not_a_bool,0.3\n" # Invalid KEV
            "CVE-2024-0006,Product E,6.0,true,1.5\n" # Out of bound EPSS (>1)
        )
        res = parse_and_inspect_dataset(csv_with_errors, "test_errors.csv")
        self.assertTrue(res["is_valid"]) # Has 1 valid record
        self.assertEqual(res["total_records"], 6)
        self.assertEqual(len(res["valid_records"]), 1)
        self.assertEqual(len(res["invalid_records"]), 5)
        
        # Check that invalid records are explicitly listed with reasons
        reasons_list = [r["reasons"] for r in res["invalid_records"]]
        self.assertTrue(any("Missing Product Name" in r for r in reasons_list))
        self.assertTrue(any("Missing CVSS base score" in r for r in reasons_list))
        self.assertTrue(any("must be float in [0.0, 10.0]" in str(r) for r in reasons_list))
        self.assertTrue(any("must be boolean" in str(r) for r in reasons_list))
        self.assertTrue(any("must be float in [0.0, 1.0]" in str(r) for r in reasons_list))

    def test_duplicate_detection_by_cve_and_product(self):
        """Verify duplicates are identified based on (cve_id, product_name) composite key."""
        csv_with_dupes = (
            "cve_id,product_name,cvss_base_score,cisa_kev,first_epss\n"
            "CVE-2024-1111,Identity Provider SaaS,8.0,true,0.5\n"
            "CVE-2024-1111,Identity Provider SaaS,8.0,true,0.5\n" # Exact Duplicate
            "CVE-2024-1111,Different Product,8.0,true,0.5\n" # Legitimate different product with same CVE
        )
        res = parse_and_inspect_dataset(csv_with_dupes, "test_dupes.csv")
        self.assertEqual(res["quality_report"]["duplicates_count"], 1)
        self.assertEqual(len(res["valid_records"]), 3)

    def test_dataset_classification_types(self):
        """Verify classifier correctly recognizes vulnerability vs organization vs unknown."""
        # Vulnerability cols
        vuln_cols = ["cve_id", "product_name", "cvss_base_score", "cisa_kev", "first_epss"]
        self.assertEqual(classify_dataset(vuln_cols), "vulnerability_dataset")
        
        # Org cols
        org_cols = ["org_id", "name", "sector", "risk_appetite", "weight_modifiers", "critical_products"]
        self.assertEqual(classify_dataset(org_cols), "organization_profile")
        
        # Unknown
        unknown_cols = ["student_id", "grade", "subject", "teacher"]
        self.assertEqual(classify_dataset(unknown_cols), "unknown_dataset")

    def test_empty_file_handling(self):
        """Verify empty file returns clear error without crashing."""
        res = parse_and_inspect_dataset("", "empty.csv")
        self.assertFalse(res["is_valid"])
        self.assertIn("empty", res["error"].lower())

if __name__ == "__main__":
    unittest.main()
