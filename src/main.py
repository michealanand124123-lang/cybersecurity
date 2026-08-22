import os
import sys

# Ensure parent directory is in Python path for absolute imports
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.append(PARENT_DIR)

from src.data_loader import load_organizations, load_vulnerabilities, load_practitioner
from src.matcher import match_products_for_organization
from src.ranking import rank_vulnerabilities, get_top_n_vulnerabilities
from src.validation import compare_with_practitioner

def print_section_header(title):
    print("=" * 80)
    print(f" {title.upper()} ".center(80, "#"))
    print("=" * 80)

def main():
    print_section_header("Task 1: Data Inspection & Validation")
    
    # 1. Load datasets
    try:
        organizations, org_errors = load_organizations()
        vulnerabilities, vuln_errors, vuln_duplicates, product_counts, vuln_columns = load_vulnerabilities()
        practitioner_vulns, prac_errors = load_practitioner()
    except Exception as e:
        print(f"CRITICAL ERROR loading datasets: {e}")
        sys.exit(1)
        
    # Print general counts
    print(f"Number of Organisations: {len(organizations)}")
    print(f"Number of Vulnerability Records: {len(vulnerabilities)}")
    print(f"Vulnerability CSV Column Names: {', '.join(vuln_columns)}")
    print(f"Number of Practitioner Reference Records: {len(practitioner_vulns)}")
    print()
    
    # Product distribution
    print("Vulnerabilities count per product:")
    for prod, count in sorted(product_counts.items(), key=lambda x: -x[1]):
        print(f" - {prod}: {count} records")
    print()
    
    # Org info
    print("Organizations and their critical products:")
    for org in organizations:
        print(f" - {org['name']} ({org['org_id']}): {org['critical_products']}")
    print()
    
    # Errors & Validation
    print("Validation reports:")
    all_errors = org_errors + vuln_errors + prac_errors
    if all_errors:
        print(f"[!] Validation found {len(all_errors)} issues:")
        for err in all_errors[:15]: # Show first 15 errors
            print(f"   - {err}")
        if len(all_errors) > 15:
            print(f"   ... and {len(all_errors) - 15} more validation errors.")
    else:
        print(" [+] No validation or parsing errors found. All data formats are valid.")
        
    # Duplicates report
    if vuln_duplicates:
        print(f"[!] Found {len(vuln_duplicates)} duplicate CVE/product records:")
        for dup in vuln_duplicates:
            print(f"   - Row {dup['line_number']}: Duplicate combination for CVE {dup['cve_id']} and Product '{dup['product_name']}'")
    else:
        print(" [+] No duplicate CVE/product records found in vulnerabilities CSV.")
    print()

    print_section_header("Task 2: Product Matching")
    
    match_reports = []
    for org in organizations:
        report = match_products_for_organization(org, vulnerabilities)
        match_reports.append(report)
        
        print(f"Organization: {report['org_name']}")
        print(f"Critical Products: {report['critical_products']}")
        print(f"Total matching vulnerabilities: {len(report['matched_vulnerabilities'])}")
        
        matched_cves = [v['cve_id'] for v in report['matched_vulnerabilities']]
        unique_matched_cves = sorted(list(set(matched_cves)))
        print(f"Matched CVE IDs ({len(unique_matched_cves)} unique): {', '.join(unique_matched_cves)}")
        
        if report['zero_match_products']:
            print(f" [*] Products with ZERO matches: {report['zero_match_products']}")
        else:
            print(" [+] All critical products have at least one vulnerability match.")
        print("-" * 80)
    print()

    print_section_header("Tasks 3 & 4: Risk Scoring and Top 5 Ranking")
    
    org_rankings = {}
    for org, m_rep in zip(organizations, match_reports):
        # Rank vulnerabilities
        ranked_vulns = rank_vulnerabilities(org, m_rep["matched_vulnerabilities"])
        org_rankings[org["org_id"]] = ranked_vulns
        
        # Get Top 5
        top_5 = get_top_n_vulnerabilities(ranked_vulns, 5)
        
        print(f"\nRANKING REPORT FOR: {org['name']} ({org['sector']} sector)")
        print(f"Risk Appetite: {org['risk_appetite']}")
        weights = org['weight_modifiers']
        print(f"Weights applied - CVSS: {weights['cvss_weight']}, KEV: {weights['cisa_kev_weight']}, EPSS: {weights['first_epss_weight']}")
        print("-" * 80)
        
        if not top_5:
            print("No vulnerabilities matched for this organization.")
            continue
            
        # Draw table
        header = f"{'Rank':<5} | {'CVE ID':<13} | {'Product Name':<28} | {'CVSS':<5} | {'KEV':<5} | {'EPSS':<7} | {'Risk Score':<10}"
        print(header)
        print("-" * len(header))
        
        for idx, item in enumerate(top_5, start=1):
            kev_str = "True" if item["cisa_kev"] else "False"
            row_str = f"{idx:<5} | {item['cve_id']:<13} | {item['product_name'][:28]:<28} | {item['cvss_base_score']:<5} | {kev_str:<5} | {item['first_epss']:<7} | {item['risk_score']:<10.6f}"
            print(row_str)
            # Explainability metrics
            expl_str = f"      -> Contributions: CVSS: {item['cvss_contribution']:.4f}  |  KEV: {item['kev_contribution']:.4f}  |  EPSS: {item['epss_contribution']:.4f}"
            print(expl_str)
        print("-" * 80)
    print()

    print_section_header("Task 5: Validation against Practitioner Ratings")
    
    comp_report = compare_with_practitioner(organizations, practitioner_vulns)
    
    for org_id, info in comp_report.items():
        print(f"\nCOMPARISON FOR: {info['org_name']}")
        print("-" * 80)
        if not info["supported"]:
            print(info["reason"])
            continue
            
        comparison_list = info["comparison"]
        
        # Print table comparing calculated rank vs practitioner rank
        header = f"{'CVE ID':<13} | {'Product Name':<28} | {'Risk Score':<10} | {'Calculated Rank':<16} | {'Practitioner Rank':<17} | {'Rank Diff':<10}"
        print(header)
        print("-" * len(header))
        
        for item in comparison_list:
            prac_rank = item["practitioner_rank"]
            calc_rank = item["calculated_rank"]
            if prac_rank is not None:
                diff_val = calc_rank - prac_rank
                diff_str = f"+{diff_val}" if diff_val > 0 else (str(diff_val) if diff_val < 0 else "0")
            else:
                diff_str = "N/A"
            
            row_str = f"{item['cve_id']:<13} | {item['product_name'][:28]:<28} | {item['risk_score']:<10.6f} | {calc_rank:<16} | {prac_rank:<17} | {diff_str:<10}"
            print(row_str)
        print("-" * 80)
    print("\n")

if __name__ == "__main__":
    main()
