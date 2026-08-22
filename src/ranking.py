from src.scorer import calculate_risk_score

def rank_vulnerabilities(org, matched_vulns):
    """
    Computes risk scores and ranks the vulnerabilities matched for an organization.
    
    Args:
        org (dict): The organization config dict
        matched_vulns (list): List of vulnerabilities matched for this organization
        
    Returns:
        list: Sorted list of vulnerability reports containing details of scoring and contributions.
    """
    weight_modifiers = org.get("weight_modifiers", {})
    ranked_list = []
    
    for vuln in matched_vulns:
        score_details = calculate_risk_score(vuln, weight_modifiers)
        
        # Build the final record preserving all fields and explainability data
        record = {
            "cve_id": vuln["cve_id"],
            "product_name": vuln["product_name"],
            "cvss_base_score": vuln.get("cvss_base_score", 0.0),
            "cisa_kev": vuln.get("cisa_kev", False),
            "first_epss": vuln.get("first_epss", 0.0),
            "cvss_contribution": score_details["cvss_contribution"],
            "kev_contribution": score_details["kev_contribution"],
            "epss_contribution": score_details["epss_contribution"],
            "risk_score": score_details["risk_score"]
        }
        ranked_list.append(record)
        
    # Sort descending by risk score. In case of ties, sort by CVSS base score descending, then CVE ID ascending
    ranked_list.sort(key=lambda x: (-x["risk_score"], -x["cvss_base_score"], x["cve_id"]))
    
    return ranked_list

def get_top_n_vulnerabilities(ranked_vulns, n=5):
    """Slices and returns the Top N vulnerabilities."""
    return ranked_vulns[:n]
