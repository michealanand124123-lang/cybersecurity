from src.scorer import calculate_risk_score

def compare_with_practitioner(organizations, practitioner_vulns):
    """
    Compares our calculated ranking for practitioner vulnerabilities against the practitioner ranks.
    
    Args:
        organizations (list): The list of organization dictionaries
        practitioner_vulns (list): The list of practitioner vulnerability dictionaries
        
    Returns:
        dict: A dictionary mapping org_id to comparison results.
    """
    comparison_report = {}
    
    # Map org IDs to their corresponding practitioner rank column in practitioner.csv
    # e.g., ORG-001 is Global Retail Bank -> practitioner_rank_bank
    # ORG-002 is Agile Cloud Tech Startup -> practitioner_rank_startup
    org_rank_cols = {
        "ORG-001": "practitioner_rank_bank",
        "ORG-002": "practitioner_rank_startup"
    }
    
    for org in organizations:
        org_id = org["org_id"]
        org_name = org["name"]
        rank_col = org_rank_cols.get(org_id)
        
        if not rank_col:
            comparison_report[org_id] = {
                "org_name": org_name,
                "supported": False,
                "reason": f"No practitioner rank column found for {org_name} (ORG-003)."
            }
            continue
            
        # Score the practitioner vulnerabilities using this organization's weights
        scored_vulns = []
        for pv in practitioner_vulns:
            # Score
            score_details = calculate_risk_score(pv, org["weight_modifiers"])
            
            # Map practitioner rank
            prac_rank = pv["ranks"].get(rank_col)
            
            scored_vulns.append({
                "cve_id": pv["cve_id"],
                "product_name": pv["product_name"],
                "cvss_base_score": pv["cvss_base_score"],
                "cisa_kev": pv["cisa_kev"],
                "first_epss": pv["first_epss"],
                "risk_score": score_details["risk_score"],
                "practitioner_rank": prac_rank
            })
            
        # Sort our scored list by risk score descending
        # Secondary sort by CVSS descending, then CVE ID ascending for tie-breaks
        scored_vulns.sort(key=lambda x: (-x["risk_score"], -(x["cvss_base_score"] or 0.0), x["cve_id"]))
        
        # Assign our rank (1-based index)
        for rank_idx, item in enumerate(scored_vulns, start=1):
            item["calculated_rank"] = rank_idx
            
        comparison_report[org_id] = {
            "org_name": org_name,
            "supported": True,
            "comparison": scored_vulns
        }
        
    return comparison_report
