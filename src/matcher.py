import re

def normalize_string(s):
    """Lowercases, normalizes consecutive whitespace down to a single space, and strips outer whitespace."""
    if not s:
        return ""
    return re.sub(r"\s+", " ", s.strip().lower())

def match_products_for_organization(org, vulnerabilities):
    """
    Matches the critical products of an organization against a list of vulnerabilities.
    
    Args:
        org (dict): The organization dictionary object containing "critical_products"
        vulnerabilities (list): The list of vulnerability dictionaries loaded from CSV
        
    Returns:
        dict: A matching report containing:
            - "org_name": string
            - "critical_products": list of strings
            - "matched_vulnerabilities": list of matched vulnerability dicts
            - "product_matches": dict mapping each critical product to its matches
            - "zero_match_products": list of critical products that had 0 matches
    """
    org_name = org.get("name", "Unknown Org")
    critical_products = org.get("critical_products", [])
    
    # Normalize the critical products
    normalized_critical_map = {normalize_string(p): p for p in critical_products}
    
    product_matches = {p: [] for p in critical_products}
    matched_vulnerabilities = []
    
    for vuln in vulnerabilities:
        vuln_prod = vuln.get("product_name", "")
        normalized_vuln_prod = normalize_string(vuln_prod)
        
        # Check direct match after normalization
        if normalized_vuln_prod in normalized_critical_map:
            original_prod_name = normalized_critical_map[normalized_vuln_prod]
            product_matches[original_prod_name].append(vuln)
            matched_vulnerabilities.append(vuln)
            
    # Find zero match products
    zero_match_products = [p for p in critical_products if len(product_matches[p]) == 0]
    
    return {
        "org_name": org_name,
        "critical_products": critical_products,
        "matched_vulnerabilities": matched_vulnerabilities,
        "product_matches": product_matches,
        "zero_match_products": zero_match_products
    }
