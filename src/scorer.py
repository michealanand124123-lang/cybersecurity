def calculate_risk_score(vuln, weight_modifiers):
    """
    Calculates the risk score for a single vulnerability based on weight modifiers from an organization.
    
    Formula:
        CVSS_normalized = cvss_base_score / 10
        KEV_value = 1 if cisa_kev is True else 0
        Risk Score = (CVSS_normalized * cvss_weight) + (KEV_value * cisa_kev_weight) + (first_epss * first_epss_weight)
        
    Args:
        vuln (dict): Vulnerability record containing cvss_base_score, cisa_kev, first_epss
        weight_modifiers (dict): Weights (cvss_weight, cisa_kev_weight, first_epss_weight)
        
    Returns:
        dict: A dictionary containing:
            - "cvss_normalized": float
            - "kev_numeric": float (0.0 or 1.0)
            - "cvss_contribution": float
            - "kev_contribution": float
            - "epss_contribution": float
            - "risk_score": float
    """
    # Dynamic weights from organization config
    cvss_w = weight_modifiers.get("cvss_weight", 0.0)
    kev_w = weight_modifiers.get("cisa_kev_weight", 0.0)
    epss_w = weight_modifiers.get("first_epss_weight", 0.0)
    
    # Safe float parsing with fallbacks for missing/malformed fields
    cvss_base = vuln.get("cvss_base_score")
    if cvss_base is None:
        cvss_base = 0.0
        
    kev_bool = vuln.get("cisa_kev")
    if kev_bool is None:
         kev_bool = False
         
    epss = vuln.get("first_epss")
    if epss is None:
        epss = 0.0
        
    cvss_norm = cvss_base / 10.0
    kev_val = 1.0 if kev_bool else 0.0
    
    # Contribution calculation
    cvss_contrib = cvss_norm * cvss_w
    kev_contrib = kev_val * kev_w
    epss_contrib = epss * epss_w
    
    # Total score calculation
    risk_score = cvss_contrib + kev_contrib + epss_contrib
    
    return {
        "cvss_normalized": cvss_norm,
        "kev_numeric": kev_val,
        "cvss_contribution": round(cvss_contrib, 6),
        "kev_contribution": round(kev_contrib, 6),
        "epss_contribution": round(epss_contrib, 6),
        "risk_score": round(risk_score, 6)
    }
