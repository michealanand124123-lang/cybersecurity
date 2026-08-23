import os
import sys
import json
import urllib.request
import urllib.error
import re

# Ensure current directory is in sys.path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PARENT_DIR = os.path.dirname(CURRENT_DIR)
if PARENT_DIR not in sys.path:
    sys.path.append(PARENT_DIR)

from src.data_loader import load_organizations, load_vulnerabilities
from src.matcher import match_products_for_organization
from src.ranking import rank_vulnerabilities

FEATHERLESS_API_URL = "https://api.featherless.ai/v1/chat/completions"

def _load_env_file():
    """Lightweight .env loader without external third-party dependencies."""
    env_path = os.path.join(PARENT_DIR, ".env")
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "=" in line:
                        k, v = line.split("=", 1)
                        k = k.strip()
                        v = v.strip().strip("'\"")
                        if k:
                            os.environ[k] = v
        except Exception:
            pass

# Initialize environment from .env if present
_load_env_file()

def get_featherless_config():
    """
    Retrieves Featherless AI configuration from environment.
    Never exposes or logs the API key.
    """
    _load_env_file()
    api_key = os.environ.get("FEATHERLESS_API_KEY", "").strip()
    model = os.environ.get("FEATHERLESS_MODEL", "").strip()
    return {
        "api_key": api_key,
        "model": model,
        "is_configured": bool(api_key and model)
    }

def get_ai_service_status():
    """
    Returns sanitized AI service status for the frontend/API.
    NEVER returns or leaks the API key.
    """
    config = get_featherless_config()
    return {
        "configured": config["is_configured"],
        "model": config["model"] if config["model"] else None,
        "provider": "Featherless AI",
        "status": "ready" if config["is_configured"] else "fallback_mode",
        "description": "Featherless AI Natural-Language Advisory Layer"
    }

def get_authoritative_vuln_context(org_id, cve_id, product_name=None, active_vulnerabilities=None, dataset_source=None):
    """
    Retrieves authoritative organization and vulnerability records strictly using org_id, cve_id,
    and the single ACTIVE dataset (in-memory session or baseline).
    Never trusts frontend-supplied calculations.
    
    Args:
        org_id (str): Organization ID (e.g. 'ORG-001')
        cve_id (str): Vulnerability CVE ID
        product_name (str, optional): Product name for disambiguation among multiple affected products
        active_vulnerabilities (list, optional): Active normalized vulnerability records. If None, loads baseline.
        dataset_source (str, optional): Name/provenance of the active dataset.
        
    Returns:
        dict containing all authoritative metrics and context, or None if not found in active dataset.
    """
    organizations, _ = load_organizations()
    
    # Resolve active vulnerabilities from session or fallback
    if active_vulnerabilities is not None:
        vulnerabilities = active_vulnerabilities
        source_label = dataset_source or "Active Uploaded Dataset"
    else:
        vulnerabilities, _, _, _, _ = load_vulnerabilities()
        source_label = dataset_source or "Bundled Baseline Dataset (data/vulnerabilities.csv)"
    
    # 1. Locate organization
    target_org = next((o for o in organizations if o.get("org_id") == org_id), None)
    if not target_org:
        return None
        
    # 2. Match products and rank vulnerabilities using authoritative pipeline
    match_rep = match_products_for_organization(target_org, vulnerabilities)
    ranked_vulns = rank_vulnerabilities(target_org, match_rep["matched_vulnerabilities"])
    
    # 3. Find candidate matches for this cve_id in the active dataset
    matches = []
    for idx, v in enumerate(ranked_vulns, start=1):
        if v["cve_id"].upper() == cve_id.upper():
            matches.append((idx, v))
            
    if not matches:
        return None
        
    # If product_name is provided for disambiguation among multiple matches
    selected_rank = None
    selected_vuln = None
    if product_name:
        prod_norm = product_name.strip().lower()
        for r_idx, v in matches:
            if v["product_name"].strip().lower() == prod_norm:
                selected_rank = r_idx
                selected_vuln = v
                break
                
    if not selected_vuln:
        selected_rank, selected_vuln = matches[0]
        
    # 4. Construct authoritative record
    return {
        "org_id": target_org["org_id"],
        "org_name": target_org["name"],
        "org_sector": target_org.get("sector", "Not specified"),
        "risk_appetite": target_org.get("risk_appetite", "Standard"),
        "critical_products": target_org.get("critical_products", []),
        "weights": target_org.get("weight_modifiers", {}),
        "cve_id": selected_vuln["cve_id"],
        "matched_product": selected_vuln["product_name"],
        "cvss_base_score": selected_vuln.get("cvss_base_score", 0.0),
        "cvss_normalized": round(selected_vuln.get("cvss_base_score", 0.0) / 10.0, 6),
        "cisa_kev": bool(selected_vuln.get("cisa_kev", False)),
        "first_epss": selected_vuln.get("first_epss", 0.0),
        "cvss_contribution": selected_vuln.get("cvss_contribution", 0.0),
        "kev_contribution": selected_vuln.get("kev_contribution", 0.0),
        "epss_contribution": selected_vuln.get("epss_contribution", 0.0),
        "official_risk_score": selected_vuln.get("risk_score", 0.0),
        "official_rank": selected_rank,
        "total_matched_count": len(ranked_vulns),
        "dataset_source": source_label
    }

def generate_deterministic_fallback_analysis(context):
    """
    Generates a structured, authoritative natural-language explanation strictly
    from deterministic math and context when Featherless AI is unconfigured or offline.
    """
    org_name = context["org_name"]
    cve_id = context["cve_id"]
    product = context["matched_product"]
    risk_score = context["official_risk_score"]
    rank = context["official_rank"]
    total = context["total_matched_count"]
    cvss = context["cvss_base_score"]
    kev = context["cisa_kev"]
    epss = context["first_epss"]
    weights = context["weights"]
    dataset_source = context.get("dataset_source", "Active Dataset")
    
    cvss_w = weights.get("cvss_weight", 0.0)
    kev_w = weights.get("cisa_kev_weight", 0.0)
    epss_w = weights.get("first_epss_weight", 0.0)
    
    cvss_c = context["cvss_contribution"]
    kev_c = context["kev_contribution"]
    epss_c = context["epss_contribution"]
    
    # Explain why prioritized
    reasons = []
    reasons.append(f"Directly impacts critical monitored asset '{product}' belonging to {org_name}.")
    if kev:
        reasons.append(f"Confirmed active in-the-wild exploitation cataloged in CISA KEV (contributing +{kev_c:.6f} to risk score).")
    else:
        reasons.append("No confirmed active exploitation listed in CISA KEV.")
    reasons.append(f"Technical base severity assessed at CVSS {cvss:.1f}/10 (contributing +{cvss_c:.6f}).")
    reasons.append(f"Statistical exploit likelihood assessed at {(epss * 100):.3f}% via FIRST EPSS (contributing +{epss_c:.6f}).")
    
    why_prioritized = " ".join(reasons)
    
    score_explanation = (
        f"The official deterministic risk score of {risk_score:.6f} is calculated via VULNTRIAGE composite formula: "
        f"CVSS Normalized ({(cvss/10):.2f} × {cvss_w}) = +{cvss_c:.6f}, "
        f"CISA KEV ({'1.0' if kev else '0.0'} × {kev_w}) = +{kev_c:.6f}, and "
        f"FIRST EPSS ({epss:.5f} × {epss_w}) = +{epss_c:.6f}."
    )
    
    org_context = (
        f"{org_name} operates in the {context['org_sector']} sector with a {context['risk_appetite']} risk appetite. "
        f"Applied prioritization weights emphasize CVSS ({cvss_w}), KEV ({kev_w}), and EPSS ({epss_w})."
    )
    
    ranking_context = (
        f"Ranked #{rank} out of {total} total matched vulnerabilities for {org_name} within {dataset_source}. "
        f"{'This represents the highest priority vulnerability requiring immediate review.' if rank == 1 else f'Positioned at rank #{rank} among top organizational priorities.'}"
    )
    
    recommended_review = (
        f"Verify the deployment status of {product} within {org_name}'s infrastructure. "
        f"{'Prioritize immediate mitigation or isolation due to active KEV exploitation.' if kev else 'Schedule remediation according to organizational patch policy.'}"
    )
    
    data_limitations = (
        "Not provided in the available dataset: Internet exposure status, specific patch release availability, "
        "deployed asset instance counts, threat actor attribution, and remediation lifecycle state."
    )
    
    return {
        "why_prioritized": why_prioritized,
        "score_contribution_explanation": score_explanation,
        "organization_context": org_context,
        "ranking_context": ranking_context,
        "recommended_review": recommended_review,
        "data_limitations": data_limitations,
        "summary": f"{cve_id} on {product} evaluated with official deterministic risk score {risk_score:.6f} (Rank #{rank} of {total}) from {dataset_source}."
    }

def analyze_vulnerability_with_ai(org_id, cve_id, product_name=None, active_vulnerabilities=None, dataset_source=None):
    """
    Main entry point to generate explainable AI natural-language analysis for a vulnerability.
    Retrieves authoritative context strictly from the active dataset and prompts Featherless AI
    (or gracefully falls back to deterministic template).
    
    Never falls back to the bundled baseline if a custom dataset is active.
    """
    context = get_authoritative_vuln_context(
        org_id=org_id,
        cve_id=cve_id,
        product_name=product_name,
        active_vulnerabilities=active_vulnerabilities,
        dataset_source=dataset_source
    )
    
    source_name = dataset_source or ("Active Uploaded Dataset" if active_vulnerabilities is not None else "Bundled Baseline Dataset")
    
    if not context:
        return {
            "error": f"Vulnerability {cve_id} on '{product_name or 'any product'}' not found in active dataset ({source_name}) for organization {org_id}.",
            "status": "not_found",
            "dataset_source": source_name
        }
        
    config = get_featherless_config()
    
    # If Featherless AI is not configured, return deterministic fallback immediately
    if not config["is_configured"]:
        fallback_analysis = generate_deterministic_fallback_analysis(context)
        return {
            "cve_id": context["cve_id"],
            "product_name": context["matched_product"],
            "org_id": context["org_id"],
            "org_name": context["org_name"],
            "deterministic_risk_score": context["official_risk_score"],
            "deterministic_rank": context["official_rank"],
            "total_matched": context["total_matched_count"],
            "cvss_base_score": context["cvss_base_score"],
            "cisa_kev": context["cisa_kev"],
            "first_epss": context["first_epss"],
            "dataset_source": context["dataset_source"],
            "contributions": {
                "cvss": context["cvss_contribution"],
                "kev": context["kev_contribution"],
                "epss": context["epss_contribution"]
            },
            "analysis": fallback_analysis,
            "is_fallback": True,
            "fallback_reason": "FEATHERLESS_API_KEY or FEATHERLESS_MODEL not configured on server",
            "model_used": None
        }
        
    # Prompt formulation with strict authoritative constraints
    system_prompt = (
        "You are an expert enterprise cyber defense advisor for VULNTRIAGE. "
        "Your role is ONLY to explain an authoritative, deterministic vulnerability risk score and ranking "
        "already calculated by the backend scoring engine.\n\n"
        "STRICT CONSTRAINTS:\n"
        "1. You MUST NOT calculate, recalculate, or alter the risk score or rank.\n"
        "2. The provided risk score and rank are authoritative and final.\n"
        "3. You must use ONLY the authoritative fields provided in the prompt.\n"
        "4. DO NOT invent fields (such as internet exposure, patch status, asset count, threat actor, exploit details, service criticality, affected version, remediation status).\n"
        "5. For any unrecorded or unavailable information, explicitly state: 'Not provided in the available dataset.'\n"
        "6. Return your response as a valid JSON object matching the requested schema exactly."
    )
    
    user_payload = {
        "dataset_source": context["dataset_source"],
        "authoritative_data": {
            "dataset_source": context["dataset_source"],
            "organization_name": context["org_name"],
            "organization_sector": context["org_sector"],
            "risk_appetite": context["risk_appetite"],
            "critical_products": context["critical_products"],
            "cve_id": context["cve_id"],
            "matched_product": context["matched_product"],
            "cvss_base_score": context["cvss_base_score"],
            "cvss_normalized": context["cvss_normalized"],
            "cisa_kev": context["cisa_kev"],
            "first_epss": context["first_epss"],
            "cvss_contribution": context["cvss_contribution"],
            "kev_contribution": context["kev_contribution"],
            "epss_contribution": context["epss_contribution"],
            "official_deterministic_risk_score": context["official_risk_score"],
            "official_deterministic_rank": context["official_rank"],
            "total_matched_count": context["total_matched_count"],
            "organization_weights": context["weights"]
        },
        "required_json_format": {
            "why_prioritized": "String explaining why this vulnerability is prioritized based on product match, CVSS, KEV, and EPSS.",
            "score_contribution_explanation": "String detailing the mathematical score contribution breakdown across CVSS, KEV, and EPSS.",
            "organization_context": "String explaining how this aligns with the organization's sector, risk appetite, and critical assets.",
            "ranking_context": "String describing its position in the organization's ranking (Rank #X of Y) within the active dataset.",
            "recommended_review": "String providing actionable security review recommendations based on authoritative findings.",
            "data_limitations": "String explicitly listing data points that are not provided in the available dataset.",
            "summary": "Short 1-2 sentence executive overview."
        }
    }
    
    request_body = {
        "model": config["model"],
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(user_payload, indent=2)}
        ],
        "temperature": 0.2,
        "max_tokens": 1000,
        "response_format": {"type": "json_object"}
    }
    
    # Make API call with clean fallback handling
    try:
        req = urllib.request.Request(
            FEATHERLESS_API_URL,
            data=json.dumps(request_body).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {config['api_key']}",
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "HTTP-Referer": "https://vulntriage.local",
                "X-Title": "VulnTriage Cyber Defense"
            },
            method="POST"
        )
        
        with urllib.request.urlopen(req, timeout=12) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            
        content_str = res_data.get("choices", [{}])[0].get("message", {}).get("content", "")
        
        # Parse JSON from model response
        analysis_json = None
        try:
            analysis_json = json.loads(content_str)
        except Exception:
            # Attempt to extract JSON from markdown code block if model wrapped it
            json_match = re.search(r"\{.*\}", content_str, re.DOTALL)
            if json_match:
                analysis_json = json.loads(json_match.group(0))
                
        if not analysis_json or not isinstance(analysis_json, dict):
            raise ValueError("Model response could not be parsed into required JSON schema")
            
        # Ensure all required keys exist
        required_keys = [
            "why_prioritized", "score_contribution_explanation", "organization_context",
            "ranking_context", "recommended_review", "data_limitations", "summary"
        ]
        fallback_vals = generate_deterministic_fallback_analysis(context)
        for key in required_keys:
            if key not in analysis_json or not analysis_json[key]:
                analysis_json[key] = fallback_vals[key]
                
        return {
            "cve_id": context["cve_id"],
            "product_name": context["matched_product"],
            "org_id": context["org_id"],
            "org_name": context["org_name"],
            "deterministic_risk_score": context["official_risk_score"],
            "deterministic_rank": context["official_rank"],
            "total_matched": context["total_matched_count"],
            "cvss_base_score": context["cvss_base_score"],
            "cisa_kev": context["cisa_kev"],
            "first_epss": context["first_epss"],
            "dataset_source": context["dataset_source"],
            "contributions": {
                "cvss": context["cvss_contribution"],
                "kev": context["kev_contribution"],
                "epss": context["epss_contribution"]
            },
            "analysis": analysis_json,
            "is_fallback": False,
            "model_used": config["model"]
        }
        
    except Exception as e:
        # Graceful fallback without breaking application
        fallback_analysis = generate_deterministic_fallback_analysis(context)
        return {
            "cve_id": context["cve_id"],
            "product_name": context["matched_product"],
            "org_id": context["org_id"],
            "org_name": context["org_name"],
            "deterministic_risk_score": context["official_risk_score"],
            "deterministic_rank": context["official_rank"],
            "total_matched": context["total_matched_count"],
            "cvss_base_score": context["cvss_base_score"],
            "cisa_kev": context["cisa_kev"],
            "first_epss": context["first_epss"],
            "dataset_source": context["dataset_source"],
            "contributions": {
                "cvss": context["cvss_contribution"],
                "kev": context["kev_contribution"],
                "epss": context["epss_contribution"]
            },
            "analysis": fallback_analysis,
            "is_fallback": True,
            "fallback_reason": f"Featherless API invocation failed: {str(e)}",
            "model_used": None
        }

def generate_executive_summary_with_ai(org_id, active_vulnerabilities=None, dataset_source=None):
    """
    Generates a natural-language executive summary brief for the organization's Top 5 priorities
    strictly from the active dataset.
    """
    organizations, _ = load_organizations()
    
    if active_vulnerabilities is not None:
        vulnerabilities = active_vulnerabilities
        source_label = dataset_source or "Active Uploaded Dataset"
    else:
        vulnerabilities, _, _, _, _ = load_vulnerabilities()
        source_label = dataset_source or "Bundled Baseline Dataset (data/vulnerabilities.csv)"
    
    target_org = next((o for o in organizations if o.get("org_id") == org_id), None)
    if not target_org:
        return {"error": f"Organization {org_id} not found"}
        
    match_rep = match_products_for_organization(target_org, vulnerabilities)
    ranked = rank_vulnerabilities(target_org, match_rep["matched_vulnerabilities"])
    top_5 = ranked[:5]
    
    config = get_featherless_config()
    
    if not top_5:
        return {
            "org_id": org_id,
            "org_name": target_org["name"],
            "top_5_cves": [],
            "executive_summary": f"No matching vulnerabilities identified for {target_org['name']} in {source_label}.",
            "dataset_source": source_label,
            "is_fallback": True,
            "model_used": None
        }
        
    # Fallback deterministic summary
    top_5_summary = [
        f"Rank #{i+1}: {v['cve_id']} on {v['product_name']} (Risk Score: {v['risk_score']:.6f}, CVSS: {v['cvss_base_score']}, KEV: {v['cisa_kev']}, EPSS: {v['first_epss']:.4f})"
        for i, v in enumerate(top_5)
    ]
    
    fallback_exec_text = (
        f"Executive Brief for {target_org['name']} ({target_org['sector']} sector, Risk Appetite: {target_org['risk_appetite']}) "
        f"derived from {source_label}:\n\n"
        f"VULNTRIAGE evaluated {len(ranked)} matched vulnerabilities across critical products {target_org['critical_products']}. "
        f"The top threat vector is {top_5[0]['cve_id']} on {top_5[0]['product_name']} with an aggregated risk score of {top_5[0]['risk_score']:.6f}. "
        f"{sum(1 for v in top_5 if v['cisa_kev'])} out of the Top 5 prioritized vulnerabilities have confirmed active exploitation in CISA KEV."
    )
    
    if not config["is_configured"]:
        return {
            "org_id": org_id,
            "org_name": target_org["name"],
            "top_5_cves": [v["cve_id"] for v in top_5],
            "executive_summary": fallback_exec_text,
            "dataset_source": source_label,
            "is_fallback": True,
            "model_used": None
        }
        
    try:
        system_prompt = (
            "You are a CISO-level cyber defense advisor for VULNTRIAGE. "
            "Write a concise, professional 3-paragraph Executive Brief summarizing the Top 5 prioritized vulnerabilities "
            "for the specified organization. Use ONLY the provided authoritative data. Do NOT invent external metrics."
        )
        user_content = json.dumps({
            "dataset_source": source_label,
            "organization": target_org["name"],
            "sector": target_org["sector"],
            "risk_appetite": target_org["risk_appetite"],
            "critical_products": target_org["critical_products"],
            "top_5_vulnerabilities": top_5
        }, indent=2)
        
        req = urllib.request.Request(
            FEATHERLESS_API_URL,
            data=json.dumps({
                "model": config["model"],
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_content}
                ],
                "temperature": 0.2,
                "max_tokens": 1000
            }).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {config['api_key']}",
                "Content-Type": "application/json",
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                "HTTP-Referer": "https://vulntriage.local",
                "X-Title": "VulnTriage Cyber Defense"
            },
            method="POST"
        )
        
        with urllib.request.urlopen(req, timeout=12) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            
        exec_text = res_data.get("choices", [{}])[0].get("message", {}).get("content", "")
        if not exec_text:
            exec_text = fallback_exec_text
            
        return {
            "org_id": org_id,
            "org_name": target_org["name"],
            "top_5_cves": [v["cve_id"] for v in top_5],
            "executive_summary": exec_text,
            "dataset_source": source_label,
            "is_fallback": False,
            "model_used": config["model"]
        }
    except Exception:
        return {
            "org_id": org_id,
            "org_name": target_org["name"],
            "top_5_cves": [v["cve_id"] for v in top_5],
            "executive_summary": fallback_exec_text,
            "dataset_source": source_label,
            "is_fallback": True,
            "model_used": None
        }
