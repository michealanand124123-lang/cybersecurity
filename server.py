import os
import sys
import json
import mimetypes
import traceback
from http.server import HTTPServer, BaseHTTPRequestHandler

# Add current directory and src directory to Python path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.append(CURRENT_DIR)

from src.data_loader import load_organizations, load_vulnerabilities, load_practitioner
from src.matcher import match_products_for_organization
from src.ranking import rank_vulnerabilities, get_top_n_vulnerabilities
from src.validation import compare_with_practitioner
from src.ai_advisor import get_ai_service_status, analyze_vulnerability_with_ai, generate_executive_summary_with_ai
from src.dataset_parser import parse_and_inspect_dataset
from src.simulator import run_remediation_simulation, compute_best_first_fix

# In-memory active session store (Leaves physical baseline files completely untouched)
_session_dataset = {
    "is_custom": False,
    "source_type": "bundled", # "bundled" or "uploaded"
    "source_name": "Bundled Baseline Dataset (data/vulnerabilities.csv)",
    "vulnerabilities": None,
    "total_records": 0,
    "valid_records_count": 0,
    "quality_report": None,
    "detected_columns": []
}

def get_active_vulnerabilities():
    """
    Returns active in-memory vulnerabilities.
    Lazily loads default bundled baseline if session has no custom dataset.
    """
    global _session_dataset
    if _session_dataset["vulnerabilities"] is None:
        vulns, vuln_errors, vuln_duplicates, product_counts, vuln_columns = load_vulnerabilities()
        _session_dataset["vulnerabilities"] = vulns
        _session_dataset["total_records"] = len(vulns)
        _session_dataset["valid_records_count"] = len(vulns)
        _session_dataset["detected_columns"] = vuln_columns
        _session_dataset["is_custom"] = False
        _session_dataset["source_type"] = "bundled"
        _session_dataset["source_name"] = "Bundled Baseline Dataset (data/vulnerabilities.csv)"
    return _session_dataset["vulnerabilities"]

def build_full_dashboard_data():
    """
    Executes the unmodified deterministic pipeline for all organizations
    against the single active in-memory vulnerabilities dataset.
    """
    organizations, org_errors = load_organizations()
    active_vulns = get_active_vulnerabilities()
    practitioners, prac_errors = load_practitioner()
    
    # Validation comparisons using practitioner dataset
    comp_report = compare_with_practitioner(organizations, practitioners)
    
    # Calculate product distribution across active dataset
    product_counts = {}
    for v in active_vulns:
        p = v.get("product_name")
        if p:
            product_counts[p] = product_counts.get(p, 0) + 1
            
    org_data = {}
    for org in organizations:
        org_id = org["org_id"]
        
        # 1. Match products using existing matcher
        m_rep = match_products_for_organization(org, active_vulns)
        
        # 2. Rank vulnerabilities using existing ranker
        ranked = rank_vulnerabilities(org, m_rep["matched_vulnerabilities"])
        
        # 3. Slice top 5
        top_5 = get_top_n_vulnerabilities(ranked, 5)
        
        org_data[org_id] = {
            "critical_products": org["critical_products"],
            "weight_modifiers": org["weight_modifiers"],
            "match_report": {
                "matched_count": len(m_rep["matched_vulnerabilities"]),
                "zero_match_products": m_rep["zero_match_products"],
                "product_matches_count": {p: len(vulns) for p, vulns in m_rep["product_matches"].items()}
            },
            "top_5": top_5,
            "ranked_vulnerabilities": ranked
        }

    return {
        "organizations": organizations,
        "errors": {
            "org_errors": org_errors,
            "vuln_errors": [],
            "prac_errors": prac_errors,
            "duplicates": []
        },
        "org_data": org_data,
        "validation_report": comp_report,
        "product_distribution": product_counts,
        "dataset_meta": {
            "is_custom": _session_dataset["is_custom"],
            "source_type": _session_dataset.get("source_type", "bundled"),
            "source_name": _session_dataset["source_name"],
            "total_records": _session_dataset["total_records"],
            "valid_records": _session_dataset["valid_records_count"],
            "quality_report": _session_dataset.get("quality_report")
        }
    }

class VulnTriageHandler(BaseHTTPRequestHandler):
    def end_headers(self):
        # Allow cross-origin requests for debugging/port flexibility
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        if self.path == '/api/ai/status':
            try:
                status_info = get_ai_service_status()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(status_info).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e)}).encode('utf-8'))
            return

        if self.path == '/api/data':
            try:
                response_data = build_full_dashboard_data()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response_data).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                error_response = {
                    "error": str(e),
                    "traceback": traceback.format_exc()
                }
                self.wfile.write(json.dumps(error_response).encode('utf-8'))
            return

        # Handle static site requests
        path = self.path.split('?')[0]
        if path == '/':
            path = '/index.html'
        
        file_path = os.path.join(CURRENT_DIR, 'static', path.lstrip('/'))
        
        if os.path.exists(file_path) and os.path.isfile(file_path):
            mime_type, _ = mimetypes.guess_type(file_path)
            if not mime_type:
                mime_type = 'application/octet-stream'
            
            self.send_response(200)
            self.send_header('Content-Type', mime_type)
            self.end_headers()
            with open(file_path, 'rb') as f:
                self.wfile.write(f.read())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Static resource not found.")

    def do_POST(self):
        global _session_dataset
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else '{}'
        
        try:
            body = json.loads(post_data)
        except Exception:
            body = {}

        # ----------------------------------------------------
        # 1. AUTO UPLOAD & SCHEMA DETECTION: INSPECT
        # ----------------------------------------------------
        if self.path == '/api/upload/inspect':
            try:
                file_content = body.get("file_content", "")
                filename = body.get("filename", "uploaded_dataset")
                
                if not file_content:
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "No file content provided."}).encode('utf-8'))
                    return
                    
                inspection = parse_and_inspect_dataset(file_content, filename)
                self.send_response(200 if inspection.get("is_valid", False) or inspection.get("dataset_type") == "organization_profile" else 422)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(inspection).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e), "traceback": traceback.format_exc()}).encode('utf-8'))
            return

        # ----------------------------------------------------
        # 2. AUTO UPLOAD & SCHEMA DETECTION: IMPORT & ACTIVATE
        # ----------------------------------------------------
        elif self.path == '/api/upload/import':
            try:
                file_content = body.get("file_content", "")
                filename = body.get("filename", "uploaded_dataset")
                
                if not file_content:
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Missing file content to import."}).encode('utf-8'))
                    return
                    
                inspection = parse_and_inspect_dataset(file_content, filename)
                valid_records = inspection.get("valid_records", [])
                
                if not valid_records:
                    self.send_response(422)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({
                        "error": "Dataset contains zero valid vulnerability records for deterministic scoring.",
                        "quality_report": inspection.get("quality_report")
                    }).encode('utf-8'))
                    return
                    
                # Activate in in-memory session only (Never overwrites physical files)
                _session_dataset["is_custom"] = True
                _session_dataset["source_type"] = "uploaded"
                _session_dataset["source_name"] = f"Uploaded Dataset ({filename})"
                _session_dataset["vulnerabilities"] = valid_records
                _session_dataset["total_records"] = inspection.get("total_records", len(valid_records))
                _session_dataset["valid_records_count"] = len(valid_records)
                _session_dataset["quality_report"] = inspection.get("quality_report")
                _session_dataset["detected_columns"] = inspection.get("detected_columns", [])
                
                print(f"[Dataset Import] Activated uploaded dataset '{filename}' with {len(valid_records)} valid records.")
                
                # Re-run existing engine for all organizations and return full dashboard
                fresh_data = build_full_dashboard_data()
                fresh_data["import_summary"] = {
                    "filename": filename,
                    "processed_count": inspection.get("total_records"),
                    "valid_count": len(valid_records),
                    "invalid_count": inspection.get("quality_report", {}).get("invalid_count", 0),
                    "duplicates_count": inspection.get("quality_report", {}).get("duplicates_count", 0),
                    "column_mappings": inspection.get("column_mappings", {})
                }
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(fresh_data).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e), "traceback": traceback.format_exc()}).encode('utf-8'))
            return

        # ----------------------------------------------------
        # 3. DATASET RESET TO BUNDLED BASELINE
        # ----------------------------------------------------
        elif self.path == '/api/dataset/reset':
            try:
                _session_dataset["is_custom"] = False
                _session_dataset["source_type"] = "bundled"
                _session_dataset["source_name"] = "Bundled Baseline Dataset (data/vulnerabilities.csv)"
                _session_dataset["vulnerabilities"] = None # Trigger lazy reload of bundled baseline
                _session_dataset["quality_report"] = None
                
                print("[Dataset Reset] Reverted in-memory session to Bundled Baseline Dataset.")
                
                fresh_data = build_full_dashboard_data()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(fresh_data).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e), "traceback": traceback.format_exc()}).encode('utf-8'))
            return

        # ----------------------------------------------------
        # 4. WHAT-IF RISK SIMULATOR: RUN
        # ----------------------------------------------------
        elif self.path == '/api/simulation/run':
            try:
                org_id = body.get("org_id")
                remediated_pairs = body.get("remediated_pairs", [])
                
                if not org_id:
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Missing required field: org_id"}).encode('utf-8'))
                    return
                    
                organizations, _ = load_organizations()
                target_org = next((o for o in organizations if o.get("org_id") == org_id), None)
                if not target_org:
                    self.send_response(404)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": f"Organization {org_id} not found"}).encode('utf-8'))
                    return
                    
                active_vulns = get_active_vulnerabilities()
                dataset_source = _session_dataset.get("source_name", "Active Dataset")
                print(f"[Simulator] Running simulation for org='{org_id}', Remediations={len(remediated_pairs)} | Active Source='{dataset_source}', Records={len(active_vulns)}")
                
                sim_result = run_remediation_simulation(target_org, active_vulns, remediated_pairs)
                sim_result["dataset_source"] = dataset_source
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(sim_result).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e), "traceback": traceback.format_exc()}).encode('utf-8'))
            return

        # ----------------------------------------------------
        # 5. WHAT-IF RISK SIMULATOR: BEST FIRST FIX
        # ----------------------------------------------------
        elif self.path == '/api/simulation/best-fix':
            try:
                org_id = body.get("org_id")
                if not org_id:
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Missing required field: org_id"}).encode('utf-8'))
                    return
                    
                organizations, _ = load_organizations()
                target_org = next((o for o in organizations if o.get("org_id") == org_id), None)
                if not target_org:
                    self.send_response(404)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": f"Organization {org_id} not found"}).encode('utf-8'))
                    return
                    
                active_vulns = get_active_vulnerabilities()
                dataset_source = _session_dataset.get("source_name", "Active Dataset")
                print(f"[Simulator] Evaluating Best First Fix for org='{org_id}' | Active Source='{dataset_source}', Records={len(active_vulns)}")
                
                best_fix = compute_best_first_fix(target_org, active_vulns)
                best_fix["dataset_source"] = dataset_source
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(best_fix).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e), "traceback": traceback.format_exc()}).encode('utf-8'))
            return

        # ----------------------------------------------------
        # 6. AI ADVISOR ENDPOINTS (Strictly Active Dataset)
        # ----------------------------------------------------
        elif self.path == '/api/ai/analyze-vulnerability':
            org_id = body.get("org_id")
            cve_id = body.get("cve_id")
            product_name = body.get("product_name")

            if not org_id or not cve_id:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing required fields: org_id and cve_id"}).encode('utf-8'))
                return

            try:
                active_vulns = get_active_vulnerabilities()
                dataset_source = _session_dataset.get("source_name", "Active Dataset")
                print(f"[AI Advisor] Request for org='{org_id}', cve='{cve_id}', prod='{product_name}' | Active Source='{dataset_source}', Records={len(active_vulns)}")
                
                result = analyze_vulnerability_with_ai(
                    org_id=org_id,
                    cve_id=cve_id,
                    product_name=product_name,
                    active_vulnerabilities=active_vulns,
                    dataset_source=dataset_source
                )
                
                status_code = 404 if "not_found" in result.get("status", "") else 200
                self.send_response(status_code)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(result).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e), "traceback": traceback.format_exc()}).encode('utf-8'))
            return

        elif self.path == '/api/ai/executive-summary':
            org_id = body.get("org_id")
            if not org_id:
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing required field: org_id"}).encode('utf-8'))
                return

            try:
                active_vulns = get_active_vulnerabilities()
                dataset_source = _session_dataset.get("source_name", "Active Dataset")
                print(f"[AI Advisor] Executive summary for org='{org_id}' | Active Source='{dataset_source}', Records={len(active_vulns)}")
                
                result = generate_executive_summary_with_ai(
                    org_id=org_id,
                    active_vulnerabilities=active_vulns,
                    dataset_source=dataset_source
                )
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(result).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": str(e), "traceback": traceback.format_exc()}).encode('utf-8'))
            return

        else:
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Endpoint not found"}).encode('utf-8'))

def run_server(port=5000):
    server_address = ('', port)
    httpd = HTTPServer(server_address, VulnTriageHandler)
    print(f"Server available at http://localhost:{port}/")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    print("Shutting down web server...")

if __name__ == '__main__':
    run_server()
