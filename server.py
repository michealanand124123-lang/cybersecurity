import os
import json
import mimetypes
import traceback
import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler

# Import authoritative deterministic backend functions (Strictly protected core)
from src.data_loader import load_organizations, load_vulnerabilities, load_practitioner
from src.matcher import match_products_for_organization
from src.ranking import rank_vulnerabilities, get_top_n_vulnerabilities
from src.validation import compare_with_practitioner
from src.ai_advisor import (
    analyze_vulnerability_with_ai,
    get_ai_service_status,
    generate_executive_summary_with_ai
)
from src.dataset_parser import parse_and_inspect_dataset, sanitize_dataset_filename
from src.simulator import run_remediation_simulation, compute_best_first_fix

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))

# Global Active Session Dataset Store (Single Source of Truth)
_session_dataset = {
    "is_custom": False,
    "source_type": "bundled",
    "source_name": "Bundled Baseline Dataset (data/vulnerabilities.csv)",
    "vulnerabilities": None, # Initialized lazily from bundled data
    "total_records": 0,
    "valid_records_count": 0,
    "quality_report": None,
    "detected_columns": []
}

def security_audit_log(event_type, client_ip, org_id=None, details=None):
    """Structured security audit event logger with timestamp and metadata (Zero secrets)."""
    ts = datetime.datetime.now(datetime.timezone.utc).isoformat()
    org_str = f"ORG={org_id}" if org_id else "ORG=N/A"
    det_str = f" | DETAILS={details}" if details else ""
    print(f"[SECURITY_AUDIT] {ts} | IP={client_ip} | EVENT={event_type} | {org_str}{det_str}")

def get_active_vulnerabilities():
    """
    Returns the single authoritative list of active vulnerabilities for the current session.
    If no custom dataset is active, loads the authoritative bundled baseline dataset.
    """
    global _session_dataset
    if _session_dataset["is_custom"] and _session_dataset["vulnerabilities"] is not None:
        return _session_dataset["vulnerabilities"]
    
    # Load bundled baseline dataset
    bundled_vulns = load_vulnerabilities()[0]
    if _session_dataset["vulnerabilities"] is None:
        _session_dataset["vulnerabilities"] = bundled_vulns
        _session_dataset["total_records"] = len(bundled_vulns)
        _session_dataset["valid_records_count"] = len(bundled_vulns)
    return bundled_vulns

def build_full_dashboard_data():
    """
    Executes the existing authoritative deterministic engine across all organizations
    using the SINGLE active session dataset.
    """
    global _session_dataset
    
    # 1. Authoritative Organization loading
    organizations, org_errors = load_organizations()
    active_vulns = get_active_vulnerabilities()
    practitioner_data, prac_errors = load_practitioner()

    # 2. Product distribution from active dataset
    product_counts = {}
    for v in active_vulns:
        p = v.get('product_name', 'Unknown')
        product_counts[p] = product_counts.get(p, 0) + 1

    org_data = {}
    comp_report = compare_with_practitioner(organizations, practitioner_data) if practitioner_data else {}

    for org in organizations:
        org_id = org['org_id']
        match_report = match_products_for_organization(org, active_vulns)
        matched_vulns = match_report.get("matched_vulnerabilities", [])
        ranked = rank_vulnerabilities(org, matched_vulns)
        top_5 = get_top_n_vulnerabilities(ranked, 5)

        # Include matched_count in match_report dict for frontend consumption
        match_report_dict = dict(match_report)
        match_report_dict["matched_count"] = len(matched_vulns)

        org_data[org_id] = {
            "matched_count": len(matched_vulns),
            "match_report": match_report_dict,
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
        # Security Headers
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type, Authorization')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'SAMEORIGIN')
        self.send_header('Referrer-Policy', 'strict-origin-when-cross-origin')
        self.send_header('Permissions-Policy', 'geolocation=(), camera=(), microphone=()')
        self.send_header('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self'; img-src 'self' data: https:;")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        client_ip = self.client_address[0] if self.client_address else "127.0.0.1"

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
                self.wfile.write(json.dumps({"error": "Unable to retrieve AI status."}).encode('utf-8'))
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
                self.wfile.write(json.dumps({"error": "Unable to process dashboard data."}).encode('utf-8'))
            return

        # Handle static site requests
        path = self.path.split('?')[0]
        if path == '/':
            path = '/index.html'
        
        # Prevent directory traversal in static file serving
        clean_path = os.path.normpath(path.lstrip('/')).replace('\\', '/')
        if clean_path.startswith('..') or clean_path.startswith('/'):
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Access denied.")
            return

        file_path = os.path.join(CURRENT_DIR, 'static', clean_path)
        
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
        client_ip = self.client_address[0] if self.client_address else "127.0.0.1"
        content_length = int(self.headers.get('Content-Length', 0))

        # Enforce payload size limit (15MB)
        if content_length > 15 * 1024 * 1024:
            self.send_response(413)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Payload exceeds maximum allowed size (15MB)."}).encode('utf-8'))
            return

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
                raw_filename = body.get("filename", "uploaded_dataset")
                safe_filename = sanitize_dataset_filename(raw_filename)
                
                if not file_content:
                    security_audit_log("UPLOAD_REJECTED", client_ip, details="Empty file content")
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "No file content provided."}).encode('utf-8'))
                    return
                    
                inspection = parse_and_inspect_dataset(file_content, safe_filename)
                is_valid = inspection.get("is_valid", False) or inspection.get("dataset_type") == "organization_profile"
                
                security_audit_log(
                    "UPLOAD_INSPECTED",
                    client_ip,
                    details=f"file='{safe_filename}', valid={is_valid}, type={inspection.get('dataset_type')}"
                )
                
                self.send_response(200 if is_valid else 422)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(inspection).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Unable to inspect dataset."}).encode('utf-8'))
            return

        # ----------------------------------------------------
        # 2. AUTO UPLOAD & SCHEMA DETECTION: IMPORT & ACTIVATE
        # ----------------------------------------------------
        elif self.path == '/api/upload/import':
            try:
                file_content = body.get("file_content", "")
                raw_filename = body.get("filename", "uploaded_dataset")
                safe_filename = sanitize_dataset_filename(raw_filename)
                
                if not file_content:
                    security_audit_log("IMPORT_REJECTED", client_ip, details="Empty file content")
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Missing file content to import."}).encode('utf-8'))
                    return
                    
                inspection = parse_and_inspect_dataset(file_content, safe_filename)
                valid_records = inspection.get("valid_records", [])
                
                if not valid_records:
                    security_audit_log("IMPORT_REJECTED", client_ip, details=f"0 valid records in '{safe_filename}'")
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
                _session_dataset["source_name"] = f"Uploaded Dataset ({safe_filename})"
                _session_dataset["vulnerabilities"] = valid_records
                _session_dataset["total_records"] = inspection.get("total_records", len(valid_records))
                _session_dataset["valid_records_count"] = len(valid_records)
                _session_dataset["quality_report"] = inspection.get("quality_report")
                _session_dataset["detected_columns"] = inspection.get("detected_columns", [])
                
                security_audit_log(
                    "DATASET_IMPORTED",
                    client_ip,
                    details=f"source='{_session_dataset['source_name']}', valid_count={len(valid_records)}"
                )
                
                # Re-run existing engine for all organizations and return full dashboard
                fresh_data = build_full_dashboard_data()
                fresh_data["import_summary"] = {
                    "filename": safe_filename,
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
                self.wfile.write(json.dumps({"error": "Failed to import dataset."}).encode('utf-8'))
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
                
                security_audit_log("DATASET_RESET", client_ip, details="Restored Bundled Baseline")
                
                fresh_data = build_full_dashboard_data()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(fresh_data).encode('utf-8'))
            except Exception as e:
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Failed to reset dataset."}).encode('utf-8'))
            return

        # ----------------------------------------------------
        # 4. WHAT-IF RISK SIMULATOR: RUN
        # ----------------------------------------------------
        elif self.path == '/api/simulation/run':
            try:
                org_id = body.get("org_id")
                remediated_pairs = body.get("remediated_pairs", [])
                
                if not org_id or not isinstance(org_id, str):
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Missing or invalid required field: org_id"}).encode('utf-8'))
                    return

                # Validate remediated_pairs structure (max 50)
                if not isinstance(remediated_pairs, list) or len(remediated_pairs) > 50:
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "remediated_pairs must be a list containing at most 50 items."}).encode('utf-8'))
                    return
                    
                organizations, _ = load_organizations()
                target_org = next((o for o in organizations if o.get("org_id") == org_id), None)
                if not target_org:
                    security_audit_log("SECURITY_VALIDATION_FAILURE", client_ip, org_id=org_id, details="Invalid org_id in simulation")
                    self.send_response(404)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": f"Organization {org_id} not found"}).encode('utf-8'))
                    return
                    
                active_vulns = get_active_vulnerabilities()
                dataset_source = _session_dataset.get("source_name", "Active Dataset")
                
                security_audit_log(
                    "SIMULATION_RUN",
                    client_ip,
                    org_id=org_id,
                    details=f"remediations={len(remediated_pairs)}, dataset='{dataset_source}'"
                )
                
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
                self.wfile.write(json.dumps({"error": "Simulation failed."}).encode('utf-8'))
            return

        # ----------------------------------------------------
        # 5. WHAT-IF RISK SIMULATOR: BEST FIRST FIX
        # ----------------------------------------------------
        elif self.path == '/api/simulation/best-fix':
            try:
                org_id = body.get("org_id")
                if not org_id or not isinstance(org_id, str):
                    self.send_response(400)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": "Missing or invalid required field: org_id"}).encode('utf-8'))
                    return
                    
                organizations, _ = load_organizations()
                target_org = next((o for o in organizations if o.get("org_id") == org_id), None)
                if not target_org:
                    security_audit_log("SECURITY_VALIDATION_FAILURE", client_ip, org_id=org_id, details="Invalid org_id in best-fix")
                    self.send_response(404)
                    self.send_header('Content-Type', 'application/json')
                    self.end_headers()
                    self.wfile.write(json.dumps({"error": f"Organization {org_id} not found"}).encode('utf-8'))
                    return
                    
                active_vulns = get_active_vulnerabilities()
                dataset_source = _session_dataset.get("source_name", "Active Dataset")
                
                security_audit_log("BEST_FIX_REQUESTED", client_ip, org_id=org_id, details=f"dataset='{dataset_source}'")
                
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
                self.wfile.write(json.dumps({"error": "Best first fix evaluation failed."}).encode('utf-8'))
            return

        # ----------------------------------------------------
        # 6. AI ADVISOR ENDPOINTS (Strictly Active Dataset)
        # ----------------------------------------------------
        elif self.path == '/api/ai/analyze-vulnerability':
            org_id = body.get("org_id")
            cve_id = body.get("cve_id")
            product_name = body.get("product_name")

            if not org_id or not cve_id or not isinstance(org_id, str) or not isinstance(cve_id, str):
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing or invalid required fields: org_id and cve_id"}).encode('utf-8'))
                return

            try:
                active_vulns = get_active_vulnerabilities()
                dataset_source = _session_dataset.get("source_name", "Active Dataset")
                
                security_audit_log(
                    "AI_ANALYSIS_REQUEST",
                    client_ip,
                    org_id=org_id,
                    details=f"cve='{cve_id}', prod='{product_name}', dataset='{dataset_source}'"
                )
                
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
                self.wfile.write(json.dumps({"error": "Failed to generate AI analysis."}).encode('utf-8'))
            return

        elif self.path == '/api/ai/executive-summary':
            org_id = body.get("org_id")
            if not org_id or not isinstance(org_id, str):
                self.send_response(400)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing or invalid required field: org_id"}).encode('utf-8'))
                return

            try:
                active_vulns = get_active_vulnerabilities()
                dataset_source = _session_dataset.get("source_name", "Active Dataset")
                
                security_audit_log("AI_EXEC_SUMMARY", client_ip, org_id=org_id, details=f"dataset='{dataset_source}'")
                
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
                self.wfile.write(json.dumps({"error": "Failed to generate executive summary."}).encode('utf-8'))
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
