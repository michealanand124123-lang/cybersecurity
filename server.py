import os
import sys
import json
import mimetypes
from http.server import HTTPServer, BaseHTTPRequestHandler

# Add current directory and src directory to Python path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.append(CURRENT_DIR)

from src.data_loader import load_organizations, load_vulnerabilities, load_practitioner
from src.matcher import match_products_for_organization
from src.ranking import rank_vulnerabilities, get_top_n_vulnerabilities
from src.validation import compare_with_practitioner

class VulnTriageHandler(BaseHTTPRequestHandler):
    def end_headers(self):
        # Allow cross-origin requests for debugging/port flexibility
        self.send_header('Access-Control-Allow-Origin', '*')
        super().end_headers()

    def do_GET(self):
        if self.path == '/api/data':
            try:
                # Load configurations and data using standard backend modules
                organizations, org_errors = load_organizations()
                vulnerabilities, vuln_errors, vuln_duplicates, product_counts, vuln_columns = load_vulnerabilities()
                practitioners, prac_errors = load_practitioner()
                
                # Perform validation comparisons
                comp_report = compare_with_practitioner(organizations, practitioners)
                
                org_data = {}
                for org in organizations:
                    org_id = org["org_id"]
                    
                    # 1. Match products
                    m_rep = match_products_for_organization(org, vulnerabilities)
                    
                    # 2. Rank vulnerabilities
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

                # Wrap all report data
                response_data = {
                    "organizations": organizations,
                    "errors": {
                        "org_errors": org_errors,
                        "vuln_errors": vuln_errors,
                        "prac_errors": prac_errors,
                        "duplicates": [d["cve_id"] for d in vuln_duplicates]
                    },
                    "org_data": org_data,
                    "validation_report": comp_report,
                    "product_distribution": product_counts
                }
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(response_data).encode('utf-8'))
                
            except Exception as e:
                import traceback
                self.send_response(500)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                error_response = {
                    "error": str(e),
                    "traceback": traceback.format_exc()
                }
                self.wfile.write(json.dumps(error_response).encode('utf-8'))
        else:
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
