import os
import json
import csv

# Define paths relative to this file's directory
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
ORG_FILE = os.path.join(DATA_DIR, "organizations.json")
VULN_FILE = os.path.join(DATA_DIR, "vulnerabilities.csv")
PRACTITIONER_FILE = os.path.join(DATA_DIR, "practitioner.csv")

def load_organizations():
    """Reads organizations.json and performs schema validation."""
    if not os.path.exists(ORG_FILE):
        raise FileNotFoundError(f"Organizations file not found at: {ORG_FILE}")
        
    with open(ORG_FILE, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    organizations = data.get("organizations", [])
    validation_errors = []
    
    for i, org in enumerate(organizations):
        org_prefix = f"Org #{i} ({org.get('name', 'Unknown')})"
        
        # Check required fields
        for field in ["org_id", "name", "sector", "risk_appetite", "weight_modifiers", "critical_products"]:
            if field not in org:
                validation_errors.append(f"{org_prefix} is missing required field: '{field}'")
                
        # Check weights
        weights = org.get("weight_modifiers", {})
        for weight_name in ["cvss_weight", "cisa_kev_weight", "first_epss_weight"]:
            if weight_name not in weights:
                validation_errors.append(f"{org_prefix} modifier weights are missing: '{weight_name}'")
            else:
                val = weights[weight_name]
                if not isinstance(val, (int, float)):
                    validation_errors.append(f"{org_prefix} weight '{weight_name}' must be a number, got: {type(val)}")
                    
        # Check critical products
        products = org.get("critical_products", [])
        if not isinstance(products, list):
            validation_errors.append(f"{org_prefix} critical_products must be a list, got: {type(products)}")
            
    return organizations, validation_errors

def load_vulnerabilities():
    """Reads vulnerabilities.csv and validates records, tracking missing values and duplicates."""
    if not os.path.exists(VULN_FILE):
        raise FileNotFoundError(f"Vulnerabilities file not found at: {VULN_FILE}")
        
    vulnerabilities = []
    validation_errors = []
    duplicates = []
    seen_keys = set()
    product_counts = {}
    csv_columns = []
    
    with open(VULN_FILE, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        try:
            csv_columns = next(reader)
        except StopIteration:
            return [], ["Vulnerabilities CSV is empty"], [], {}, []
            
        # Clean column names (strip whitespace)
        csv_columns = [col.strip() for col in csv_columns]
        
        # Verify required columns exist
        expected_cols = ["cve_id", "product_name", "cvss_base_score", "cisa_kev", "first_epss"]
        for col in expected_cols:
            if col not in csv_columns:
                validation_errors.append(f"Vulnerability CSV is missing expected column: '{col}'")
                
        # Indices of expected columns
        try:
            cve_idx = csv_columns.index("cve_id")
            prod_idx = csv_columns.index("product_name")
            cvss_idx = csv_columns.index("cvss_base_score")
            kev_idx = csv_columns.index("cisa_kev")
            epss_idx = csv_columns.index("first_epss")
        except ValueError as e:
            return [], validation_errors, [], {}, csv_columns
            
        for line_num, row in enumerate(reader, start=2): # header is line 1
            if not row:
                continue # Skip empty lines
                
            # Check column count
            if len(row) < len(csv_columns):
                validation_errors.append(f"Row {line_num} has fewer columns ({len(row)}) than header ({len(csv_columns)}): {row}")
                continue
            elif len(row) > len(csv_columns):
                # We can still parse but flag it
                validation_errors.append(f"Row {line_num} has more columns ({len(row)}) than header ({len(csv_columns)}): {row}")
                
            cve_id = row[cve_idx].strip()
            product_name = row[prod_idx].strip()
            cvss_str = row[cvss_idx].strip()
            kev_str = row[kev_idx].strip()
            epss_str = row[epss_idx].strip()
            
            # 1. Check for missing values in row elements
            missing_fields = []
            if not cve_id: missing_fields.append("cve_id")
            if not product_name: missing_fields.append("product_name")
            if not cvss_str: missing_fields.append("cvss_base_score")
            if not kev_str: missing_fields.append("cisa_kev")
            if not epss_str: missing_fields.append("first_epss")
            
            if missing_fields:
                validation_errors.append(f"Row {line_num}: Missing values in columns: {missing_fields}")
                
            # 2. Type validation
            cvss_val = None
            if cvss_str:
                try:
                    cvss_val = float(cvss_str)
                    if not (0.0 <= cvss_val <= 10.0):
                        validation_errors.append(f"Row {line_num} ({cve_id}): CVSS score {cvss_val} out of bounds [0, 10]")
                except ValueError:
                    validation_errors.append(f"Row {line_num} ({cve_id}): Invalid CVSS float value '{cvss_str}'")
                    
            kev_val = None
            if kev_str:
                lower_kev = kev_str.lower()
                if lower_kev in ("true", "1", "yes"):
                    kev_val = True
                elif lower_kev in ("false", "0", "no"):
                    kev_val = False
                else:
                    validation_errors.append(f"Row {line_num} ({cve_id}): Invalid KEV boolean value '{kev_str}'")
                    
            epss_val = None
            if epss_str:
                try:
                    epss_val = float(epss_str)
                    if not (0.0 <= epss_val <= 1.0):
                        validation_errors.append(f"Row {line_num} ({cve_id}): EPSS value {epss_val} out of bounds [0, 1]")
                except ValueError:
                    validation_errors.append(f"Row {line_num} ({cve_id}): Invalid EPSS float value '{epss_str}'")
                    
            # 3. Duplicate checks based on (cve_id, product_name)
            record_key = (cve_id, product_name)
            if record_key in seen_keys:
                duplicates.append({
                    "line_number": line_num,
                    "cve_id": cve_id,
                    "product_name": product_name,
                    "row": row
                })
            else:
                seen_keys.add(record_key)
                
            # 4. Product distribution mapping
            if product_name:
                product_counts[product_name] = product_counts.get(product_name, 0) + 1
                
            vulnerabilities.append({
                "line_number": line_num,
                "cve_id": cve_id,
                "product_name": product_name,
                "cvss_base_score": cvss_val,
                "cisa_kev": kev_val,
                "first_epss": epss_val
            })
            
    return vulnerabilities, validation_errors, duplicates, product_counts, csv_columns

def load_practitioner():
    """Loads practitioner.csv and validates validation/reference rows."""
    if not os.path.exists(PRACTITIONER_FILE):
        raise FileNotFoundError(f"Practitioner file not found at: {PRACTITIONER_FILE}")
        
    practitioners = []
    validation_errors = []
    
    with open(PRACTITIONER_FILE, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        try:
            columns = next(reader)
        except StopIteration:
            return [], ["Practitioner CSV is empty"]
            
        columns = [col.strip() for col in columns]
        
        # Required columns mapping
        expected = ["cve_id", "product_name", "cvss_base_score", "cisa_kev", "first_epss"]
        for col in expected:
            if col not in columns:
                validation_errors.append(f"Practitioner CSV is missing required base column: '{col}'")
                
        # Note: we may have fields for organization rankings (practitioner_rank_bank, practitioner_rank_startup)
        
        try:
            cve_idx = columns.index("cve_id")
            prod_idx = columns.index("product_name")
            cvss_idx = columns.index("cvss_base_score")
            kev_idx = columns.index("cisa_kev")
            epss_idx = columns.index("first_epss")
        except ValueError:
            return [], validation_errors
            
        # We can dynamically handle other columns like rank columns
        rank_cols = [col for col in columns if "rank" in col.lower()]
        rank_indices = {col: columns.index(col) for col in rank_cols}
        
        for line_num, row in enumerate(reader, start=2):
            if not row:
                continue
                
            if len(row) < len(columns):
                validation_errors.append(f"Practitioner Row {line_num} has fewer columns than header.")
                continue
                
            cve_id = row[cve_idx].strip()
            product = row[prod_idx].strip()
            
            # Numeric conversion
            try:
                cvss = float(row[cvss_idx].strip())
            except ValueError:
                cvss = None
                validation_errors.append(f"Practitioner Row {line_num} ({cve_id}): Invalid CVSS '{row[cvss_idx]}'")
                
            kev = row[kev_idx].strip().lower() in ("true", "1", "yes")
            
            try:
                epss = float(row[epss_idx].strip())
            except ValueError:
                epss = None
                validation_errors.append(f"Practitioner Row {line_num} ({cve_id}): Invalid EPSS '{row[epss_idx]}'")
                
            # Load ranks
            ranks = {}
            for col_name, idx in rank_indices.items():
                rank_str = row[idx].strip()
                if rank_str:
                    try:
                        ranks[col_name] = int(rank_str)
                    except ValueError:
                        validation_errors.append(f"Practitioner Row {line_num} ({cve_id}): Invalid rank '{rank_str}' in {col_name}")
                        
            practitioners.append({
                "cve_id": cve_id,
                "product_name": product,
                "cvss_base_score": cvss,
                "cisa_kev": kev,
                "first_epss": epss,
                "ranks": ranks
            })
            
    return practitioners, validation_errors
