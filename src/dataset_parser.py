import csv
import io
import json
import re

# Column variations mapping dictionary
COLUMN_ALIASES = {
    "cve_id": [
        "cve_id", "cve", "cve id", "cve_identifier", "cve_name", "vulnerability_id", "vuln_id", "cve-id", "cve_number"
    ],
    "product_name": [
        "product_name", "product", "affected_product", "technology", "asset", "product name",
        "affected_technology", "software", "software_name", "app_name", "component"
    ],
    "cvss_base_score": [
        "cvss_base_score", "cvss", "cvss_score", "cvss_base", "cvss_v3", "cvss_v3_score",
        "base_score", "cvss score", "cvss base score"
    ],
    "cisa_kev": [
        "cisa_kev", "kev", "known_exploited", "kev_status", "in_kev", "cisa_known_exploited",
        "cisa kev", "is_kev", "exploited_in_wild"
    ],
    "first_epss": [
        "first_epss", "epss", "epss_score", "epss_probability", "epss_score_prob",
        "epss probability", "first epss", "epss_percentile"
    ],
    "vendor": [
        "vendor", "vendor_name", "manufacturer", "publisher"
    ],
    "published_date": [
        "published_date", "published", "date_published", "publish_date", "release_date"
    ],
    "reference_url": [
        "reference_url", "url", "reference", "source_url", "link", "references"
    ]
}

ORG_FIELD_SIGNATURES = [
    "org_id", "sector", "risk_appetite", "weight_modifiers", "critical_products"
]

def normalize_header_name(header):
    """Cleans and standardizes column header names for fuzzy alias matching."""
    if not header:
        return ""
    h = str(header).strip().lower()
    h = re.sub(r"[\s\-_]+", "_", h)
    return h

def detect_column_mappings(columns):
    """
    Scans list of columns from dataset and automatically maps to standard internal keys.
    Returns:
        dict: { standard_key: detected_column_name }
    """
    normalized_cols = {normalize_header_name(c): c for c in columns if c is not None}
    mappings = {}
    
    for standard_key, aliases in COLUMN_ALIASES.items():
        found = False
        for alias in aliases:
            norm_alias = normalize_header_name(alias)
            if norm_alias in normalized_cols:
                mappings[standard_key] = normalized_cols[norm_alias]
                found = True
                break
        if not found:
            # Fallback: substring matching
            for norm_c, orig_c in normalized_cols.items():
                if any(normalize_header_name(a) == norm_c for a in aliases):
                    mappings[standard_key] = orig_c
                    found = True
                    break
    return mappings

def classify_dataset(columns, sample_rows=None, raw_json=None):
    """
    Classifies dataset type into:
    - 'vulnerability_dataset'
    - 'organization_profile'
    - 'unknown_dataset'
    """
    # 1. Check if it's an organization profile structure
    if raw_json and isinstance(raw_json, dict):
        if "organizations" in raw_json and isinstance(raw_json["organizations"], list):
            sample_org = raw_json["organizations"][0] if raw_json["organizations"] else {}
            if any(k in sample_org for k in ORG_FIELD_SIGNATURES):
                return "organization_profile"
        if any(k in raw_json for k in ORG_FIELD_SIGNATURES):
            return "organization_profile"
            
    norm_cols = [normalize_header_name(c) for c in columns if c is not None]
    
    org_matches = sum(1 for f in ORG_FIELD_SIGNATURES if any(f in c for c in norm_cols))
    if org_matches >= 3:
        return "organization_profile"
        
    # 2. Check if it's a vulnerability dataset
    mappings = detect_column_mappings(columns)
    # A valid vulnerability dataset must at minimum map CVE and Product
    if "cve_id" in mappings and "product_name" in mappings:
        return "vulnerability_dataset"
        
    # Additional check: CVE ID found with at least one scoring metric
    if "cve_id" in mappings and any(k in mappings for k in ["cvss_base_score", "cisa_kev", "first_epss"]):
        return "vulnerability_dataset"
        
    return "unknown_dataset"

def parse_boolean_value(val):
    """
    Strict boolean parser.
    Returns (bool_val, is_valid).
    """
    if val is None:
        return None, False
    if isinstance(val, bool):
        return val, True
    if isinstance(val, (int, float)):
        if val == 1:
            return True, True
        elif val == 0:
            return False, True
        return None, False
        
    s = str(val).strip().lower()
    if s in ("true", "1", "yes", "y", "t", "known", "active", "exploited"):
        return True, True
    elif s in ("false", "0", "no", "n", "f", "unknown", "unlisted", "none", ""):
        return False, True
    return None, False

def parse_float_value(val, min_val=None, max_val=None):
    """
    Strict float parser with boundary enforcement.
    Returns (float_val, is_valid).
    """
    if val is None or str(val).strip() == "":
        return None, False
    try:
        f = float(str(val).strip())
        if min_val is not None and f < min_val:
            return None, False
        if max_val is not None and f > max_val:
            return None, False
        return f, True
    except (ValueError, TypeError):
        return None, False

def parse_and_inspect_dataset(file_content_str, filename="uploaded_file"):
    """
    Inspects, validates, and normalizes an uploaded CSV or JSON string.
    
    Returns:
        dict: Inspection report containing:
            - is_valid (bool)
            - error (str or None)
            - dataset_type (str)
            - detected_columns (list)
            - column_mappings (dict)
            - total_records (int)
            - valid_records (list of normalized dicts)
            - invalid_records (list with failure reasons)
            - duplicates_count (int)
            - quality_report (dict)
            - preview_rows (list of first 5-10 rows)
    """
    if not file_content_str or not file_content_str.strip():
        return {
            "is_valid": False,
            "error": "Uploaded file is completely empty.",
            "dataset_type": "unknown_dataset"
        }
        
    content = file_content_str.strip()
    raw_rows = []
    columns = []
    raw_json = None
    
    # 1. Determine JSON vs CSV format
    is_json = False
    if content.startswith("{") or content.startswith("["):
        try:
            raw_json = json.loads(content)
            is_json = True
        except Exception:
            is_json = False
            
    if is_json:
        if isinstance(raw_json, list):
            raw_rows = raw_json
        elif isinstance(raw_json, dict):
            if "vulnerabilities" in raw_json and isinstance(raw_json["vulnerabilities"], list):
                raw_rows = raw_json["vulnerabilities"]
            elif "records" in raw_json and isinstance(raw_json["records"], list):
                raw_rows = raw_json["records"]
            elif "data" in raw_json and isinstance(raw_json["data"], list):
                raw_rows = raw_json["data"]
            else:
                raw_rows = [raw_json]
                
        if raw_rows and isinstance(raw_rows[0], dict):
            columns = list(raw_rows[0].keys())
        else:
            return {
                "is_valid": False,
                "error": "JSON file did not contain a valid array of vulnerability objects.",
                "dataset_type": "unknown_dataset"
            }
    else:
        # Parse CSV
        try:
            # Detect dialect/delimiter
            sample = content[:4096]
            delimiter = ","
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",\t;|")
                delimiter = dialect.delimiter
            except Exception:
                delimiter = ","
                
            csv_reader = csv.reader(io.StringIO(content), delimiter=delimiter)
            try:
                header = next(csv_reader)
            except StopIteration:
                return {
                    "is_valid": False,
                    "error": "CSV file is empty or missing a header row.",
                    "dataset_type": "unknown_dataset"
                }
                
            columns = [c.strip() for c in header if c is not None]
            
            for line_idx, row in enumerate(csv_reader, start=2):
                if not row or not any(field.strip() for field in row):
                    continue
                # Create dict from row
                row_dict = {}
                for idx, col_name in enumerate(columns):
                    val = row[idx].strip() if idx < len(row) else ""
                    row_dict[col_name] = val
                row_dict["_line_number"] = line_idx
                raw_rows.append(row_dict)
                
        except Exception as e:
            return {
                "is_valid": False,
                "error": f"Failed to parse CSV file: {str(e)}",
                "dataset_type": "unknown_dataset"
            }
            
    # 2. Classify Dataset
    dataset_type = classify_dataset(columns, raw_rows, raw_json)
    if dataset_type == "unknown_dataset":
        return {
            "is_valid": False,
            "error": "Unknown dataset structure. Could not identify vulnerability or organization attributes.",
            "dataset_type": "unknown_dataset",
            "detected_columns": columns
        }
        
    if dataset_type == "organization_profile":
        return {
            "is_valid": True,
            "dataset_type": "organization_profile",
            "detected_columns": columns,
            "total_records": len(raw_rows),
            "message": "Organization profile dataset detected."
        }
        
    # 3. Detect Column Mappings
    mappings = detect_column_mappings(columns)
    
    # Required core keys for deterministic ranking
    cve_col = mappings.get("cve_id")
    prod_col = mappings.get("product_name")
    cvss_col = mappings.get("cvss_base_score")
    kev_col = mappings.get("cisa_kev")
    epss_col = mappings.get("first_epss")
    vendor_col = mappings.get("vendor")
    published_col = mappings.get("published_date")
    ref_col = mappings.get("reference_url")
    
    if not cve_col or not prod_col:
        return {
            "is_valid": False,
            "error": f"Dataset is missing mandatory identifiers. Detected columns: {columns}",
            "dataset_type": "vulnerability_dataset",
            "detected_columns": columns,
            "column_mappings": mappings
        }
        
    # 4. Process and strictly validate every row
    valid_records = []
    invalid_records = []
    seen_keys = set()
    duplicates_count = 0
    
    missing_epss_count = 0
    missing_cvss_count = 0
    missing_kev_count = 0
    missing_product_count = 0
    invalid_ranges_count = 0
    
    for row_idx, row in enumerate(raw_rows, start=1):
        line_num = row.get("_line_number", row_idx)
        
        # Extract values using mapped columns
        raw_cve = str(row.get(cve_col, "")).strip() if cve_col else ""
        raw_prod = str(row.get(prod_col, "")).strip() if prod_col else ""
        raw_cvss = row.get(cvss_col) if cvss_col else None
        raw_kev = row.get(kev_col) if kev_col else None
        raw_epss = row.get(epss_col) if epss_col else None
        
        # Optional metadata
        raw_vendor = str(row.get(vendor_col, "")).strip() if vendor_col else None
        raw_published = str(row.get(published_col, "")).strip() if published_col else None
        raw_ref = str(row.get(ref_col, "")).strip() if ref_col else None
        
        reasons = []
        
        # Validate CVE
        if not raw_cve:
            reasons.append("Missing CVE ID")
            
        # Validate Product
        if not raw_prod:
            reasons.append("Missing Product Name")
            missing_product_count += 1
            
        # Validate CVSS (0.0 to 10.0)
        cvss_val, cvss_valid = parse_float_value(raw_cvss, min_val=0.0, max_val=10.0)
        if not cvss_valid:
            if raw_cvss is None or str(raw_cvss).strip() == "":
                reasons.append("Missing CVSS base score")
                missing_cvss_count += 1
            else:
                reasons.append(f"Invalid CVSS score '{raw_cvss}' (must be float in [0.0, 10.0])")
                invalid_ranges_count += 1
                
        # Validate KEV (boolean)
        kev_val, kev_valid = parse_boolean_value(raw_kev)
        if not kev_valid:
            if raw_kev is None or str(raw_kev).strip() == "":
                reasons.append("Missing CISA KEV status")
                missing_kev_count += 1
            else:
                reasons.append(f"Invalid CISA KEV value '{raw_kev}' (must be boolean true/false)")
                invalid_ranges_count += 1
                
        # Validate EPSS (0.0 to 1.0)
        epss_val, epss_valid = parse_float_value(raw_epss, min_val=0.0, max_val=1.0)
        if not epss_valid:
            if raw_epss is None or str(raw_epss).strip() == "":
                reasons.append("Missing FIRST EPSS probability")
                missing_epss_count += 1
            else:
                reasons.append(f"Invalid EPSS value '{raw_epss}' (must be float in [0.0, 1.0])")
                invalid_ranges_count += 1
                
        if reasons:
            # Mark invalid/unrankable; do NOT coerce to 0.0
            invalid_records.append({
                "line_number": line_num,
                "cve_id": raw_cve or "UNKNOWN",
                "product_name": raw_prod or "UNKNOWN",
                "reasons": reasons,
                "raw_values": {k: v for k, v in row.items() if not k.startswith("_")}
            })
            continue
            
        # Check duplicates based on (cve_id, product_name)
        comp_key = (raw_cve.upper(), raw_prod.lower())
        if comp_key in seen_keys:
            duplicates_count += 1
            # Note: per requirements, keep track of duplicates
        else:
            seen_keys.add(comp_key)
            
        # Normalize into internal VULNTRIAGE record
        normalized_record = {
            "cve_id": raw_cve,
            "product_name": raw_prod,
            "cvss_base_score": cvss_val,
            "cisa_kev": kev_val,
            "first_epss": epss_val
        }
        if raw_vendor:
            normalized_record["vendor"] = raw_vendor
        if raw_published:
            normalized_record["published_date"] = raw_published
        if raw_ref:
            normalized_record["reference_url"] = raw_ref
            
        valid_records.append(normalized_record)
        
    # 5. Build Preview Rows (first 10 valid or raw rows)
    preview_rows = []
    preview_limit = min(10, len(raw_rows))
    for i in range(preview_limit):
        r = raw_rows[i]
        mapped_preview = {
            "line_number": r.get("_line_number", i + 1),
            "cve_id": r.get(cve_col, ""),
            "product_name": r.get(prod_col, ""),
            "cvss_base_score": r.get(cvss_col, ""),
            "cisa_kev": r.get(kev_col, ""),
            "first_epss": r.get(epss_col, "")
        }
        preview_rows.append(mapped_preview)
        
    quality_report = {
        "total_records": len(raw_rows),
        "valid_count": len(valid_records),
        "invalid_count": len(invalid_records),
        "duplicates_count": duplicates_count,
        "missing_epss_count": missing_epss_count,
        "missing_cvss_count": missing_cvss_count,
        "missing_kev_count": missing_kev_count,
        "missing_product_count": missing_product_count,
        "invalid_ranges_count": invalid_ranges_count,
        "duplicate_identity_rule": "Composite (cve_id + product_name)"
    }
    
    return {
        "is_valid": len(valid_records) > 0,
        "filename": filename,
        "dataset_type": "vulnerability_dataset",
        "detected_columns": columns,
        "column_mappings": mappings,
        "total_records": len(raw_rows),
        "valid_records": valid_records,
        "invalid_records": invalid_records[:50], # Send first 50 invalid samples for UI display
        "quality_report": quality_report,
        "preview_rows": preview_rows
    }
