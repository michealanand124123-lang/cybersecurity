# VULNTRIAGE

> **CYBER DEFENSE INTELLIGENCE** — Personalized, Explainable Vulnerability Triage, What-If Risk Simulation & AI-Powered Threat Advisory

Modern security teams are overwhelmed by the constant influx of publicly disclosed CVEs, yet only a fraction of those vulnerabilities directly impact their specific technology stack or asset inventory. **VULNTRIAGE** is an enterprise-grade contextual vulnerability triage and cyber defense intelligence platform designed to help organizations filter out noise and prioritize the vulnerabilities that present the highest actual risk to their specific operational environment. 

By combining organizational asset context, CVSS base severity, CISA Known Exploited Vulnerabilities (KEV) status, and FIRST Exploit Prediction Scoring System (EPSS) probabilities, VULNTRIAGE produces a transparent, deterministic Top 5 vulnerability ranking tailored to an organization's unique risk profile, enriched by an interactive **What-If Risk Simulator**, a **Dynamic Dataset Ingestion Engine**, and an **AI Threat Advisor**.

---

## Problem Statement

- **Vulnerability Overload & Alert Fatigue:** Thousands of new vulnerabilities are published annually. Security practitioners and operations teams cannot remediate every CVE simultaneously and often lack the bandwidth to manually investigate every alert.
- **Insufficiency of CVSS in Isolation:** Generic CVSS base scores reflect theoretical technical severity in a vacuum. A CVSS 9.8 vulnerability in software an organization does not run poses zero immediate threat, whereas a CVSS 7.5 flaw that is actively exploited in the wild (CISA KEV) on a core production system demands immediate remediation.
- **The Criticality of Organizational Context:** Different organizations have distinct technology stacks, business-critical assets, and operational risk appetites. A cloud-native tech startup prioritizes threats differently than a municipal water utility or a global commercial bank.
- **Remediation Uncertainty & Impact Planning:** Security leaders struggle to answer: *"If we patch these two CVEs this sprint, how much does our organizational risk actually drop, and what emerges as our next critical threat?"*
- **The Value of an Actionable Top 5:** Rather than handing security engineers an unprioritized backlog of hundreds of findings, delivering a concise, explainable Top 5 list enables focused, high-impact remediation with clear rationale for every decision.

---

## Architecture & Processing Pipeline

VULNTRIAGE implements a deterministic, multi-stage processing pipeline that transforms raw vulnerability data into personalized threat intelligence and actionable insights:

```text
┌────────────────────────────────────────────────────────┐
│             Organisation Profile (JSON)                │
│    Sector • Risk Appetite • Critical Assets • Weights  │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│               Product Matching Engine                  │
│    Normalizes & matches CVEs against critical assets   │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│         Vulnerability Filtering & Quality Gate         │
│   Sanitizes, deduplicates, & extracts monitored assets │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│                  Risk Scoring Engine                   │
│   Normalized CVSS + Binary CISA KEV + FIRST EPSS       │
│        Weighted by Organization Risk Modifiers         │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│             Top 5 Deterministic Ranking                │
│    Deterministic sorting (Risk Score, CVSS, CVE ID)    │
└────────────┬─────────────┬─────────────┬───────────────┘
             │             │             │
             ▼             ▼             ▼
┌──────────────────┐┌─────────────┐┌─────────────────────┐
│ Explainable Math ││ What-If Risk││ AI Threat Advisor   │
│ Contribution &   ││ Simulator   ││ Grounded Remediation│
│ Score Breakdown  ││ & Best Fix  ││ & Exec Summaries    │
└────────────┬─────┘└──────┬──────┘└─────────────┬───────┘
             │             │                     │
             └─────────────┼─────────────────────┘
                           ▼
┌────────────────────────────────────────────────────────┐
│            CyberTech Dashboard & REST API              │
│    Interactive workspace, analytics, & auth gateway    │
└────────────────────────────────────────────────────────┘
```

---

## Key Features

- **Organisation-Specific Prioritization:** Evaluates vulnerabilities strictly against the critical technology assets and risk appetite defined for each organization.
- **Multi-Factor Risk Scoring Formula:** Combines technical severity (CVSS), threat feed confirmation (CISA KEV), and statistical exploit likelihood (FIRST EPSS) with zero arbitrary scoring shifts.
- **Explainable Score Attribution:** Calculates and displays exact point and percentage contributions for CVSS, KEV, and EPSS for every prioritized finding.
- **Interactive What-If Risk Simulator:** 
  - Allows security teams to simulate patching individual CVE/asset pairs.
  - Recalculates risk reductions, rank shifts, and displays the *new* projected Top 5 in real time without mutating baseline datasets.
  - **Best First Fix Engine:** Automatically analyzes all candidate vulnerabilities and recommends the single highest-impact patch.
- **AI Threat Advisor (Featherless AI / LLM Integration):**
  - Synthesizes authoritative scoring math into deep-dive remediation advisories, attack path scenarios, and executive board summaries.
  - **Strict Grounding:** AI advice is grounded strictly in deterministic backend scores; the model cannot hallucinate or override official scores.
  - **Graceful Fallback:** Built-in offline rule-based intelligence engine provides complete advisory coverage if LLM service is unreachable.
- **Dynamic Dataset Ingestion & Dirty Data Sanitizer:**
  - Ingests custom CSV and JSON vulnerability feeds via drag-and-drop.
  - Auto-detects columns with fuzzy alias matching (e.g., `cve`, `cvss3`, `in_kev`, `epss_score`).
  - Enforces strict quality validation, bounds checks ($0 \le \text{CVSS} \le 10$, $0 \le \text{EPSS} \le 1$), composite key deduplication, and zero unverified defaults.
  - In-memory active session switching with instantaneous single-click reset to bundled baseline.
- **Enterprise Security Hardening:**
  - Content Security Policy (CSP), anti-clickjacking headers (`X-Frame-Options: SAMEORIGIN`), and `X-Content-Type-Options: nosniff`.
  - Directory traversal prevention with path normalization and filename sanitization.
  - Strict secret isolation—API keys and tokens are loaded strictly server-side from `.env` and are never exposed to client APIs or audit logs.
  - Structured UTC security audit logging for all authentication, upload, simulation, and advisory events.
- **Practitioner Reference Validation:** Built-in validation module comparing calculated algorithmic rankings against reference human practitioner rankings without altering scoring formulas.
- **CyberTech Enterprise Dashboard:** Responsive web interface featuring real-time organization switching, threat metrics, collapsible vulnerability cards, filterable findings table, and full contextual analysis modals.
- **Comprehensive Automated Test Suite:** 37 automated tests across 6 suites verifying scoring integrity, security boundaries, simulation accuracy, and AI fallback isolation.

---

## Risk Scoring Formula

The risk score for any matched vulnerability is calculated using the following deterministic formula:

$$\text{Risk Score} = (\text{CVSS}_{\text{normalized}} \times \text{cvss\_weight}) + (\text{KEV}_{\text{value}} \times \text{cisa\_kev\_weight}) + (\text{first\_epss} \times \text{first\_epss\_weight})$$

### Component Definitions

1. **Normalized CVSS ($\text{CVSS}_{\text{normalized}}$):**
   $$\text{CVSS}_{\text{normalized}} = \frac{\text{cvss\_base\_score}}{10.0}$$
   Scales the CVSS v3 base severity score (range $0.0 - 10.0$) into a $[0.0, 1.0]$ float representation.

2. **Binary CISA KEV ($\text{KEV}_{\text{value}}$):**
   $$\text{KEV}_{\text{value}} = \begin{cases} 1.0 & \text{if } \text{cisa\_kev} = \text{True} \\ 0.0 & \text{if } \text{cisa\_kev} = \text{False} \end{cases}$$
   Represents whether the vulnerability is listed on the CISA Known Exploited Vulnerabilities catalog as actively exploited in the wild.

3. **Exploit Prediction Probability ($\text{first\_epss}$):**
   The FIRST EPSS probability score (range $0.0 - 1.0$) indicating the statistical probability that the vulnerability will be exploited in the wild within 30 days.

4. **Component Contributions:**
   - $\text{CVSS Contribution} = \text{CVSS}_{\text{normalized}} \times \text{cvss\_weight}$
   - $\text{KEV Contribution} = \text{KEV}_{\text{value}} \times \text{cisa\_kev\_weight}$
   - $\text{EPSS Contribution} = \text{first\_epss} \times \text{first\_epss\_weight}$

---

## Organisation Profiles

The system includes three pre-configured organizational profiles in `data/organizations.json`:

| Org ID | Organisation Name | Sector | Risk Appetite | Critical Products Monitored | Risk Weight Modifiers |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ORG-001** | **Global Retail Bank** | Financial Services | Low | • Core Banking Framework<br>• Identity Provider SaaS | • CVSS: `0.30`<br>• KEV: `0.45`<br>• EPSS: `0.25` |
| **ORG-002** | **Agile Cloud Tech Startup** | Technology | High | • Cloud Database Engine<br>• Web Application Firewall | • CVSS: `0.20`<br>• KEV: `0.20`<br>• EPSS: `0.60` |
| **ORG-003** | **Municipal Utility Provider** | Critical Infrastructure | Zero-Tolerance | • Embedded IoT Gateway<br>• Enterprise Router OS | • CVSS: `0.50`<br>• KEV: `0.40`<br>• EPSS: `0.10` |

---

## Data Sources

The project utilizes local structured datasets located in the `data/` directory:

1. **`data/vulnerabilities.csv` (Primary Vulnerability Corpus):**
   Contains 541 vulnerability entries with the following fields:
   - `cve_id` *(string)*: Unique CVE identifier (e.g., `CVE-2025-5380`).
   - `product_name` *(string)*: Technology product affected by the vulnerability.
   - `cvss_base_score` *(float)*: Base severity score ranging from `0.0` to `10.0`.
   - `cisa_kev` *(boolean)*: CISA Known Exploited Vulnerability status (`True` / `False`).
   - `first_epss` *(float)*: FIRST EPSS exploitation likelihood probability (`0.0` to `1.0`).

2. **`data/organizations.json` / `data/profiles.json`:**
   Defines the organizational schemas, operational sectors, risk appetites, critical product inventories, and customized weight modifier sets.

3. **`data/practitioner.csv` / `data/gold_set.csv`:**
   Reference benchmark dataset containing expert practitioner ranking baselines (`practitioner_rank_bank`, `practitioner_rank_startup`) used exclusively for algorithmic validation.

---

## Technology Stack

- **Backend:**
  - **Python 3.8+** (Standard Library only: `http.server`, `urllib.request`, `json`, `csv`, `re`, `os`, `sys`, `mimetypes`, `unittest`)
  - Zero external Python package requirements for base functionality.
- **AI & Threat Intelligence Integration:**
  - **Featherless AI** REST API (`Qwen/Qwen2.5-7B-Instruct` or user-configured model) with zero-leakage proxying and offline fallback intelligence.
- **Frontend:**
  - **HTML5 & Vanilla CSS3** (Custom CyberTech Design System, CSS Grid & Flexbox, Glassmorphism, CSS Custom Properties)
  - **JavaScript (ES6+)**
  - **Vue.js 3** (via Global CDN build)
- **Typography:**
  - Google Fonts: `Outfit`, `Share Tech Mono`, `Inter`

---

## Project Structure

```text
cybersecurity/
├── data/
│   ├── dirty_student_data.csv        # Supplementary / messy test data
│   ├── gold_set.csv                  # Reference benchmark dataset
│   ├── organizations.json            # Organization configuration schemas
│   ├── practitioner.csv              # Practitioner ranking reference
│   ├── profiles.json                 # Organization profiles mirror
│   └── vulnerabilities.csv           # Baseline vulnerability records corpus (541 rows)
├── src/
│   ├── ai_advisor.py                 # Featherless AI integration & grounded advisory engine
│   ├── data_loader.py                # Dataset ingestion & schema validation
│   ├── dataset_parser.py             # Flexible dataset upload, sanitization & quality gate
│   ├── main.py                       # CLI execution entry point
│   ├── matcher.py                    # Product string normalisation & matching
│   ├── ranking.py                    # Ranking & Top-N selection logic
│   ├── scorer.py                     # Risk scoring formula & contribution math
│   ├── simulator.py                  # What-If risk remediation simulation & Best First Fix
│   └── validation.py                 # Practitioner benchmark validation
├── static/
│   ├── index.css                     # CyberTech theme, modal & responsive layout styles
│   ├── index.html                    # Single-page application, simulator & upload markup
│   └── index.js                      # Vue 3 reactive state, simulation & AI controllers
├── tests/
│   ├── __init__.py
│   ├── test_ai_integration.py        # AI advisor grounding, secret isolation & schema tests
│   ├── test_deterministic_integrity.py # Top-5 rankings, tie-breaker & formula assertions
│   ├── test_risk_simulator.py        # Remediation what-if math & rank-shift tests
│   ├── test_security_hardening.py    # Path traversal, CSP, secret leakage & injection tests
│   ├── test_upload_and_schema.py     # Dirty dataset parsing, alias detection & quality checks
│   └── test_uploaded_dataset_integration.py # End-to-end custom dataset lifecycle tests
├── .env.example                      # Environment configuration template for AI keys
├── .gitignore                        # Git exclusion rules (protects .env and caches)
├── server.py                         # Hardened HTTP server & REST API handler
└── README.md                         # Project documentation
```

---

## REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/data` | Retrieves organizations, baseline/active findings, Top-5 rankings, and quality metrics. |
| `GET` | `/api/ai/status` | Returns AI Advisor service availability status (never leaks secrets). |
| `POST` | `/api/upload/inspect` | Inspects and validates uploaded CSV/JSON datasets, detecting columns and data quality. |
| `POST` | `/api/upload/import` | Activates inspected dataset for the current session and recomputes all organization rankings. |
| `POST` | `/api/dataset/reset` | Resets active dataset back to bundled baseline (`data/vulnerabilities.csv`). |
| `POST` | `/api/simulation/run` | Runs What-If remediation simulation for selected CVE/asset pairs on an organization. |
| `POST` | `/api/simulation/best-fix` | Evaluates all candidate vulnerabilities to identify and rank the optimal first remediation. |
| `POST` | `/api/ai/analyze-vulnerability` | Generates grounded AI remediation advice and attack scenarios for a specific CVE. |
| `POST` | `/api/ai/executive-summary` | Generates a strategic executive board threat summary for an organization. |

---

## Getting Started

### Prerequisites
- Python 3.8 or higher installed on your system.
- Any modern web browser (Chrome, Edge, Firefox, Safari).

### Environment Configuration (Optional - for AI Advisor)

To enable live LLM threat advisories using Featherless AI:
1. Copy the `.env.example` file to `.env`:
   ```bash
   cp .env.example .env
   ```
2. Open `.env` and configure your API key:
   ```env
   FEATHERLESS_API_KEY=your_featherless_api_key_here
   FEATHERLESS_MODEL=Qwen/Qwen2.5-7B-Instruct
   ```
> *Note:* If no API key is provided, the platform automatically operates using its built-in offline rule-based intelligence engine without interruption.

### Running the Interactive Web Application

1. Start the HTTP server:
   ```bash
   python server.py
   ```
2. Open your web browser and navigate to:
   ```text
   http://localhost:5000/
   ```
3. Use the login screen to sign in (an **AUTO-FILL** button is available for `analyst@vulntriage.sec`), or explore the full interactive dashboard.

### Running the Automated Test Suite

To run all 37 comprehensive unit, integration, and security tests:

```bash
python -m unittest discover -s tests -v
```

### Running the CLI Analysis Suite

To execute the core end-to-end data validation, product matching, risk scoring, Top 5 ranking, and practitioner comparison directly in the terminal:

```bash
python src/main.py
```
