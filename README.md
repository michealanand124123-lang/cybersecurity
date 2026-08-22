# VULNTRIAGE

> **CYBER DEFENSE INTELLIGENCE** — Personalized, Explainable Vulnerability Triage

Modern security teams are overwhelmed by the constant influx of publicly disclosed CVEs, yet only a fraction of those vulnerabilities directly impact their specific technology stack or asset inventory. **VULNTRIAGE** is a contextual vulnerability triage platform designed to help organizations filter out noise and prioritize the vulnerabilities that present the highest actual risk to their specific operational environment. By combining organizational asset context, CVSS base severity, CISA Known Exploited Vulnerabilities (KEV) status, and FIRST Exploit Prediction Scoring System (EPSS) probabilities, VULNTRIAGE produces a transparent, deterministic Top 5 vulnerability ranking tailored to an organization's unique risk profile.

---

## Problem Statement

- **Vulnerability Overload & Alert Fatigue:** Thousands of new vulnerabilities are published annually. Security practitioners and operations teams cannot remediate every CVE simultaneously and often lack the bandwidth to manually investigate every alert.
- **Insufficiency of CVSS in Isolation:** Generic CVSS base scores reflect theoretical technical severity in a vacuum. A CVSS 9.8 vulnerability in software an organization does not run poses zero immediate threat, whereas a CVSS 7.5 flaw that is actively exploited in the wild (CISA KEV) on a core production system demands immediate remediation.
- **The Criticality of Organizational Context:** Different organizations have distinct technology stacks, business-critical assets, and operational risk appetites. A cloud-native tech startup prioritizes threats differently than a municipal water utility or a global commercial bank.
- **The Value of an Actionable Top 5:** Rather than handing security engineers an unprioritized backlog of hundreds of findings, delivering a concise, explainable Top 5 list enables focused, high-impact remediation with clear rationale for every decision.

---

## Our Solution

VULNTRIAGE implements a deterministic, multi-stage processing pipeline that transforms raw vulnerability data into personalized threat intelligence:

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
│                Vulnerability Filtering                 │
│      Extracts CVEs affecting monitored infrastructure   │
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
│                    Top 5 Ranking                       │
│    Deterministic sorting (Risk Score, CVSS, CVE ID)    │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│                 Explainable Results                    │
│   Exact contribution breakdown per scoring component   │
└──────────────────────────┬─────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│            CyberTech Dashboard & REST API              │
│    Interactive workspace, analytics, & auth gateway    │
└────────────────────────────────────────────────────────┘
```

---

## Key Features

- **Organisation-Specific Prioritization:** Evaluates vulnerabilities strictly against the critical technology assets and risk appetite defined for each organization.
- **Product Normalization & Matching:** Robust string normalisation (whitespace cleanup and case folding) to accurately pair CVE product identifiers with monitored infrastructure.
- **Multi-Factor Risk Scoring:** Combines technical severity (CVSS), threat feed confirmation (CISA KEV), and statistical exploit likelihood (FIRST EPSS).
- **Dynamic Weight Modifiers:** Allows tailoring of component weights to reflect distinct organizational postures (Low, High, Zero-Tolerance).
- **Deterministic Top 5 Ranking:** Computes top priorities with rigorous tie-breaking rules (Risk Score descending, CVSS base score descending, and CVE ID ascending).
- **Explainable Score Attribution:** Calculates and presents exact point and percentage contributions for CVSS, KEV, and EPSS for every prioritized finding.
- **Practitioner Reference Validation:** Built-in validation module comparing calculated algorithmic rankings against reference human practitioner rankings without altering scoring formulas.
- **Multi-Organisation Support:** Pre-configured profiles for Banking, Cloud Technology, and Critical Infrastructure sectors.
- **CyberTech Enterprise Dashboard:** Responsive web interface featuring real-time organization switching, threat metrics, collapsible vulnerability cards, filterable findings table, and full contextual analysis modals.
- **AI Threat Intelligence & Remediation Playbooks:** One-click generation of CISO executive briefings, adversary attack vectors, step-by-step mitigation plans, and SIEM detection signatures powered by Featherless.ai open-source LLMs (Llama 3.1, Mistral, Qwen, DeepSeek).
- **Interactive AI Cyber Copilot:** Real-time conversational drawer for instant incident response Q&A and emergency mitigation workarounds.
- **Secure Authentication UI:** Full-screen responsive CyberTech login experience with form validation, password visibility toggle, session persistence, and disconnect controls.
- **Dual Execution Modes:** Available both as a standalone CLI analysis tool and as a lightweight web application.

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

## Validation Mechanism

VULNTRIAGE includes an automated validation module (`src/validation.py`) to verify how calculated algorithmic priorities align with human expert practitioner judgments:

- **Independent Benchmark:** Practitioner rankings are strictly used as an external validation comparator. They do **not** influence or mutate the core mathematical risk ranking calculations.
- **Comparative Alignment:** Scored outputs for benchmark CVEs are matched against `practitioner_rank_bank` (for ORG-001) and `practitioner_rank_startup` (for ORG-002) to calculate relative rank offsets.
- **Graceful Handling of Unmapped Profiles:** For organizations without dedicated practitioner columns (such as ORG-003 Municipal Utility Provider), the validation module gracefully reports the absence of reference data without halting execution.

---

## Technology Stack

- **Backend:**
  - **Python 3** (Standard Library only: `http.server`, `json`, `csv`, `re`, `os`, `sys`, `mimetypes`)
  - Zero heavy external backend framework dependencies required.
- **Frontend:**
  - **HTML5 & Vanilla CSS3** (Custom CyberTech Design System, CSS Grid & Flexbox, Glassmorphism, CSS Custom Properties)
  - **JavaScript (ES6+)**
  - **Vue.js 3** (via Global CDN build)
- **Typography:**
  - Google Fonts: `Outfit`, `Share Tech Mono`, `Inter`
- **Data Formats:**
  - JSON (`organizations.json`, `profiles.json`)
  - CSV (`vulnerabilities.csv`, `practitioner.csv`, `gold_set.csv`)

---

## Project Structure

```text
cybersecurity/
├── data/
│   ├── dirty_student_data.csv        # Supplementary data
│   ├── gold_set.csv                  # Reference benchmark dataset
│   ├── organizations.json            # Organization configuration schemas
│   ├── practitioner.csv              # Practitioner ranking reference
│   ├── profiles.json                 # Organization profiles mirror
│   └── vulnerabilities.csv           # Vulnerability records corpus
├── src/
│   ├── ai_analyst.py                 # Featherless.ai LLM client & prompt templates
│   ├── data_loader.py                # Dataset ingestion & schema validation
│   ├── main.py                       # CLI execution entry point
│   ├── matcher.py                    # Product string normalisation & matching
│   ├── ranking.py                    # Ranking & Top-N selection logic
│   ├── scorer.py                     # Risk scoring formula & contribution math
│   └── validation.py                 # Practitioner benchmark validation
├── static/
│   ├── index.css                     # CyberTech theme & responsive layout styles
│   ├── index.html                    # Single-page application & login markup
│   └── index.js                      # Vue 3 reactive state & auth controllers
├── server.py                         # HTTP server & static/API request handler
├── .gitignore                        # Git exclusion rules
└── README.md                         # Project documentation
```

---

## Getting Started

### Prerequisites
- Python 3.8 or higher installed on your system.
- Any modern web browser (Chrome, Edge, Firefox, Safari).

### Option 1: Run the Interactive Web Application

1. Start the HTTP server:
   ```bash
   python server.py
   ```
2. Open your web browser and navigate to:
   ```text
   http://localhost:5000/
   ```
3. Use the login screen to sign in (a quick **AUTO-FILL** button is available for `analyst@vulntriage.sec`), or explore the full interactive dashboard.

### Option 2: Run the CLI Analysis Suite

To execute the complete end-to-end data validation, product matching, risk scoring, Top 5 ranking, and practitioner comparison directly in the terminal:

```bash
python src/main.py
```
