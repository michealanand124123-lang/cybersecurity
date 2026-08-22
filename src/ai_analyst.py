import os
import json
import urllib.request
import urllib.error

# Featherless.ai OpenAI-compatible endpoint
FEATHERLESS_API_URL = "https://api.featherless.ai/v1/chat/completions"

# Default supported models on Featherless
AVAILABLE_MODELS = [
    {
        "id": "meta-llama/Meta-Llama-3.1-8B-Instruct",
        "name": "Llama 3.1 8B Instruct (Recommended / Fast)",
        "provider": "Meta"
    },
    {
        "id": "mistralai/Mistral-7B-Instruct-v0.3",
        "name": "Mistral 7B Instruct v0.3",
        "provider": "Mistral AI"
    },
    {
        "id": "Qwen/Qwen2.5-7B-Instruct",
        "name": "Qwen 2.5 7B Instruct",
        "provider": "Alibaba"
    },
    {
        "id": "deepseek-ai/DeepSeek-R1-Distill-Qwen-8B",
        "name": "DeepSeek R1 Distill Qwen 8B (Reasoning)",
        "provider": "DeepSeek"
    }
]

def get_api_key(client_key=None):
    """Retrieves API key prioritizing client-provided key, then environment variable."""
    if client_key and client_key.strip():
        return client_key.strip()
    return os.environ.get("FEATHERLESS_API_KEY", "").strip()

def call_featherless_chat(messages, api_key=None, model="meta-llama/Meta-Llama-3.1-8B-Instruct", max_tokens=1000, temperature=0.2):
    """
    Executes a chat completion call to Featherless.ai using standard urllib.
    
    Returns:
        tuple: (content_string, error_string_or_none)
    """
    key = get_api_key(api_key)
    if not key:
        return None, "NO_API_KEY"

    payload = {
        "model": model or "meta-llama/Meta-Llama-3.1-8B-Instruct",
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens
    }

    req_data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        FEATHERLESS_API_URL,
        data=req_data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
            "User-Agent": "VULNTRIAGE-CyberDefense/1.0"
        },
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            res_body = response.read().decode("utf-8")
            res_json = json.loads(res_body)
            choices = res_json.get("choices", [])
            if choices and len(choices) > 0:
                content = choices[0].get("message", {}).get("content", "")
                return content, None
            return None, "Empty response received from Featherless API."
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="ignore")
        try:
            err_json = json.loads(err_msg)
            if "error" in err_json:
                return None, f"Featherless API Error ({e.code}): {err_json['error'].get('message', err_msg)}"
        except Exception:
            pass
        return None, f"Featherless API HTTP {e.code}: {err_msg or e.reason}"
    except urllib.error.URLError as e:
        return None, f"Network connection error to Featherless API: {e.reason}"
    except Exception as e:
        return None, f"Unexpected error during AI generation: {str(e)}"

def generate_remediation_playbook(vuln, org, api_key=None, model="meta-llama/Meta-Llama-3.1-8B-Instruct"):
    """
    Generates a tailored Cyber Defense Remediation Playbook using Featherless LLM.
    """
    cve_id = vuln.get("cve_id", "Unknown CVE")
    product = vuln.get("product_name", "Unknown Product")
    cvss = vuln.get("cvss_base_score", 0.0)
    kev = "ACTIVE IN THE WILD (CISA KEV Listed)" if vuln.get("cisa_kev") else "Not currently listed in CISA KEV"
    epss = f"{(float(vuln.get('first_epss', 0.0)) * 100):.2f}%"
    risk_score = vuln.get("risk_score", 0.0)

    org_name = org.get("name", "Target Organisation")
    sector = org.get("sector", "Enterprise")
    risk_appetite = org.get("risk_appetite", "Standard")

    system_prompt = (
        "You are VULNTRIAGE AI Cyber Intelligence Analyst, an elite SecOps and Vulnerability Management expert. "
        "Your role is to produce clear, authoritative, highly technical, and immediately actionable remediation playbooks "
        "tailored to the organization's business sector and technology stack. Format with clear Markdown headings, bullet points, and code snippets."
    )

    user_prompt = f"""Generate a comprehensive Cyber Defense Remediation Playbook for the following prioritized vulnerability:

### Target Organisation Context:
- **Organisation:** {org_name}
- **Industry Sector:** {sector}
- **Risk Appetite:** {risk_appetite}

### Prioritized Threat Telemetry:
- **Vulnerability ID:** {cve_id}
- **Affected Business Asset:** {product}
- **CVSS Base Severity:** {cvss}
- **Active Exploitation Status:** {kev}
- **EPSS Exploitation Likelihood:** {epss}
- **Computed Contextual Risk Score:** {risk_score}

Please structure the playbook into the following 4 sections:
1. 🛡️ **Executive Risk Summary & Business Impact:** (2-3 concise sentences for CISOs explaining why this asset is at risk).
2. 🔍 **Adversary Attack Vector & Weaponization Path:** (How attackers exploit this specific product flaw in the wild).
3. 🛠️ **Actionable Step-by-Step Remediation Plan:** (Immediate short-term workarounds, config hardenings, firewall rules, and permanent patch guidance).
4. 🚨 **Detection Rule / SIEM Signature:** (Provide a concrete Splunk, KQL, Suricata, or Snort rule template to detect exploitation attempts).
"""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt}
    ]

    content, error = call_featherless_chat(messages, api_key=api_key, model=model)
    
    if error == "NO_API_KEY":
        # Provide clean structured fallback guidance
        fallback_playbook = f"""### 🛡️ Executive Risk Summary & Business Impact
**{cve_id}** poses a significant threat to **{org_name}**'s critical asset **{product}**. With a CVSS base score of **{cvss}** and an EPSS exploitation probability of **{epss}**, this vulnerability requires prioritized intervention under your **{risk_appetite}** risk tolerance policy.

### 🔍 Adversary Attack Vector & Weaponization Path
Threat actors exploit unauthenticated remote code execution or state deserialization flaws in **{product}** to bypass identity boundaries and gain lateral movement. {kev}.

### 🛠️ Actionable Step-by-Step Remediation Plan
1. **Immediate Quarantine:** Restrict ingress network access to **{product}** endpoints using strict firewall ACLs.
2. **Patch Application:** Deploy the latest vendor security advisory update for **{product}**.
3. **Session Audit:** Invalidate all active administrative sessions and force multi-factor re-authentication.

### 🚨 Detection Rule / SIEM Query
```splint
index=security sourcetype=firewall OR sourcetype=waf dest_product="{product}" (status=403 OR status=500 OR "{cve_id}")
| stats count by src_ip, dest_ip, uri_path, http_method
| where count > 10
```

> 💡 **Notice:** To generate dynamic real-time AI playbooks powered by Featherless open-source LLMs (Llama 3.1, Mistral, DeepSeek), please enter your **Featherless API Key** in the **AI Settings** panel.
"""
        return {
            "success": True,
            "playbook": fallback_playbook,
            "is_mock": True,
            "model": "VULNTRIAGE Built-in Intelligence Engine"
        }

    if error:
        return {
            "success": False,
            "error": error,
            "playbook": None,
            "model": model
        }

    return {
        "success": True,
        "playbook": content,
        "is_mock": False,
        "model": model
    }

def ask_copilot_chat(query, vuln, org, chat_history=None, api_key=None, model="meta-llama/Meta-Llama-3.1-8B-Instruct"):
    """
    Handles interactive conversational queries about a vulnerability or organization context.
    """
    cve_id = vuln.get("cve_id", "General") if vuln else "General Environment"
    product = vuln.get("product_name", "Infrastructure") if vuln else "Infrastructure"
    cvss = vuln.get("cvss_base_score", "N/A") if vuln else "N/A"
    kev = "Yes (CISA KEV)" if (vuln and vuln.get("cisa_kev")) else "No"
    epss = f"{(float(vuln.get('first_epss', 0.0)) * 100):.2f}%" if vuln else "N/A"
    
    org_name = org.get("name", "Organisation") if org else "Target Enterprise"
    sector = org.get("sector", "Enterprise") if org else "Enterprise"
    risk_appetite = org.get("risk_appetite", "Standard") if org else "Standard"

    system_prompt = (
        f"You are the VULNTRIAGE AI Cyber Copilot. You are assisting a security engineer at {org_name} ({sector} sector, {risk_appetite} risk appetite). "
        f"Active context: CVE {cve_id} on {product} (CVSS: {cvss}, KEV: {kev}, EPSS: {epss}). "
        "Provide direct, sharp, professional cybersecurity answers. Use concise markdown formatting."
    )

    messages = [{"role": "system", "content": system_prompt}]
    
    if chat_history and isinstance(chat_history, list):
        for msg in chat_history[-6:]: # Keep last 6 context turns
            if isinstance(msg, dict) and "role" in msg and "content" in msg:
                messages.append({"role": msg["role"], "content": msg["content"]})

    messages.append({"role": "user", "content": query})

    content, error = call_featherless_chat(messages, api_key=api_key, model=model, max_tokens=600)
    
    if error == "NO_API_KEY":
        # Helpful response with key reminder
        mock_reply = (
            f"**[Copilot Analysis for {org_name} - {product}]**\n\n"
            f"Regarding *\"{query}\"*: For **{cve_id}**, the primary recommendation is applying micro-segmentation around **{product}** and enforcing TLS mutual authentication. "
            f"Because this organization has a **{risk_appetite}** risk tolerance, ensure zero-trust logging is enabled on all ingress traffic.\n\n"
            "> 💡 *Tip: Connect your free Featherless API Key in **AI Settings** for live interactive responses from Llama 3.1 & Mistral.*"
        )
        return {
            "success": True,
            "reply": mock_reply,
            "is_mock": True,
            "model": "VULNTRIAGE Built-in Copilot"
        }

    if error:
        return {
            "success": False,
            "error": error,
            "reply": None
        }

    return {
        "success": True,
        "reply": content,
        "is_mock": False,
        "model": model
    }
