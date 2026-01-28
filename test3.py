#!/usr/bin/env python3
"""
Multi-Platform Patch Impact Engine (NVD Edition)
- Fetches from NVD API 2.0
- CPE Parser: Extracts software names from NIST CPE strings.
- Safety Net: Hard-coded logic for reboots to prevent AI hallucination.
"""

import json
import urllib.request
import re
import ollama

# -----------------------------
# Configuration
# -----------------------------

# NVD API 2.0 Endpoint
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"
# Get a key at https://nvd.nist.gov/developers/request-an-api-key for higher rate limits
NVD_API_KEY = "355920ca-2b5c-4717-bc7c-17b0137c4dfe" 

# Critical components that ALWAYS require a reboot/heavy caution
CRITICAL_COMPONENTS = {"linux_kernel", "glibc", "openssl", "systemd", "windows_server"}

SYSTEM_PROMPT = """
You are a Senior Site Reliability Engineer (SRE).
Analyze the provided CVE data and assess the "Operational Blast Radius."
Also infer from your already known data whether the patch is likely to require a reboot.

### GUIDELINES:
1. REBOOTS: If the software is a Kernel or Core System Library, reboot_required is ALWAYS true.
2. IMPACT: HIGH = System-wide downtime; MODERATE = Service restart; LOW = No downtime.
3. REGRESSION: Is the fix likely to break custom configurations?

### OUTPUT FORMAT:
Return ONLY a JSON object:
{"impact_level": "LOW/LOW-MODERATE/MODERATE/MODERATE-HIGH/HIGH", "summary": "string", "service_requires_restart": bool, "system_requires_restart": bool, "restart_services": []}
"""

# -----------------------------
# Data Fetching & CPE Parsing
# -----------------------------

def fetch_nvd_data(cve_id):
    """Fetches CVE data from NIST NVD"""
    url = NVD_API_URL.format(cve_id)
    headers = {"User-Agent": "SRE-Impact-Bot/1.0"}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        print(f"Error: {e}")
        return None

def parse_nvd_json(raw_json):
    """Extracts CVSS, Description, and affected products from NVD JSON"""
    if not raw_json.get("vulnerabilities"):
        return None
    
    cve_item = raw_json["vulnerabilities"][0]["cve"]
    
    # Extract English Description
    descriptions = cve_item.get("descriptions", [])
    summary = next((d["value"] for d in descriptions if d["lang"] == "en"), "No description found.")
    
    # Extract Severity
    metrics = cve_item.get("metrics", {})
    cvss_v31 = metrics.get("cvssMetricV31", [{}])[0].get("cvssData", {})
    severity = cvss_v31.get("baseSeverity", "UNKNOWN")

    # Extract Affected Software from CPE strings
    affected_software = set()
    configs = cve_item.get("configurations", [])
    for config in configs:
        for node in config.get("nodes", []):
            for cpe_match in node.get("cpeMatch", []):
                cpe = cpe_match.get("criteria", "")
                # CPE Format: cpe:2.3:part:vendor:product:version...
                parts = cpe.split(":")
                if len(parts) > 4:
                    affected_software.add(parts[4]) # Extract 'product' name

    return {
        "cve_id": cve_item.get("id"),
        "severity": severity,
        "affected_software": list(affected_software),
        "technical_summary": summary[:1500]
    }

# -----------------------------
# Reasoning & Safety Logic
# -----------------------------

def sre_assessment(data):
    """The Agentic Reasoning Core with Robust Output Parsing"""
    
    is_kernel = any(comp in data["affected_software"] for comp in CRITICAL_COMPONENTS)
    
    prompt_input = (
        f"CVE ID: {data['cve_id']}\n"
        f"Affected Software: {', '.join(data['affected_software'])}\n"
        f"Context: {data['technical_summary']}\n"
        f"SRE Note: {'[CRITICAL] Kernel update detected.' if is_kernel else ''}"
    )

    # Upgrade 1: Use the 'format' parameter to force JSON mode in Ollama
    response = ollama.chat(
        model="qwen2.5:3b",
        format="json", 
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt_input}
        ]
    )

    raw_content = response["message"]["content"]

    try:
        # Upgrade 2: Use Regex to extract only the part between { and }
        # This handles the case where the AI adds "Sure! Here is the JSON:"
        json_match = re.search(r'(\{.*\})', raw_content, re.DOTALL)
        if json_match:
            clean_json = json_match.group(1)
            report = json.loads(clean_json)
        else:
            raise ValueError("No JSON block found in output")

        # Post-processing Safety Net
        if is_kernel:
            report["reboot_required"] = True
            report["impact_level"] = "HIGH"
            
        return report

    except (json.JSONDecodeError, ValueError) as e:
        # If it still fails, we return a structured 'failure' object 
        # so the rest of your script doesn't crash.
        return {
            "impact_level": "UNKNOWN",
            "summary": "LLM failed to produce parsable impact report.",
            "reboot_required": is_kernel, # Fallback to safety
            "error_detail": str(e),
            "raw_debug": raw_content[:200]
        }
    

# -----------------------------
# Main Execution
# -----------------------------

if __name__ == "__main__":
    cve_id = input("Enter CVE (e.g., CVE-2023-25690): ").strip().upper()
    
    raw = fetch_nvd_data(cve_id)
    if raw:
        processed = parse_nvd_json(raw)
        print(f"[*] Analyzing {cve_id} against {len(processed['affected_software'])} components...")
        
        final_report = sre_assessment(processed)
        
        print("\n" + "="*40)
        print(f"SRE BLAST RADIUS REPORT: {cve_id}")
        print("="*40)
        print(json.dumps(final_report, indent=2))
    else:
        print("Could not find CVE or NVD API is rate-limiting.")