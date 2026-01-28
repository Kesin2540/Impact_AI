#!/usr/bin/env python3
import json
import urllib.request
import re
import ollama
from packaging import version  # Required for SemVer comparison

# -----------------------------
# Configuration
# -----------------------------
OSV_QUERY_URL = "https://api.osv.dev/v1/query"

SYSTEM_PROMPT = """
You are a Senior SRE Engineer. 
You are evaluating a third-party library update based on OSV data and Version Delta signals.

### GOAL:
Reason on the "Operational Impact" of patching. Determine if this is a "blind" update or requires code refactoring.

### CRITERIA:
1. DELTA SIGNAL: If the delta is 'MAJOR', prioritize 'Breaking Risk' in your summary.
2. TYPE: Is this a "Runtime" library (affects the running app) or a "Build" tool (low risk)?
3. SCOPE: Does the vulnerability affect a core function (e.g. Auth, Crypto) or a niche feature?
4. RESTART REQUIREMENT: Based on the vulnerabilities and delta, decide if a service restart is needed.

### OUTPUT FORMAT:
Return ONLY JSON:
{"impact_level": "LOW/LOW-MODERATE/MODERATE/MODERATE-HIGH/HIGH", "summary": "string", "service_requires_restart": bool, "system_requires_restart": bool, "version_analysis": "string"}
"""

# -----------------------------
# Helper Functions
# -----------------------------

def get_fix_version(vuln):
    """Deeply parses OSV affected ranges to find the first fixed version."""
    fix_versions = []
    for affected in vuln.get("affected", []):
        for v_range in affected.get("ranges", []):
            for event in v_range.get("events", []):
                if "fixed" in event:
                    fix_versions.append(event["fixed"])
    
    # Sort and return the earliest fix version found
    if fix_versions:
        try:
            return sorted(fix_versions, key=lambda x: version.parse(x))[0]
        except:
            return fix_versions[0]
    return "Unknown"

def calculate_delta(current, fixed):
    """Calculates the distance between current and safe versions."""
    if fixed == "Unknown": return "UNKNOWN"
    try:
        curr = version.parse(current)
        fix = version.parse(fixed)
        
        if fix.major > curr.major: return "MAJOR (Breaking Changes Likely)"
        if fix.minor > curr.minor: return "MINOR (Feature Addition)"
        return "PATCH (Bugfix/Low Risk)"
    except:
        return "NON-STANDARD"

# -----------------------------
# Data & Reasoning
# -----------------------------

def fetch_osv_data(package_name, ver, ecosystem):
    query = {"version": ver, "package": {"name": package_name, "ecosystem": ecosystem}}
    data = json.dumps(query).encode("utf-8")
    req = urllib.request.Request(OSV_QUERY_URL, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read().decode()).get("vulns", [])
    except: return []

def assess_impact(package, current_ver, ecosystem, vulns):
    context_blocks = []
    global_delta = "PATCH"

    for v in vulns:
        fix_v = get_fix_version(v)
        delta = calculate_delta(current_ver, fix_v)
        if "MAJOR" in delta: global_delta = "MAJOR"
        
        context_blocks.append(
            f"ID: {v['id']}\nFix Version: {fix_v}\nDelta: {delta}\nSummary: {v.get('summary')}\n---"
        )

    full_context = "\n".join(context_blocks)
    prompt = f"Package: {package}\nCurrent: {current_ver}\nEcosystem: {ecosystem}\nDelta Signal: {global_delta}\n\nVulnerabilities:\n{full_context}"

    response = ollama.chat(
        model="qwen2.5:3b",
        format="json",
        messages=[{"role": "system", "content": SYSTEM_PROMPT}, {"role": "user", "content": prompt}]
    )
    return json.loads(response["message"]["content"])

# -----------------------------
# Main
# -----------------------------
if __name__ == "__main__":
    pkg = input("Package: ").strip()
    ver = input("Version: ").strip()
    eco = input("Ecosystem (PyPI/npm/Go): ").strip()

    print(f"[*] Analyzing {pkg}...")
    vulns = fetch_osv_data(pkg, ver, eco)

    if not vulns:
        print("No vulnerabilities found.")
    else:
        report = assess_impact(pkg, ver, eco, vulns)
        print("\n--- SRE IMPACT REPORT ---")
        print(json.dumps(report, indent=2))