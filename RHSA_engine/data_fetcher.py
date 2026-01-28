import json
import urllib.request
import re
import subprocess

RH_CSAF_URL = "https://access.redhat.com/hydra/rest/securitydata/csaf/{}.json"

def fetch_csaf(rhsa_id):
    """Fetches the full CSAF JSON from Red Hat"""
    url = RH_CSAF_URL.format(rhsa_id)
    req = urllib.request.Request(url, headers={"User-Agent": "Impact-Engine/2.0"})
    try:
        with urllib.request.urlopen(req) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        print(f"Error fetching {rhsa_id}: {e}")
        return None
    

def extract_impact_data(csaf):
    """Deep-dives into CSAF to extract packages and technical notes"""
    packages = set()
    descriptions = []
    
    # 1. Extract Packages from Product Tree
    # We look for 'full_product_name' entries which contain the fixed RPM strings
    def find_names(obj):
        if isinstance(obj, dict):
            if "full_product_name" in obj:
                # Regex to extract package name from strings like 'httpd-2.4.37-56.el8.x86_64'
                name_str = obj["full_product_name"].get("name", "")
                match = re.match(r"^([a-zA-Z0-9_\-]+)(?=-\d)", name_str)
                if match: packages.add(match.group(1))
            for v in obj.values(): find_names(v)
        elif isinstance(obj, list):
            for i in obj: find_names(i)

    find_names(csaf.get("product_tree", {}))

    # 2. Extract Technical Descriptions from Vulnerabilities
    for vuln in csaf.get("vulnerabilities", []):
        for note in vuln.get("notes", []):
            if note.get("category") in ["description", "summary", "general"]:
                descriptions.append(note.get("text", ""))

    packages = {
        p for p in packages
            if not p.endswith(("-debuginfo", "-debugsource"))
    }

    return {
        "advisory_id": csaf.get("document", {}).get("tracking", {}).get("id"),
        "title": csaf.get("document", {}).get("title"),
        "severity": csaf.get("document", {}).get("aggregate_severity", {}).get("text"),
        "affected_packages": sorted(list(packages)),
        "technical_details": " ".join(descriptions)[:2000] # Limit to avoid context overflow
    }

def analyze_reverse_deps(packages):
    """RESTORED: Calculates how many other things break if these packages change"""
    total = 0
    for p in packages:
        try:
            out = subprocess.check_output(["repoquery", "--recursive", "--installed", "--whatrequires", p, "--qf", "%{name}"], stderr=subprocess.DEVNULL, timeout=5).decode()
            total += len(out.splitlines())
        except: continue
    
    avg = total / len(packages) if packages else 0
    if avg > 80:
        fanout = "VERY_HIGH"
    elif 21 < avg and avg < 80:
        fanout = "HIGH"
    elif 5 < avg and avg < 20:
        fanout = "MODERATE"
    else:
        fanout = "LOW"
    return {"average_reverse_deps": round(avg, 1), "fanout_level": fanout}