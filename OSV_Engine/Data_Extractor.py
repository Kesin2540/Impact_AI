import json
import urllib.request
from collections import defaultdict

OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"

# -----------------------------
# 1. Fetch OSV vulnerability
# -----------------------------
def fetch_osv(vuln_id):
    """Fetch OSV vulnerability JSON (CVE, GHSA, etc.)"""
    url = OSV_VULN_URL.format(vuln_id)
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "Impact-Engine/2.0"}
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        print(f"Error fetching {vuln_id}: {e}")
        return None


# -----------------------------
# 2. Extract impact data
# -----------------------------
def extract_impact_data(osv):
    """
    Extracts affected packages, versions, severity, and
    technical descriptions from an OSV record.
    """
    affected = defaultdict(list)

    # Affected packages + version ranges
    for item in osv.get("affected", []):
        pkg = item.get("package", {})
        ecosystem = pkg.get("ecosystem")
        name = pkg.get("name")

        if not ecosystem or not name:
            continue

        for r in item.get("ranges", []):
            for ev in r.get("events", []):
                affected[ecosystem].append({
                    "package": name,
                    "introduced": ev.get("introduced"),
                    "fixed": ev.get("fixed"),
                    "last_affected": ev.get("last_affected")
                })

    # Technical narrative
    descriptions = []
    if osv.get("summary"):
        descriptions.append(osv["summary"])
    if osv.get("details"):
        descriptions.append(osv["details"])

    # Severity normalization (best-effort)
    severity = "UNKNOWN"
    for s in osv.get("severity", []):
        if s.get("type") == "CVSS_V3":
            try:
                score = float(s["score"].split("/")[0])
                if score >= 9.0:
                    severity = "CRITICAL"
                elif score >= 7.0:
                    severity = "HIGH"
                elif score >= 4.0:
                    severity = "MEDIUM"
                else:
                    severity = "LOW"
            except Exception:
                pass

    return {
        "vuln_id": osv.get("id"),
        "aliases": osv.get("aliases", []),
        "severity": severity,
        "affected_packages": dict(affected),
        "technical_details": " ".join(descriptions)[:2000]
    }


# -----------------------------
# 3. End-to-end helper
# -----------------------------
def analyze_vulnerability(vuln_id):
    osv = fetch_osv(vuln_id)
    if not osv:
        return None
    return extract_impact_data(osv)
