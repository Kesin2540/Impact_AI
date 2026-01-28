#!/usr/bin/env python3
"""
OSV Patch Impact Engine (Deterministic Fix-Aware Edition)

- Uses OSV.dev as authoritative source
- Extracts fixed versions deterministically
- Computes version delta (MAJOR / MINOR / PATCH)
- LLM reasons ONLY on derived patch facts
- Explicit confidence modeling
"""

import json
import urllib.request
import re
import ollama
from packaging.version import Version, InvalidVersion

# -----------------------------
# Configuration
# -----------------------------

OSV_QUERY_URL = "https://api.osv.dev/v1/query"

SYSTEM_PROMPT = """
You are a Senior Site Reliability Engineer (SRE).

You are evaluating a THIRD-PARTY software update using ONLY the provided data.
Do NOT assume vendor guarantees.
Do NOT invent patch behavior.

Assess OPERATIONAL IMPACT based on:
- Version delta (major/minor/patch)
- Scope implied by vulnerability descriptions

### OUTPUT FORMAT (JSON ONLY):
{
  "impact_level": "LOW|MODERATE|HIGH",
  "summary": "string",
  "requires_restart": true|false,
  "confidence": "LOW",
  "confidence_reason": []
}
"""

# -----------------------------
# OSV Query
# -----------------------------

def fetch_osv_data(package, version, ecosystem):
    query = {
        "package": {"name": package, "ecosystem": ecosystem},
        "version": version
    }
    data = json.dumps(query).encode("utf-8")
    req = urllib.request.Request(OSV_QUERY_URL, data=data, method="POST")
    req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read().decode()).get("vulns", [])
    except Exception:
        return []

# -----------------------------
# Fix Version Extraction
# -----------------------------

def extract_fixed_versions(vulns):
    fixes = set()

    for v in vulns:
        for affected in v.get("affected", []):
            for r in affected.get("ranges", []):
                for ev in r.get("events", []):
                    if "fixed" in ev:
                        try:
                            fixes.add(str(Version(ev["fixed"])))
                        except InvalidVersion:
                            continue

    return sorted(fixes, key=Version)

# -----------------------------
# Version Delta Logic
# -----------------------------

def classify_version_delta(current, target):
    try:
        c = Version(current)
        t = Version(target)
    except InvalidVersion:
        return "UNKNOWN"

    if t.major != c.major:
        return "MAJOR"
    if t.minor != c.minor:
        return "MINOR"
    if t.micro != c.micro:
        return "PATCH"
    return "NONE"

def choose_nearest_fix(current, fixes):
    try:
        curr = Version(current)
    except InvalidVersion:
        return None

    same_major_minor = [
        f for f in fixes
        if Version(f).major == curr.major and Version(f).minor == curr.minor
    ]

    return same_major_minor[0] if same_major_minor else (fixes[0] if fixes else None)

# -----------------------------
# LLM Reasoning
# -----------------------------

def llm_assess(context):
    response = ollama.chat(
        model="qwen2.5:3b",
        format="json",
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": json.dumps(context, indent=2)}
        ]
    )

    raw = response["message"]["content"]
    match = re.search(r'(\{.*\})', raw, re.DOTALL)

    if not match:
        return {
            "impact_level": "UNKNOWN",
            "summary": "LLM output was not parseable.",
            "requires_restart": False,
            "confidence": "LOW",
            "confidence_reason": ["Invalid LLM output"]
        }

    return json.loads(match.group(1))

# -----------------------------
# Main
# -----------------------------

if __name__ == "__main__":
    print("--- OSV Patch Impact Engine ---")

    pkg = input("Package name: ").strip()
    ver = input("Current version: ").strip()
    eco = input("Ecosystem (PyPI, npm, Go, Maven, etc.): ").strip()

    vulns = fetch_osv_data(pkg, ver, eco)

    if not vulns:
        print("\n[+] No known vulnerabilities for this version.")
        exit(0)

    fixes = extract_fixed_versions(vulns)
    target = choose_nearest_fix(ver, fixes)

    if not target:
        print("\n[!] Vulnerabilities found, but no fixed version available.")
        exit(1)

    delta = classify_version_delta(ver, target)

    # Build deterministic context for the LLM
    context = {
        "package": pkg,
        "ecosystem": eco,
        "current_version": ver,
        "target_version": target,
        "version_delta": delta,
        "vulnerability_count": len(vulns),
        "vulnerability_summaries": [
            v.get("summary", "") for v in vulns
        ][:5],
        "confidence": "LOW",
        "confidence_reason": [
            "Third-party software",
            "No vendor patch advisory available",
            "Impact inferred from version delta and vulnerability descriptions"
        ]
    }

    report = llm_assess(context)

    print("\n" + "=" * 50)
    print(f"PATCH IMPACT REPORT: {pkg}")
    print("=" * 50)
    print(json.dumps(report, indent=2))
