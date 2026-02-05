#!/usr/bin/env python3

import requests
import sys

API_BASE = "https://access.redhat.com/hydra/rest/securitydata"

import re

def is_exact_rhel_version(product_name, version):
    pattern = rf"^red hat enterprise linux {version}($| \()"
    return re.search(pattern, product_name.lower()) is not None


def get_rhsas_for_cve(cve, rhel_version):
    url = f"{API_BASE}/cve/{cve}.json"
    r = requests.get(url, timeout=10)

    if r.status_code != 200:
        print(f"[!] Failed to fetch data for {cve}")
        return []

    data = r.json()
    unique_rhsas = {}

    for advisory in data.get("affected_release", []):
        product = advisory.get("product_name", "").lower()

        if is_exact_rhel_version(product, rhel_version):
            rhsa_id = advisory.get("advisory")
            if rhsa_id not in unique_rhsas:
                unique_rhsas[rhsa_id] = {
                    "package": advisory.get("package"),
                    "release_date": advisory.get("release_date"),
                }

    return unique_rhsas


def RHSA():
    cves = [input("Enter CVE ID (e.g., CVE-2023-1234): ").strip()]
    rhel_version = input("Enter RHEL version (e.g., 8, 9): ").strip()

    results = {}  # Store CVE -> list of RHSA IDs

    for cve in cves:
        rhsas = get_rhsas_for_cve(cve, rhel_version)

        if not rhsas:
            results[cve] = []
        else:
            results[cve] = list(rhsas.keys())  # Only RHSA IDs

        print(results)

    return results

RHSA()


