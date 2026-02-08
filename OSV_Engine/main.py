from audit_engine import (
    is_package_live,
    get_service_context,
    get_live_signal_assessment,
    HIGH_BLAST_LIBRARIES,
    advisory_requires_reboot,
    extract_restart_services,
    package_execution_domain
)
from Data_Extractor import fetch_osv, extract_impact_data
from ReverseDepsAnalyzer import analyze_reverse_deps_for_osv
from llm_processor import llm_assess
import json
import os
import csv

# Default scan path - can be configured
DEFAULT_SCAN_PATH = "/"

def analyze_patch(vuln_id, scan_path: str = DEFAULT_SCAN_PATH):
    """
    Main pipeline for OSV vulnerability analysis.
    Similar to RHSA_engine/main.py but adapted for OSV vulnerabilities.
    """
    print(f"[*] Fetching OSV data for {vuln_id}...")
    osv = fetch_osv(vuln_id)
    if not osv:
        print(f"[!] Failed to fetch OSV data for {vuln_id}")
        return None

    print("[*] Extracting vulnerability context and affected packages...")
    extracted = extract_impact_data(osv)
    
    # Flatten affected packages for processing
    affected_packages_flat = []
    for ecosystem, packages in extracted.get("affected_packages", {}).items():
        for pkg_info in packages:
            pkg_name = pkg_info.get("package", "")
            affected_packages_flat.append({
                "name": pkg_name,
                "ecosystem": ecosystem,
                **pkg_info
            })
    
    extracted["affected_packages_flat"] = affected_packages_flat
    
    # Check which packages are live on the system
    print("[*] Checking which packages are live on the system...")
    live_packages = []
    for pkg_info in affected_packages_flat:
        pkg_name = pkg_info.get("name", "")
        ecosystem = pkg_info.get("ecosystem", "")
        is_live, pkg_details = is_package_live(pkg_name, ecosystem, scan_path)
        if is_live:
            live_packages.append({
                **pkg_info,
                "is_live": True,
                "details": pkg_details
            })
    
    extracted["live_packages"] = live_packages
    extracted["live_package_count"] = len(live_packages)
    
    if not live_packages:
        print("[!] No affected packages found to be live on the system.")
        print("[*] Assessment will proceed with static analysis only.")
    
    # Determine execution domain impact
    print("[*] Checking execution domain and reboot requirements...")
    extracted["reboot_required_signal"] = advisory_requires_reboot(
        live_packages if live_packages else affected_packages_flat,
        scan_path
    )

    if extracted.get("reboot_required_signal"):
        extracted["minimum_impact_level"] = "MODERATE-HIGH"
    else:
        extracted["minimum_impact_level"] = None

    extracted["system_service_status"] = get_service_context(
        live_packages if live_packages else affected_packages_flat,
        scan_path
    )

    # 1. PRE-EMPTIVE AUDIT: This is the primary signal for the LLM.
    # It finds exactly which SERVICES and PIDs are touching these files.
    print("[*] Performing Pre-emptive Live System Audit...")
    packages_to_audit = live_packages if live_packages else affected_packages_flat
    live_radius = get_live_signal_assessment(packages_to_audit, scan_path)

    extracted["live_audit_signal"] = {
        "radius": live_radius,
        "radius_counts": {
            k: len(v) if isinstance(v, dict) else 0 for k, v in live_radius.items()
        }
    }

    if extracted.get("reboot_required_signal"):
        # Boot-time updates cannot be resolved by restarting services
        extracted["restart_required_signal"] = False
        extracted["restart_services"] = []
    else:
        extracted["restart_required_signal"] = bool(
            live_radius.get("direct_exec") or
            live_radius.get("shared_dependency")
        )
        extracted["restart_services"] = extract_restart_services(live_radius)

    print("[*] Analyzing reverse dependencies (Static Fanout)...")
    # For OSV, we need to analyze reverse dependencies using SBOM
    try:
        revdeps = analyze_reverse_deps_for_osv(scan_path, extracted)
        extracted.update(revdeps)
    except Exception as e:
        print(f"[!] Error analyzing reverse dependencies: {e}")
        extracted["average_reverse_deps"] = 0
        extracted["fanout_level"] = "LOW"
    
    # 3. Core Impact Check
    core_packages = []
    for pkg_info in affected_packages_flat:
        pkg_name = pkg_info.get("name", "").lower()
        if any(high_blast in pkg_name for high_blast in HIGH_BLAST_LIBRARIES):
            core_packages.append(pkg_name)
    
    extracted["is_core_system_impact"] = len(core_packages) > 0
    extracted["core_packages"] = core_packages

    reboot_reasons = []
    for pkg in packages_to_audit:
        if package_execution_domain(pkg, scan_path) == "BOOT_TIME":
            pkg_name = pkg.get("name", "") if isinstance(pkg, dict) else str(pkg)
            reboot_reasons.append(f"Package '{pkg_name}' affects the BOOT_TIME execution domain.")
    
    extracted["reboot_rationale"] = reboot_reasons if reboot_reasons else ["No boot-time components detected."]

    # 4. Final Assessment
    print("[*] Running LLM Blast Radius Assessment...")
    # The LLM will now see exactly which services are 'hot' in the live_audit_signal
    report = llm_assess(extracted)

    # 5. Persist the assessment as a CSV record
    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)

    csv_path = os.path.join(reports_dir, "osv_engine_reports.csv")
    file_exists = os.path.exists(csv_path)
    needs_header = not file_exists or os.path.getsize(csv_path) == 0

    vuln_id_used = extracted.get("vuln_id", vuln_id)
    aliases = ";".join(extracted.get("aliases", []))
    severity = extracted.get("severity", "")

    impact_level = report.get("impact_level", "")
    reboot_required = report.get("reboot_required", False)
    service_requires_restart = report.get("service_requires_restart", False)
    restart_services = ";".join(report.get("restart_services", []))
    summary = report.get("summary", "")
    technical_justification = report.get("technical_justification", "")

    with open(csv_path, "a", encoding="utf-8", newline="") as csvfile:
        writer = csv.writer(csvfile)
        if needs_header:
            writer.writerow([
                "vuln_id",
                "aliases",
                "severity",
                "impact_level",
                "reboot_required",
                "service_requires_restart",
                "restart_services",
                "summary",
                "technical_justification",
            ])
        writer.writerow([
            vuln_id_used,
            aliases,
            severity,
            impact_level,
            reboot_required,
            service_requires_restart,
            restart_services,
            summary,
            technical_justification,
        ])

    print(f"[*] SRE report CSV row written to {csv_path}")
    
    return {
        "metadata": extracted,
        "assessment": report
    }

if __name__ == "__main__":
    vuln_id = input("Enter OSV vulnerability ID (e.g., CVE-2023-12345, GHSA-xxxx-xxxx): ").strip()
    scan_path = input("Enter scan path (default: /): ").strip() or DEFAULT_SCAN_PATH
    print(json.dumps(analyze_patch(vuln_id, scan_path), indent=2))
