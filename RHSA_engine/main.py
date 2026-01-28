from audit_engine import package_execution_domain, get_service_context, get_live_signal_assessment, HIGH_BLAST_LIBRARIES, advisory_requires_reboot, extract_restart_services
from data_fetcher import fetch_csaf, extract_impact_data, analyze_reverse_deps
from llm_processor import llm_assess
import json
import os
import csv

def analyze_patch(rhsa_id):
    print(f"[*] Fetching data for {rhsa_id}...")
    csaf = fetch_csaf(rhsa_id)
    if not csaf: return

    print("[*] Extracting package context and technical notes...")
    extracted = extract_impact_data(csaf)

    print("[*] Checking systemd service states...")
    # Determine execution domain impact
    extracted["reboot_required_signal"] = advisory_requires_reboot(
        extracted["affected_packages"]
    )

    if extracted.get("reboot_required_signal"):
        extracted["minimum_impact_level"] = "MODERATE-HIGH"
    else:
        extracted["minimum_impact_level"] = None

    extracted["system_service_status"] = get_service_context(
        extracted["affected_packages"]
    )

    # 1. PRE-EMPTIVE AUDIT: This is the primary signal for the LLM.
    # It finds exactly which SERVICES and PIDs are touching these files.
    print("[*] Performing Pre-emptive Live System Audit...")
    live_radius = get_live_signal_assessment(extracted["affected_packages"])

    extracted["live_audit_signal"] = {
        "radius": live_radius,
        "radius_counts": {
            k: len(v) for k, v in live_radius.items()
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
    revdeps = analyze_reverse_deps(extracted["affected_packages"])
    extracted.update(revdeps)
    
    # 3. Core Impact Check
    extracted["is_core_system_impact"] = any(p in HIGH_BLAST_LIBRARIES for p in extracted["affected_packages"])

    reboot_reasons = []
    for p in extracted["affected_packages"]:
        if package_execution_domain(p) == "BOOT_TIME":
            reboot_reasons.append(f"Package '{p}' affects the BOOT_TIME execution domain.")
    
    extracted["reboot_rationale"] = reboot_reasons if reboot_reasons else ["No boot-time components detected."]

    # 4. Final Assessment
    print("[*] Running LLM Blast Radius Assessment...")
    # The LLM will now see exactly which services are 'hot' in the live_audit_signal
    report = llm_assess(extracted)

    # 5. Persist the assessment as a CSV record
    reports_dir = "reports"
    os.makedirs(reports_dir, exist_ok=True)

    csv_path = os.path.join(reports_dir, "sre_reports.csv")
    file_exists = os.path.exists(csv_path)
    needs_header = not file_exists or os.path.getsize(csv_path) == 0

    advisory_id = extracted.get("advisory_id", rhsa_id)
    title = extracted.get("title", "")
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
                "advisory_id",
                "title",
                "severity",
                "impact_level",
                "reboot_required",
                "service_requires_restart",
                "restart_services",
                "summary",
                "technical_justification",
            ])
        writer.writerow([
            advisory_id,
            title,
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
    rhsa = input("Enter RHSA (e.g., RHSA-2023:1673): ").strip()
    print(json.dumps(analyze_patch(rhsa), indent=2))
