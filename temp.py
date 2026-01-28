#!/usr/bin/env python3
"""
Enterprise RHEL Patch Impact Engine (v2.0)
- Deep CSAF Parsing: Extracting packages from the full Product Tree.
- Context-Heavy LLM Prompting: Passing raw technical notes for reasoning.
- Operational Risk Mapping: Identifying breaking changes via keyword analysis.
"""

import json
from posixpath import basename
import urllib.request
import re
import ollama
import subprocess
import os

# -----------------------------
# Configuration
# -----------------------------

RH_CSAF_URL = "https://access.redhat.com/hydra/rest/securitydata/csaf/{}.json"

# Core libraries that, if updated, affect almost every process on the system
HIGH_BLAST_LIBRARIES = {"glibc", "openssl", "systemd", "kernel", "dbus", "krb5"}

BOOT_PATH_PREFIXES = (
    "/boot/",
    "/lib/modules/",
    "/usr/lib/modules/",
    "/lib/firmware/",
    "/usr/lib/firmware/",
    "/usr/lib/microcode/",
    "/usr/lib/dracut/",
    "/usr/lib/kernel/",
    "/usr/lib/initramfs/",
)


SYSTEM_PROMPT = """
You are a Senior Site Reliability Engineer (SRE) specializing in Linux Platform Security.
Your task is to analyze a RHEL Security Advisory (RHSA) and produce a precise, operational
Blast Radius Assessment suitable for change management and patch planning.

You will be given authoritative runtime and dependency signals. Treat these signals as
ground truth. Do not speculate beyond the provided data.

### AUTHORITATIVE RULES (DO NOT OVERRIDE):
- service_requires_restart MUST exactly match RESTART_REQUIRED_SIGNAL.
- restart_services MUST exactly match RESTART_SERVICES_SIGNAL.
- A required service restart does NOT imply high impact by itself.
- A reboot is required ONLY for boot-time components that cannot be replaced at runtime (e.g., kernel, kernel modules, firmware).
- If Reboot Required is true, the impact level MUST NOT be LOW or LOW-MODERATE.
- Do not downgrade boot-time updates due to lack of running services.
- If a Minimum Impact Level is provided, impact_level MUST be at least that level.

### IMPACT LEVEL DETERMINATION (CRITICAL):
Impact level must be based primarily on operational scope and disruption,

Use the following rubric:

LOW:
- No running services affected OR no restart required.

LOW-MODERATE:
- Restart required for a single non-critical application service.
- No reverse dependency fanout.
- No configuration changes implied.

MODERATE:
- Restart required for one or two application services.
- No reboot required.
- No core system libraries involved.

MODERATE-HIGH:
- Multiple services affected OR
- High reverse dependency fanout OR
- Elevated configuration or compatibility risk.

HIGH:
- Reboot required OR
- Core system libraries involved OR
- System-wide impact affecting many services.

### ASSESSMENT DIMENSIONS:
1. OPERATIONAL RISK:
   Likelihood of configuration or behavior changes after applying the patch.
2. SERVICE IMPACT:
   Which running services are affected and why a restart is required.
3. BLAST RADIUS:
   Whether impact is isolated (single application) or system-wide.
4. REGRESSION RISK:
   Likelihood of functional regressions based on fix type and scope.

### RESPONSE GUIDANCE:
- The summary must be concise and operationally focused.
- The technical_justification must explain WHY the impact level was chosen,
  referencing runtime signals and dependency scope.
- Do NOT restate the vulnerability description unless it directly affects operations.
- Do NOT escalate impact level solely due to security severity.

### AUTHORITATIVE RULES:
1. IF Reboot Required is TRUE: Set impact to MODERATE-HIGH or HIGH.
2. IF Reboot Required is FALSE: You MUST strictly follow the rubric below. Do NOT escalate based on security severity (e.g., "Important" or "Critical").
3. A Minimum Impact Level of 'null' or 'NONE' means the rubric is the only authority.
4. If exactly one or two services need a restart and Reboot Required is False, the impact is MODERATE.

EXECUTION DOMAINS:
1. USERSPACE DOMAIN: Includes standard applications and libraries. Impact is calculated via PIDs and service restarts.
2. BOOT_TIME DOMAIN: Includes the Kernel, Kernel Modules (kmod), Firmware, Microcode, and Bootloaders. 
   - These components do NOT have PIDs and cannot be restarted via systemd.
   - If 'Reboot Required' is TRUE, it means a BOOT_TIME component is being patched.
   - For BOOT_TIME updates, you MUST set "reboot_required": true and the minimum "impact_level": "MODERATE-HIGH", regardless of whether the PID audit is empty.
3. NEVER downgrade a BOOT_TIME impact because of a lack of running services.

### OUTPUT FORMAT:
Return a JSON object with exactly these keys:
- "impact_level": one of LOW, LOW-MODERATE, MODERATE, MODERATE-HIGH, HIGH
- "summary"
- "technical_justification"
- "reboot_required": boolean
- "service_requires_restart": boolean
- "restart_services": list
"""

# -----------------------------
# Pre-emptive Audit Logic
# -----------------------------

def get_live_signal_assessment(package_list):
    """
    Live Runtime Radius Assessment
    Finds running processes connected to the patch and classifies the connection strength.
    """
    radius = {
        "direct_exec": {},       
        "shared_dependency": {}, 
        "package_component": {}  
    }

    # 1. Build a lookup set of "interesting" file paths from the package
    target_files = {}

    for pkg in package_list:
        try:
            # Get full paths of files in the package
            files = subprocess.check_output(
                ["rpm", "-ql", pkg], stderr=subprocess.DEVNULL
            ).decode().splitlines()
            
            for f_path in files:
                # Skip directories and documentation
                if f_path.endswith("/"): continue
                if "/share/doc/" in f_path or "/share/man/" in f_path: continue
                
                # Classify Tier
                if f_path.startswith(("/usr/bin/", "/usr/sbin/", "/usr/libexec/")):
                    tier = "direct_exec"
                elif ".so" in f_path or "/lib" in f_path:
                    tier = "shared_dependency"
                else:
                    tier = "package_component"
                
                target_files[f_path] = tier

        except Exception:
            continue

    if not target_files:
        return radius

    # 2. Walk the Process Table
    for pid in os.listdir("/proc"):
        if not pid.isdigit(): continue

        try:

            try:
                proc_name = subprocess.check_output(
                    ["ps", "-p", pid, "-o", "comm="], stderr=subprocess.DEVNULL
                ).decode().strip()
            except Exception:
                proc_name = "unknown"

            # Read memory maps
            with open(f"/proc/{pid}/maps", "r") as maps:
                matched_tier = None

                for line in maps:
                    parts = line.strip().split()
                    if len(parts) < 6:
                        continue

                    perms = parts[1]
                    mapped_path = parts[-1]

                    # Only executable code matters
                    if "x" not in perms:
                        continue

                    # Handle deleted binaries
                    if mapped_path.endswith(" (deleted)"):
                        mapped_path = mapped_path[:-10]

                    tier = target_files.get(mapped_path)
                    if not tier:
                        continue

                    # Validate actual execution for direct_exec
                    exe_name = os.path.basename(mapped_path)
                    if tier == "direct_exec" and proc_name != exe_name:
                        continue

                    if tier == "direct_exec":
                        matched_tier = "direct_exec"
                        break
                    elif not matched_tier:
                        matched_tier = tier
            if not matched_tier:
                continue

            # 4. Identify the Owner (Service or Process Name)
            unit = ""
            try:
                with open(f"/proc/{pid}/cgroup", "r") as cg:
                    # Broad regex to catch user.slice, system.slice, etc.
                    content = cg.read()
                    match = re.search(r'([a-zA-Z0-9\-\_\.]+\.service)', content)
                    if match:
                        unit = match.group(1)
            except Exception:
                pass

            # 5. Format the Identifier
            # If it's a service, use the Unit Name. If it's a manual process, use the binary name.
            identifier = unit if unit else f"Process: {proc_name}"

            # Add to results
            radius[matched_tier].setdefault(identifier, set()).add(pid)

        except (PermissionError, FileNotFoundError):
            continue

    # 6. Final Formatting (Sets -> Lists)
    final_output = {}
    for tier, items in radius.items():
        final_output[tier] = {k: list(v) for k, v in items.items()}

    return final_output

def package_execution_domain(pkg):
    try:
        files = subprocess.check_output(
            ["rpm", "-ql", pkg],
            stderr=subprocess.DEVNULL
        ).decode().splitlines()
    except Exception:
        return "UNKNOWN"

    for f in files:
        if f.startswith(BOOT_PATH_PREFIXES):
            return "BOOT_TIME"

    return "USERSPACE"


def get_service_context(package_list):
    """
    Checks if services matching the package names are enabled or active.
    """
    context = {}
    for pkg in package_list:
        # Many RHEL services share the package name (e.g., httpd, sshd)
        unit_name = f"{pkg}.service"
        
        try:
            # Query specific properties from systemd
            cmd = ["systemctl", "show", unit_name, "--property=ActiveState,UnitFileState"]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
            
            # Parse output like 'ActiveState=active' into a dictionary
            props = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
            
            # We only care if it's active or enabled
            if props.get("ActiveState") != "inactive" or props.get("UnitFileState") == "enabled":
                context[unit_name] = {
                    "active": props.get("ActiveState"),
                    "enabled": props.get("UnitFileState")
                }
        except Exception:
            # Service likely doesn't exist for this package, skip it
            continue
            
    return context

# -----------------------------
# CSAF Data Fetching & Extraction
# -----------------------------

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
    
def reverse_dependencies(pkg, limit=200):
    """
    Returns a list of packages that depend on `pkg`
    Uses repoquery (RPM-level reverse deps)
    """
    try:
        cmd = [
            "repoquery",
            "--installed",
            "--whatrequires", pkg,
            "--qf", "%{name}"
        ]
        out = subprocess.check_output(
            cmd,
            stderr=subprocess.DEVNULL,
            timeout=10
        ).decode()

        deps = sorted(set(out.splitlines()))
        return deps[:limit]
    except Exception:
        return []

def get_running_affected_processes(package_list):
    """
    Checks if any running process is currently using files from the affected packages.
    """
    affected_pids = {}
    
    for pkg in package_list:
        try:
            # 1. Get list of files owned by the package
            files_cmd = ["rpm", "-ql", pkg]
            pkg_files = subprocess.check_output(files_cmd, stderr=subprocess.DEVNULL).decode().splitlines()
            
            # 2. Use lsof to see if any process is using these files
            # We filter for processes mapped to these files
            for file_path in pkg_files:
                if not file_path.strip(): continue
                try:
                    # 'lsof -t' returns just the PIDs using a file
                    lsof_out = subprocess.check_output(["lsof", "-t", file_path], stderr=subprocess.DEVNULL).decode()
                    pids = lsof_out.strip().split('\n')
                    for pid in pids:
                        if pid:
                            # Get process name for better LLM context
                            ps_name = subprocess.check_output(["ps", "-p", pid, "-o", "comm="]).decode().strip()
                            affected_pids[pid] = ps_name
                except subprocess.CalledProcessError:
                    continue # No one using this specific file
        except Exception:
            continue

    return affected_pids
    
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
    dep_map = {}
    total = 0

    for p in packages:
        deps = reverse_dependencies(p)
        dep_map[p] = {
            "count": len(deps),
            "examples": deps[:10]
        }
        total += len(deps)

    avg = total / len(packages) if packages else 0

    if avg > 80:
        fanout_level = "VERY_HIGH"
    elif 21 < avg and avg < 80:
        fanout_level = "HIGH"
    elif 5 < avg and avg < 20:
        fanout_level = "MODERATE"
    else:
        fanout_level = "LOW"

    return {
        "reverse_dependency_summary": dep_map,
        "average_reverse_deps": round(avg, 1),
        "fanout_level": fanout_level
    }

def compute_restart_requirement(live_radius):
    return bool(
        live_radius.get("direct_exec") or
        live_radius.get("shared_dependency")
    )

def extract_restart_services(live_radius):
    services = set()
    for tier in ("direct_exec", "shared_dependency"):
        for ident in live_radius.get(tier, {}):
            if ident.endswith(".service"):
                services.add(ident)
    return sorted(services)

def advisory_requires_reboot(packages):
    return any(
        package_execution_domain(p) == "BOOT_TIME"
        for p in packages
    )


# -----------------------------
# LLM Reasoning
# -----------------------------

def llm_assess(data):
    """Feeds the technical context + Live Surgical Signal to Ollama for reasoning"""
    
    # 1. Format the new Surgical Signal (Live Audit)
    # This shows exactly which services/PIDs are "touching" the vulnerable files right now
    live_signal_str = json.dumps(data.get('live_audit_signal', {}), indent=2)

    service_status_str = json.dumps(data.get('system_service_status', {}), indent=2)
    
    # 2. Format the dependency data
    rev_deps_summary = f"Avg Deps: {data.get('average_reverse_deps', 0)}, Fanout: {data.get('fanout_level', 'LOW')}"

    rationale_str = ", ".join(data.get('reboot_rationale', ["No boot-time components detected."]))

    # 3. Build the refined prompt
    prompt_content = (
        f"### ADVISORY METADATA\n"
        f"ID: {data['advisory_id']} - Severity: {data['severity']}\n"
        f"Core System Impact (Kernel/Glibc/etc): {data.get('is_core_impact', False)}\n\n"

        f"### EXECUTION DOMAIN SIGNAL (CRITICAL)\n"
        f"- Reboot Required: {data.get('reboot_required_signal', False)}\n"
        f"- Execution Domain Rationale: {rationale_str}\n"
        f"Note: Boot-time components affect the system foundation and require a full power-cycle/reboot.\n\n"
        
        f"### REVERSE DEPENDENCY ANALYSIS\n"
        f"{rev_deps_summary}\n\n"
        
        f"### LIVE SYSTEM SURGICAL AUDIT\n"
        f"{live_signal_str}\n\n"

        f"### MANDATORY CONSTRAINTS\n"
        f"1. ONLY apply the 'Reboot Required' high-impact rule if 'Reboot Required' is actually TRUE.\n"
        f"2. Since 'Reboot Required' is {data.get('reboot_required_signal')}, you must choose the level based on the service restart count.\n"
        f"3. Do NOT use the Security Severity ('Important') to determine the Impact Level.\n"
        
        f"### TECHNICAL DETAILS\n"
        f"{data['technical_details']}\n"

        f"### SYSTEM SERVICE STATUS\n"
        f"{service_status_str}\n"

        f"### RESTART DETERMINATION (AUTHORITATIVE)\n"
        f"Restart Required: {data['restart_required_signal']}\n\n"

        f"### EXECUTION DOMAIN SIGNAL\n"
        f"Reboot Required: {data.get('reboot_required_signal', False)}\n\n"

        f"### IMPACT POLICY OVERRIDE\n"
        f"Minimum Impact Level: {data.get('minimum_impact_level') if data.get('minimum_impact_level') else 'NONE (Follow Rubric Only)'}\n"
    )

    # 4. Call the LLM with JSON format enforced
    response = ollama.chat(
        model="qwen2.5:3b",
        format="json",
        options={"temperature": 0.5}, 
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt_content}
        ]
    )
    
    return json.loads(response["message"]["content"])
    

# -----------------------------
# Main Runner
# -----------------------------

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

    # 4. Final Assessment
    print("[*] Running LLM Blast Radius Assessment...")
    # The LLM will now see exactly which services are 'hot' in the live_audit_signal
    report = llm_assess(extracted)
    
    return {
        "metadata": extracted,
        "assessment": report
    }

if __name__ == "__main__":
    rhsa = input("Enter RHSA ID (e.g., RHSA-2023:1673): ").strip()
    result = analyze_patch(rhsa)
    print("\n" + "="*50)
    print(f"IMPACT REPORT: {rhsa}")
    print("="*50)
    print(json.dumps(result, indent=2))