import os
import subprocess
import re

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

def package_execution_domain(pkg):
    try:
        files = subprocess.check_output(["rpm", "-ql", pkg], stderr=subprocess.DEVNULL).decode().splitlines()
        if any(f.startswith(BOOT_PATH_PREFIXES) for f in files): return "BOOT_TIME"
    except: pass
    return "USERSPACE"

def advisory_requires_reboot(packages):
    return any(package_execution_domain(p) == "BOOT_TIME" for p in packages)

def extract_restart_services(live_radius):
    services = set()
    for tier in ("direct_exec", "shared_dependency"):
        for ident in live_radius.get(tier, {}):
            if ident.endswith(".service"): services.add(ident)
    return sorted(services)

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