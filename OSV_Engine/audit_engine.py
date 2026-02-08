import os
import re
import subprocess
import json
import tempfile
from pathlib import Path
from collections import defaultdict
from SyftChecker import generate_sbom, normalize_name
from live_impact import scan_live_impact

HIGH_BLAST_LIBRARIES = {"glibc", "openssl", "systemd", "kernel", "dbus", "krb5", "node", "python", "npm", "pip"}

# For OSV, we need to scan the system to find installed packages
# This is different from RPM-based systems
DEFAULT_SCAN_PATH = "/"  # Can be configured to scan specific directories

def get_installed_packages_from_sbom(scan_path: str = DEFAULT_SCAN_PATH):
    """Generate SBOM and extract installed packages from CycloneDX format"""
    try:
        sbom = generate_sbom(scan_path)
        packages = {}
        
        # Extract packages from CycloneDX SBOM
        for component in sbom.get("components", []):
            name = component.get("name", "").lower()
            purl = component.get("purl", "")
            ecosystem = ""
            
            # Extract ecosystem from purl (e.g., pkg:npm/package@version)
            if purl:
                try:
                    # Format: pkg:ecosystem/name@version
                    if purl.startswith("pkg:"):
                        purl_part = purl[4:]  # Remove "pkg:"
                        parts = purl_part.split("/")
                        if len(parts) > 0:
                            ecosystem = parts[0].split("@")[0]
                except Exception:
                    pass
            
            # Extract locations from CycloneDX format
            locations = []
            for loc in component.get("locations", []):
                path = loc.get("path")
                if path:
                    locations.append(path)
            
            packages[name] = {
                "name": name,
                "version": component.get("version", ""),
                "ecosystem": ecosystem,
                "purl": purl,
                "locations": locations
            }
        
        return packages, sbom
    except Exception as e:
        print(f"Error generating SBOM: {e}")
        return {}, None

def is_package_live(package_name: str, ecosystem: str, scan_path: str = DEFAULT_SCAN_PATH):
    """Check if a package is installed/live on the system"""
    packages, sbom = get_installed_packages_from_sbom(scan_path)
    
    # Normalize package name for matching
    target_name = package_name.lower()
    
    # Check if package exists in installed packages
    for pkg_name, pkg_info in packages.items():
        if target_name in pkg_name or pkg_name in target_name:
            # Also check ecosystem match if provided
            if ecosystem and pkg_info.get("ecosystem"):
                if ecosystem.lower() not in pkg_info.get("ecosystem", "").lower():
                    continue
            return True, pkg_info
    
    return False, None

def get_service_context(package_list, scan_path: str = DEFAULT_SCAN_PATH):
    """
    Checks if services matching the package names are enabled or active.
    For OSV packages, this is less relevant but we check systemd services.
    """
    context = {}
    for pkg_info in package_list:
        pkg_name = pkg_info.get("name", "") if isinstance(pkg_info, dict) else str(pkg_info)
        unit_name = f"{pkg_name}.service"
        
        try:
            cmd = ["systemctl", "show", unit_name, "--property=ActiveState,UnitFileState"]
            out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL).decode()
            
            props = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
            
            if props.get("ActiveState") != "inactive" or props.get("UnitFileState") == "enabled":
                context[unit_name] = {
                    "active": props.get("ActiveState"),
                    "enabled": props.get("UnitFileState")
                }
        except Exception:
            continue
            
    return context

def find_target_files_from_sbom(sbom: dict, target_name: str):
    """
    Locate filesystem paths belonging to a package in the CycloneDX SBOM.
    """
    target_files = set()
    target = target_name.lower()
    
    # CycloneDX format uses "components"
    for component in sbom.get("components", []):
        name = component.get("name", "").lower()
        if target not in name and name not in target:
            continue
        
        # Extract file paths from locations
        for loc in component.get("locations", []):
            path = loc.get("path")
            if path:
                target_files.add(path)
    
    return target_files

def get_live_signal_assessment(package_list, scan_path: str = DEFAULT_SCAN_PATH):
    """
    Live Runtime Radius Assessment for OSV packages
    Finds running processes connected to the patch and classifies the connection strength.
    """
    radius = {
        "direct_exec": {},
        "shared_dependency": {},
        "package_component": {}
    }
    
    # Generate SBOM to find package files
    try:
        sbom = generate_sbom(scan_path)
    except Exception as e:
        print(f"Error generating SBOM for live assessment: {e}")
        return radius
    
    # Build target files from all packages in the list
    target_files = set()
    target_files_by_tier = {}
    
    for pkg_info in package_list:
        if isinstance(pkg_info, dict):
            pkg_name = pkg_info.get("name", "")
            ecosystem = pkg_info.get("ecosystem", "")
        else:
            pkg_name = str(pkg_info)
            ecosystem = ""
        
        # Find files for this package from CycloneDX SBOM
        files = find_target_files_from_sbom(sbom, pkg_name)
        
        for f_path in files:
            if not f_path:
                continue
            
            # Skip directories and documentation
            if "/share/doc/" in f_path or "/share/man/" in f_path:
                continue
            
            # Classify tier
            if f_path.startswith(("/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/bin/", "/sbin/")):
                tier = "direct_exec"
            elif ".so" in f_path or "/lib" in f_path or "/node_modules/" in f_path:
                tier = "shared_dependency"
            else:
                tier = "package_component"
            
            target_files.add(f_path)
            target_files_by_tier.setdefault(tier, set()).add(f_path)
    
    if not target_files:
        return radius
    
    # Scan live processes
    live_impact = scan_live_impact(target_files)
    
    # Merge results and format
    for tier in ["direct_exec", "shared_dependency"]:
        if tier in live_impact:
            radius[tier] = live_impact[tier]
    
    # Add package_component tier if we have files but no direct matches
    if "package_component" in target_files_by_tier:
        # Check for any processes that might be using these files
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            
            try:
                with open(f"/proc/{pid}/maps", "r") as maps:
                    for line in maps:
                        parts = line.strip().split()
                        if len(parts) < 6:
                            continue
                        
                        perms = parts[1]
                        mapped_path = parts[-1]
                        
                        if "x" not in perms and "r" not in perms:
                            continue
                        
                        if mapped_path.endswith(" (deleted)"):
                            mapped_path = mapped_path[:-10]
                        
                        if mapped_path in target_files_by_tier.get("package_component", set()):
                            service = None
                            try:
                                with open(f"/proc/{pid}/cgroup", "r") as cg:
                                    content = cg.read()
                                    match = re.search(r'([a-zA-Z0-9\-\_\.]+\.service)', content)
                                    if match:
                                        service = match.group(1)
                            except Exception:
                                pass
                            
                            identifier = service if service else f"Process:{pid}"
                            radius["package_component"].setdefault(identifier, []).append(pid)
            except (PermissionError, FileNotFoundError):
                continue
    
    return radius

def extract_restart_services(live_radius):
    """Extract service names that need restarting"""
    services = set()
    for tier in ("direct_exec", "shared_dependency"):
        for ident in live_radius.get(tier, {}):
            if ident.endswith(".service"):
                services.add(ident)
    return sorted(services)

def package_execution_domain(pkg_info, scan_path: str = DEFAULT_SCAN_PATH):
    """
    Determine execution domain for OSV packages.
    For OSV, we check if package files are in boot-time paths.
    """
    if isinstance(pkg_info, dict):
        pkg_name = pkg_info.get("name", "")
    else:
        pkg_name = str(pkg_info)
    
    try:
        sbom = generate_sbom(scan_path)
        files = find_target_files_from_sbom(sbom, pkg_name)
        
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
        
        for f_path in files:
            if any(f_path.startswith(prefix) for prefix in BOOT_PATH_PREFIXES):
                return "BOOT_TIME"
    except Exception:
        pass
    
    return "USERSPACE"

def advisory_requires_reboot(packages, scan_path: str = DEFAULT_SCAN_PATH):
    """Check if any package requires reboot (boot-time domain)"""
    return any(package_execution_domain(p, scan_path) == "BOOT_TIME" for p in packages)
