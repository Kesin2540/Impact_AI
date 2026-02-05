import os
import re
import json
import subprocess
import tempfile
from pathlib import Path
from collections import defaultdict

SYFT_BIN = "/usr/local/bin/syft"  # adjust if needed

def generate_sbom(scan_path, output_file):
    cmd = [SYFT_BIN, f"dir:{scan_path}", "-o", "json"]
    with open(output_file, "w") as f:
        subprocess.run(cmd, stdout=f, check=True)

def find_target_files(sbom, target_name):
    target_files = set()
    for artifact in sbom.get("artifacts", []):
        name = artifact.get("name", "").lower()
        if target_name.lower() not in name:
            continue

        for loc in artifact.get("locations", []):
            path = loc.get("path")
            if path:
                target_files.add(path)

    return target_files


def map_pid_to_service(pid):
    try:
        with open(f"/proc/{pid}/cgroup") as f:
            data = f.read()
        m = re.search(r'([a-zA-Z0-9_.-]+\.service)', data)
        return m.group(1) if m else None
    except:
        return None


def scan_live_impact(target_files):
    impact = {
        "direct_exec": defaultdict(set),
        "shared_dependency": defaultdict(set),
    }

    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue

        maps_path = f"/proc/{pid}/maps"
        try:
            with open(maps_path) as maps:
                for line in maps:
                    parts = line.strip().split()
                    if len(parts) < 6:
                        continue

                    perms = parts[1]
                    path = parts[-1]

                    if "x" not in perms:
                        continue

                    if path.endswith(" (deleted)"):
                        path = path[:-10]

                    if path not in target_files:
                        continue

                    tier = "shared_dependency" if ".so" in path else "direct_exec"

                    service = map_pid_to_service(pid)
                    identifier = service if service else f"Process:{pid}"

                    impact[tier][identifier].add(pid)

        except (PermissionError, FileNotFoundError):
            continue

    # convert sets → lists
    return {k: {i: list(p) for i, p in v.items()} for k, v in impact.items()}


def main():
    if os.geteuid() != 0:
        print("Run as root.")
        return

    if len(os.sys.argv) != 3:
        print("Usage: sudo python syft_live_impact_target.py <scan_path> <package_name>")
        return

    scan_path = os.sys.argv[1]
    target_pkg = os.sys.argv[2]

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        sbom_path = Path(tmp.name)

    try:
        print("[+] Generating SBOM...")
        generate_sbom(scan_path, sbom_path)

        with open(sbom_path) as f:
            sbom = json.load(f)

        print(f"[+] Locating files for package: {target_pkg}")
        target_files = find_target_files(sbom, target_pkg)

        if not target_files:
            print("Package not found in SBOM.")
            return

        print(f"[+] Found {len(target_files)} files. Checking runtime usage...")
        impact = scan_live_impact(target_files)

        print("\n=== LIVE IMPACT REPORT ===\n")
        if not any(impact.values()):
            print("Package is installed but NOT currently affecting running processes.")
            return

        for tier, items in impact.items():
            if not items:
                continue
            print(f"{tier.upper()}:")
            for ident, pids in items.items():
                print(f"  {ident} → PIDs {', '.join(pids)}")
            print()

    finally:
        sbom_path.unlink(missing_ok=True)

if __name__ == "__main__":
    main()