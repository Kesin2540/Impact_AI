import os
import re
from pathlib import Path
from collections import defaultdict
from typing import Set, Dict

SYFT_BIN = "/usr/local/bin/syft"  # adjust if needed

# -----------------------------
# Runtime inspection helpers
# -----------------------------
def map_pid_to_service(pid: str):
    try:
        with open(f"/proc/{pid}/cgroup") as f:
            data = f.read()
        m = re.search(r'([a-zA-Z0-9_.-]+\.service)', data)
        return m.group(1) if m else None
    except Exception:
        return None


def scan_live_impact(target_files: Set[str]) -> Dict[str, Dict[str, list]]:
    """
    Scan /proc to find running processes executing or mapping target files.
    """
    impact = {
        "direct_exec": defaultdict(set),
        "shared_dependency": defaultdict(set),
    }

    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue

        try:
            with open(f"/proc/{pid}/maps") as maps:
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
                    identifier = service or f"Process:{pid}"

                    impact[tier][identifier].add(pid)

        except (PermissionError, FileNotFoundError):
            continue

    # normalize sets → lists
    return {
        tier: {ident: sorted(pids) for ident, pids in items.items()}
        for tier, items in impact.items()
    }
