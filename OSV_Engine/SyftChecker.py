import json
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path


def generate_sbom(scan_path: str) -> dict:
    """Generate a CycloneDX SBOM using syft and return parsed JSON"""
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        sbom_path = Path(tmp.name)

    try:
        cmd = ["syft", f"dir:{scan_path}", "-o", "cyclonedx-json"]
        with open(sbom_path, "w") as f:
            subprocess.run(cmd, stdout=f, check=True)

        with open(sbom_path) as f:
            return json.load(f)

    finally:
        sbom_path.unlink(missing_ok=True)


def build_reverse_deps(sbom_data: dict):
    reverse_deps = defaultdict(list)

    for dep in sbom_data.get("dependencies", []):
        source = dep.get("ref")
        for target in dep.get("dependsOn", []):
            reverse_deps[target].append(source)

    return reverse_deps


def normalize_name(purl: str) -> str:
    try:
        name_part = purl.split("/")[-1]
        return name_part.split("@")[0].lower()
    except Exception:
        return purl.lower()


def find_reverse_dependencies(reverse_map, target_name: str):
    """Return list of packages that depend on target_name"""
    results = []

    for pkg, parents in reverse_map.items():
        if target_name in normalize_name(pkg):
            results.extend(parents)

    return sorted(set(results))
