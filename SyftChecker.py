import json
import subprocess
import sys
import tempfile
from collections import defaultdict
from pathlib import Path


def generate_sbom(scan_path: str, output_file: Path):
    print(f"[+] Generating SBOM for: {scan_path}")
    cmd = ["syft", f"dir:{scan_path}", "-o", "cyclonedx-json"]
    with open(output_file, "w") as f:
        subprocess.run(cmd, stdout=f, check=True)


def build_reverse_deps(sbom_data):
    reverse_deps = defaultdict(list)

    for dep in sbom_data.get("dependencies", []):
        source = dep.get("ref")
        for target in dep.get("dependsOn", []):
            reverse_deps[target].append(source)

    return reverse_deps


def normalize_name(purl: str):
    # Extract readable package name from purl
    # Example: pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
    try:
        name_part = purl.split("/")[-1]
        return name_part.split("@")[0].lower()
    except Exception:
        return purl.lower()


def find_reverse_dependencies(reverse_map, target_name):
    print(f"\n[+] Searching for packages depending on: {target_name}\n")
    found = False

    for pkg, parents in reverse_map.items():
        if target_name in normalize_name(pkg):
            found = True
            print(f"{pkg}")
            for p in parents:
                print(f"  └── required by: {p}")
            print()

    if not found:
        print("No reverse dependencies found.")


def main():
    if len(sys.argv) != 3:
        print("Usage: python syft_reverse_deps.py <scan_path> <package_name>")
        sys.exit(1)

    scan_path = sys.argv[1]
    target_package = sys.argv[2].lower()

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        sbom_path = Path(tmp.name)

    try:
        generate_sbom(scan_path, sbom_path)

        with open(sbom_path) as f:
            sbom_data = json.load(f)

        reverse_map = build_reverse_deps(sbom_data)
        find_reverse_dependencies(reverse_map, target_package)

    finally:
        sbom_path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
