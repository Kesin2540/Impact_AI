from SyftChecker import (
    generate_sbom,
    build_reverse_deps,
    find_reverse_dependencies
)

def classify_fanout(avg: float) -> str:
    if avg > 80:
        return "VERY_HIGH"
    elif avg > 20:
        return "HIGH"
    elif avg > 5:
        return "MODERATE"
    return "LOW"


def analyze_reverse_deps_for_osv(scan_path: str, osv_impact: dict):
    sbom = generate_sbom(scan_path)
    reverse_map = build_reverse_deps(sbom)

    results = {}
    counts = []

    for ecosystem, pkgs in osv_impact["affected_packages"].items():
        for pkg in pkgs:
            name = pkg["package"].lower()

            deps = find_reverse_dependencies(reverse_map, name)
            count = len(deps)
            counts.append(count)

            results.setdefault(ecosystem, []).append({
                "package": name,
                "reverse_dependencies": deps,
                "count": count
            })

    avg = sum(counts) / len(counts) if counts else 0

    return {
        "average_reverse_deps": round(avg, 1),
        "fanout_level": classify_fanout(avg),
        "by_package": results
    }
