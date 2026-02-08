import requests
import subprocess
import tempfile
import shutil
import sys
from datetime import datetime
from typing import List, Optional

OSV_API = "https://api.osv.dev/v1/vulns"


# -----------------------------
# OSV helpers
# -----------------------------

def fetch_osv(cve_id: str) -> dict:
    url = f"{OSV_API}/{cve_id}"
    r = requests.get(url, timeout=15)

    if r.status_code == 404:
        print("CVE not found in OSV")
        sys.exit(0)

    r.raise_for_status()
    return r.json()

import re

def clean_repo_url(url: str) -> str:
    """
    Truncates a URL like https://github.com/user/repo/blob/file to 
    https://github.com/user/repo
    """
    # This regex looks for the standard GitHub/GitLab pattern: site.com/user/repo
    match = re.match(r"(https?://(?:github|gitlab)\.com/[^/]+/[^/]+)", url)
    if match:
        return match.group(1).rstrip("/")
    return url

def extract_upstream_repo(osv: dict) -> str:
    # 1. Priority: Check 'affected' ranges for a GIT repo field
    # This is the "Golden Source" in OSV data.
    for affected in osv.get("affected", []):
        for r in affected.get("ranges", []):
            if r.get("type") == "GIT" and r.get("repo"):
                return clean_repo_url(r["repo"])

    # 2. Secondary: Look for an explicit 'REPOSITORY' reference
    for ref in osv.get("references", []):
        if ref.get("type") == "REPOSITORY":
            return clean_repo_url(ref["url"])

    # 3. Fallback: Find any GitHub/GitLab link, but clean it
    for ref in osv.get("references", []):
        url = ref.get("url", "")
        if "github.com" in url or "gitlab.com" in url:
            # Filter out common "noise" links if possible
            if not any(x in url for x in ["/issues", "/pull/", "/security/advisories"]):
                return clean_repo_url(url)

    raise RuntimeError("Unable to determine upstream repository accurately")

def extract_git_ranges_for_repo(osv: dict, repo_url: str) -> List[dict]:
    matches = []

    for affected in osv.get("affected", []):
        for r in affected.get("ranges", []):
            if r.get("type") == "GIT" and r.get("repo") == repo_url:
                matches.append(r)

    return matches


def extract_semver_ranges(osv: dict) -> List[dict]:
    ranges = []

    for affected in osv.get("affected", []):
        for r in affected.get("ranges", []):
            if r.get("type") == "SEMVER":
                ranges.append(r)

    return ranges


# -----------------------------
# Git helpers
# -----------------------------

def run_git(args, cwd=None) -> str:
    r = subprocess.run(
        ["git"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    )
    return r.stdout.strip()


def tag_commit_date(repo_dir: str, tag: str) -> datetime:
    iso = run_git(["log", "-1", "--format=%cI", tag], repo_dir)
    return datetime.fromisoformat(iso)


def tag_contains(repo_dir: str, tag: str, commit: str) -> bool:
    try:
        subprocess.run(
            ["git", "merge-base", "--is-ancestor", commit, tag],
            cwd=repo_dir,
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except subprocess.CalledProcessError:
        return False


# -----------------------------
# Analysis
# -----------------------------

def blobless_clone(repo_url: str) -> str:
    temp_dir = tempfile.mkdtemp(prefix="osv_git_")
    run_git(
        [
            "clone",
            "--quiet",
            "--filter=blob:none",
            "--no-checkout",
            "--tags",
            repo_url,
            temp_dir,
        ]
    )
    return temp_dir


def analyze_by_commits(repo_url: str, intro: str, fix: str):
    repo_dir = blobless_clone(repo_url)
    try:
        tags = run_git(["tag"], repo_dir).splitlines()

        tag_data = []
        for tag in tags:
            try:
                date = tag_commit_date(repo_dir, tag)
                tag_data.append((tag, date))
            except Exception:
                pass

        tag_data.sort(key=lambda x: x[1])

        vulnerable = []
        fixed = []

        for tag, date in tag_data:
            if tag_contains(repo_dir, tag, intro) and not tag_contains(repo_dir, tag, fix):
                vulnerable.append((tag, date))
            elif tag_contains(repo_dir, tag, fix):
                fixed.append((tag, date))

        print("\n=== Vulnerable Tags ===")
        for t, d in vulnerable:
            print(f"{t} | {d.date()}")

        print("\n=== Fixed Tags ===")
        for t, d in fixed[:5]:
            print(f"{t} | {d.date()}")

        if fixed:
            print(f"\nFirst fixed release: {fixed[0][0]}")

    finally:
        shutil.rmtree(repo_dir, ignore_errors=True)


def analyze_by_semver(repo_url: str, fixed_versions: List[str]):
    repo_dir = blobless_clone(repo_url)
    try:
        tags = run_git(["tag"], repo_dir).splitlines()
        tag_dates = []

        for tag in tags:
            try:
                tag_dates.append((tag, tag_commit_date(repo_dir, tag)))
            except Exception:
                pass

        tag_dates.sort(key=lambda x: x[1])

        print("\nFixed versions from OSV:")
        for v in fixed_versions:
            print(f" - {v}")

        print("\nTags matching fixed versions:")
        for tag, date in tag_dates:
            for v in fixed_versions:
                if v in tag:
                    print(f"{tag} | {date.date()}")

    finally:
        shutil.rmtree(repo_dir, ignore_errors=True)


# -----------------------------
# Main
# -----------------------------

def main():
    if len(sys.argv) != 2:
        print("Usage: python osv_git.py CVE-YYYY-NNNN")
        sys.exit(1)

    cve = sys.argv[1].upper()
    print(f"Fetching {cve} from OSV...")

    osv = fetch_osv(cve)
    repo = extract_upstream_repo(osv)

    print(f"Upstream repository: {repo}")

    git_ranges = extract_git_ranges_for_repo(osv, repo)

    if git_ranges:
        r = git_ranges[0]
        intro = next(e["introduced"] for e in r["events"] if "introduced" in e)
        fix = next(e["fixed"] for e in r["events"] if "fixed" in e)

        print("\nUsing GIT range from OSV")
        print(f"Introduced: {intro}")
        print(f"Fixed:      {fix}")

        analyze_by_commits(repo, intro, fix)
        return

    semver_ranges = extract_semver_ranges(osv)
    if not semver_ranges:
        raise RuntimeError("No usable GIT or SEMVER ranges found")

    fixed_versions = []
    for r in semver_ranges:
        for e in r["events"]:
            if "fixed" in e:
                fixed_versions.append(e["fixed"])

    print("\nNo upstream GIT ranges found — using SEMVER fallback")
    analyze_by_semver(repo, fixed_versions)


if __name__ == "__main__":
    main()
