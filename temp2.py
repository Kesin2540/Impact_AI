import os
import shutil
import subprocess
import tempfile
from datetime import datetime

REPO_URL = "https://github.com/apache/logging-log4j2.git"

INTRO_COMMIT = "6b788facd3479dfe9052b3a5e13f6603dce8c16f"
FIX_COMMIT = "38513a7d57343881f7bf58f37e67d6a87e0a47c5"


def run_git(args, cwd=None):
    result = subprocess.run(
        ["git"] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True
    )
    return result.stdout.strip()


def get_tag_commit_date(repo_dir, tag):
    date_str = run_git(["log", "-1", "--format=%cI", tag], repo_dir)
    return datetime.fromisoformat(date_str)


def tag_contains(repo_dir, tag, commit):
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


def main():
    temp_dir = tempfile.mkdtemp(prefix="repo_clone_")
    print(f"Blobless cloning repo into {temp_dir} ...")

    try:
        # Blobless + tags + full history
        run_git([
            "clone",
            "--quiet",
            "--filter=blob:none",
            "--no-checkout",
            "--tags",
            REPO_URL,
            temp_dir
        ])

        tags = run_git(["tag"], temp_dir).splitlines()

        tag_data = []
        for tag in tags:
            try:
                date = get_tag_commit_date(temp_dir, tag)
                tag_data.append((tag, date))
            except Exception:
                continue

        tag_data.sort(key=lambda x: x[1])

        vulnerable_versions = []
        fixed_versions = []

        for tag, date in tag_data:
            has_intro = tag_contains(temp_dir, tag, INTRO_COMMIT)
            has_fix = tag_contains(temp_dir, tag, FIX_COMMIT)

            if has_intro and not has_fix:
                vulnerable_versions.append((tag, date))
            elif has_fix:
                fixed_versions.append((tag, date))

        print("\n=== Vulnerable Versions ===")
        for tag, date in vulnerable_versions:
            print(f"{tag}  |  {date.date()}")

        print("\n=== Fixed Versions ===")
        for tag, date in fixed_versions[:5]:
            print(f"{tag}  |  {date.date()}")

        if fixed_versions:
            print(f"\nFirst fixed release: {fixed_versions[0][0]}")

    finally:
        print("\nCleaning up...")
        shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
