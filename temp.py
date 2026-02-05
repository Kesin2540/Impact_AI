import requests
import sys
import json

def query_cve_direct(cve_id: str) -> dict:
    url = f"https://api.osv.dev/v1/vulns/{cve_id}"

    try:
        response = requests.get(url, timeout=15)

        if response.status_code == 404:
            print("CVE not found in OSV database.")
            sys.exit(0)

        response.raise_for_status()
        return response.json()

    except requests.RequestException as e:
        print(f"[!] Network or API error: {e}")
        sys.exit(1)


def main():
    if len(sys.argv) != 2:
        print("Usage: python temp.py CVE-YYYY-NNNN")
        sys.exit(1)

    cve_id = sys.argv[1].strip().upper()

    print(f"Fetching {cve_id} from OSV...")
    data = query_cve_direct(cve_id)

    print(json.dumps(data, indent=2))


if __name__ == "__main__":
    main()
