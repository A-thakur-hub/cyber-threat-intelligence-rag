import requests
import json
import os
from datetime import datetime, timedelta
from tqdm import tqdm

OUTPUT_PATH = os.path.join("data", "cve", "cve_data.jsonl")
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = None  # Optional: Register on NVD for higher rate limits

def get_headers():
    return {"apiKey": API_KEY} if API_KEY else {}

def fetch_cves(start_date: str, end_date: str, max_pages: int = 3):
    all_cves = []
    params = {
        "pubStartDate": start_date + "T00:00:00.000Z",
        "pubEndDate": end_date + "T23:59:59.999Z",
        "resultsPerPage": 200,
    }

    for start_index in tqdm(range(0, max_pages * 200, 200)):
        params["startIndex"] = start_index
        response = requests.get(BASE_URL, params=params, headers=get_headers())
        if response.status_code != 200:
            print(f"Error {response.status_code}: {response.text}")
            break

        data = response.json()
        cves = data.get("vulnerabilities", [])
        for item in cves:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "")
            description = (
                cve.get("descriptions", [{}])[0].get("value", "No description")
            )
            published = cve.get("published", "")
            severity = (
                cve.get("metrics", {}).get("cvssMetricV31", [{}])[0]
                .get("cvssData", {})
                .get("baseSeverity", "UNKNOWN")
            )
            all_cves.append(
                {
                    "cve_id": cve_id,
                    "description": description,
                    "published": published,
                    "severity": severity,
                    "source": "NVD",
                }
            )

    return all_cves


def save_to_jsonl(records, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")
    print(f"✅ Saved {len(records)} CVEs to {path}")


if __name__ == "__main__":
    today = datetime.utcnow()
    week_ago = today - timedelta(days=30)

    start = week_ago.strftime("%Y-%m-%d")
    end = today.strftime("%Y-%m-%d")

    print(f"Fetching CVEs from {start} to {end}...")
    cve_data = fetch_cves(start, end, max_pages=5)  # ~1000 CVEs
    save_to_jsonl(cve_data, OUTPUT_PATH)
