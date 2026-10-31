import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path 
import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DATA_DIR = Path("data")

def getWithRetry(url, params, retries=5, timeout=120):
    for attempt in range(1, retries + 1):
        try:
            r = requests.get(url, params=params, timeout=timeout)
            r.raise_for_status()
            return r
        except (requests.exceptions.Timeout, requests.exceptions.HTTPError) as e:
            print(f"Attempt {attempt}/{retries} failed: {e}")
            if attempt == retries:
                raise
            time.sleep(10 * attempt)

def fetchRecentCves(days):
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=days)
    fmt = "%Y-%m-%dT%H:%M:%S.000"

    allCves = []
    startIndex = 0
    pageSize = 100

    while True:
        params = {
            "lastModStartDate": start.strftime(fmt),
            "lastModEndDate": end.strftime(fmt),
            "resultsPerPage": pageSize,
            "startIndex": startIndex,
        }
        r = getWithRetry(NVD_URL, params)
        data = r.json()

        allCves.extend(data["vulnerabilities"])
        total = data["totalResults"]
        print(f"NVM fetched {len(allCves)} | {total}")

        startIndex += pageSize
        if startIndex >= total:
            break
        time.sleep(6)

    return allCves

def fetchKev():
    r = requests.get(KEV_URL,timeout=60)
    r.raise_for_status()
    return r.json()["vulnerabilities"]

if __name__ == "__main__":
    DATA_DIR.mkdir(exist_ok=True)

    nvdFile = DATA_DIR / "rawNVD.json"
    kevFile = DATA_DIR / "rawKEV.json"

    # NVD: reuse the saved file if it exists
    if nvdFile.exists():
        print("Using saved NVD data (delete the file to re-download)")
        cves = json.loads(nvdFile.read_text(encoding="utf-8"))
    else:
        cves = fetchRecentCves(days=7)
        nvdFile.write_text(json.dumps(cves), encoding="utf-8")

    # KEV: same idea
    if kevFile.exists():
        print("Using saved KEV data (delete the file to re-download)")
        kev = json.loads(kevFile.read_text(encoding="utf-8"))
    else:
        kev = fetchKev()
        kevFile.write_text(json.dumps(kev), encoding="utf-8")

    print(f"\nLoaded {len(cves)} CVEs and {len(kev)} KEV entries.")

    # Look at one CVE to understand the structure
    print(json.dumps(cves[0], indent=2))