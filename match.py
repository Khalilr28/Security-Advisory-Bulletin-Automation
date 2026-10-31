import json
import re
from collections import defaultdict
from pathlib import Path

DATA_DIR = Path("data")

RANGE_KEYS = (
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEndIncluding",
    "versionEndExcluding",
)


def toTuple(version):
    return tuple(int(n) for n in re.findall(r"\d+", version))


def compare(a, b):
    """Return -1 if a < b, 0 if equal, 1 if a > b."""
    ta, tb = toTuple(a), toTuple(b)
    size = max(len(ta), len(tb))
    ta += (0,) * (size - len(ta))
    tb += (0,) * (size - len(tb))
    return (ta > tb) - (ta < tb)


def versionMatch(assetVersion, entry):
    """Return the match type, or None if the asset is not affected."""
    if any(k in entry for k in RANGE_KEYS):
        if "versionStartIncluding" in entry and compare(assetVersion, entry["versionStartIncluding"]) < 0:
            return None
        if "versionStartExcluding" in entry and compare(assetVersion, entry["versionStartExcluding"]) <= 0:
            return None
        if "versionEndIncluding" in entry and compare(assetVersion, entry["versionEndIncluding"]) > 0:
            return None
        if "versionEndExcluding" in entry and compare(assetVersion, entry["versionEndExcluding"]) >= 0:
            return None
        return "range"

    cpeVersion = entry["version"]
    if cpeVersion == "*":
        return "all-versions"
    if cpeVersion == "-":
        return "unspecified"
    if compare(assetVersion, cpeVersion) == 0:
        return "exact"
    return None


def buildIndex(cves):
    """Map (vendor, product) -> list of (cve, entry)."""
    index = defaultdict(list)
    for cve in cves:
        for entry in cve["affected"]:
            index[(entry["vendor"], entry["product"])].append((cve, entry))
    return index


def matchClient(client, index):
    results = {}
    for asset in client["assets"]:
        key = (asset["vendor"], asset["product"])
        for cve, entry in index.get(key, []):
            matchType = versionMatch(asset["version"], entry)
            if matchType is None or cve["id"] in results:
                continue
            results[cve["id"]] = {
                "cveId": cve["id"],
                "asset": f'{asset["vendor"]}:{asset["product"]} {asset["version"]}',
                "matchType": matchType,
                "cvssScore": cve["cvssScore"],
                "severity": cve["severity"],
                "exploited": cve["exploited"],
                "kevDateAdded": cve["kevDateAdded"],
                "published": cve["published"],
                "description": cve["description"],
                "patchLinks": cve["patchLinks"],
            }
    return list(results.values())


if __name__ == "__main__":
    cves = json.loads((DATA_DIR / "normalized.json").read_text(encoding="utf-8"))
    inventory = json.loads(Path("inventory.json").read_text(encoding="utf-8"))

    index = buildIndex(cves)
    allMatches = {}

    for client in inventory["clients"]:
        matches = matchClient(client, index)
        matches.sort(key=lambda m: (m["exploited"], m["cvssScore"] or 0), reverse=True)
        allMatches[client["id"]] = matches

        print(f'\n{client["name"]}: {len(matches)} matching CVEs')
        for m in matches[:5]:
            flag = "EXPLOITED" if m["exploited"] else "         "
            print(f'  {flag} {m["cveId"]}  {m["cvssScore"]}  {m["matchType"]:<12} {m["asset"]}  ({m["published"][:10]})')

    (DATA_DIR / "matches.json").write_text(json.dumps(allMatches, indent=2), encoding="utf-8")