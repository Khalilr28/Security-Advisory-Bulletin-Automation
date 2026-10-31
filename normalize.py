import json
from pathlib import Path

DATA_DIR = Path("data")

RANGE_KEYS = (
    "versionStartIncluding",
    "versionStartExcluding",
    "versionEndIncluding",
    "versionEndExcluding",
)


def getDescription(cve):
    for d in cve.get("descriptions", []):
        if d["lang"] == "en":
            return d["value"]
    return ""


def getCvss(metrics):
    """Return (score, severity), preferring the newest CVSS version."""
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            m = metrics[key][0]
            data = m["cvssData"]
            severity = data.get("baseSeverity") or m.get("baseSeverity")
            return data.get("baseScore"), severity
    return None, None


def parseCpe(criteria):
    parts = criteria.split(":")
    return parts[3], parts[4], parts[5]  # vendor, product, version


def getAffectedProducts(cve):
    products = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                vendor, product, version = parseCpe(match["criteria"])
                entry = {"vendor": vendor, "product": product, "version": version}
                for key in RANGE_KEYS:
                    if key in match:
                        entry[key] = match[key]
                products.append(entry)
    return products


def getPatchLinks(cve):
    links = []
    for ref in cve.get("references", []):
        tags = ref.get("tags", [])
        if "Patch" in tags or "Vendor Advisory" in tags:
            if ref["url"] not in links:
                links.append(ref["url"])
    return links


def normalize(vuln, kevById):
    cve = vuln["cve"]
    score, severity = getCvss(cve.get("metrics", {}))
    kevEntry = kevById.get(cve["id"])
    return {
        "id": cve["id"],
        "description": getDescription(cve),
        "published": cve["published"],
        "lastModified": cve["lastModified"],
        "cvssScore": score,
        "severity": severity,
        "affected": getAffectedProducts(cve),
        "patchLinks": getPatchLinks(cve),
        "exploited": kevEntry is not None,
        "kevDateAdded": kevEntry["dateAdded"] if kevEntry else None,
        "kevAction": kevEntry["requiredAction"] if kevEntry else None,
    }


if __name__ == "__main__":
    rawNvd = json.loads((DATA_DIR / "rawNVD.json").read_text(encoding="utf-8"))
    rawKev = json.loads((DATA_DIR / "rawKEV.json").read_text(encoding="utf-8"))

    kevById = {k["cveID"]: k for k in rawKev}
    normalized = [normalize(v, kevById) for v in rawNvd]

    (DATA_DIR / "normalized.json").write_text(
        json.dumps(normalized, indent=2), encoding="utf-8"
    )

    withProducts = [c for c in normalized if c["affected"]]
    exploited = [c for c in normalized if c["exploited"]]
    print(f"Total CVEs:                {len(normalized)}")
    print(f"With affected products:    {len(withProducts)}")
    print(f"Actively exploited (KEV):  {len(exploited)}")

    first = next(c for c in normalized if c["id"] == "CVE-2006-2073")
    first["affected"] = first["affected"][:2]  # shortened for display
    print(json.dumps(first, indent=2))