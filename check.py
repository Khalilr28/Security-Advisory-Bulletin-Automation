import json
from pathlib import Path

cves = json.loads(Path("data/normalized.json").read_text(encoding="utf-8"))

for vendor, product in [("microsoft", "windows_server_2019"), ("vmware", "esxi"), ("canonical", "ubuntu_linux")]:
    hits = [c for c in cves if any(a["vendor"] == vendor and a["product"] == product for a in c["affected"])]
    print(vendor, product, len(hits), "CVEs in the data")

raw = json.loads(Path("data/rawNVD.json").read_text(encoding="utf-8"))
v = next(x for x in raw if x["cve"]["id"] == "CVE-2026-109618")
print(json.dumps(v["cve"]["configurations"], indent=2)[:3000])
names = {(a["vendor"], a["product"]) for c in cves for a in c["affected"]
         if "esxi" in a["product"] or a["vendor"] in ("vmware", "broadcom")}
print(names)