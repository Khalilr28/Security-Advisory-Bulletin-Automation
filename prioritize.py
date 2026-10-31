import json
from datetime import datetime, timedelta
from pathlib import Path

DATA_DIR = Path("data")
SENT_FILE = DATA_DIR / "sent.json"
WINDOW_DAYS = 30
ORDER = {"URGENT": 0, "CRITICAL": 1, "HIGH": 2, "LOW": 3}


def parseDate(text):
    return datetime.fromisoformat(text[:10])  # keep YYYY-MM-DD only


def isNew(m, cutoff):
    if parseDate(m["published"]) >= cutoff:
        return True
    kev = m.get("kevDateAdded")
    return bool(kev) and parseDate(kev) >= cutoff


def getPriority(m):
    score = m["cvssScore"] or 0
    if m["exploited"]:
        return "URGENT"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    return "LOW"


if __name__ == "__main__":
    matches = json.loads((DATA_DIR / "matches.json").read_text(encoding="utf-8"))
    sent = json.loads(SENT_FILE.read_text(encoding="utf-8")) if SENT_FILE.exists() else {}
    cutoff = datetime.now() - timedelta(days=WINDOW_DAYS)

    selected = {}
    for clientId, items in matches.items():
        alreadySent = set(sent.get(clientId, []))
        keep = []
        for m in items:
            if m["cveId"] in alreadySent:
                continue
            priority = getPriority(m)
            if priority == "LOW":
                continue
            if not (isNew(m, cutoff) or m["exploited"]):
                continue
            m["priority"] = priority
            keep.append(m)

        keep.sort(key=lambda m: (ORDER[m["priority"]], -(m["cvssScore"] or 0)))
        selected[clientId] = keep

        print(f"\n{clientId}: {len(items)} matched -> {len(keep)} for the bulletin")
        for m in keep:
            print(f'  {m["priority"]:<9} {m["cveId"]}  {m["cvssScore"]}  {m["asset"]}')

    (DATA_DIR / "selected.json").write_text(json.dumps(selected, indent=2), encoding="utf-8")