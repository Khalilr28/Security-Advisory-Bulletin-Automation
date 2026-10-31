import json
from datetime import date
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

DATA_DIR = Path("data")
OUT_DIR = Path("bulletins")

ACTIONS = {
    "URGENT": "Actively exploited in the wild. Apply the vendor fix immediately. "
              "If you cannot patch today, apply the vendor's mitigations and review logs for signs of compromise.",
    "CRITICAL": "Apply the vendor fix as soon as possible, ideally within 7 days.",
    "HIGH": "Schedule the vendor fix in your next patch cycle, within 30 days.",
}


def cleanDescription(text, limit=300):
    text = text.replace("<insert attack vector here>", "an unspecified vector")
    text = " ".join(text.split())  # collapse newlines and odd spaces
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0].rstrip(" .,;:") + "…"

def safeLinks(links):
    return [l for l in links if l.startswith(("http://", "https://"))]


if __name__ == "__main__":
    OUT_DIR.mkdir(exist_ok=True)
    selected = json.loads((DATA_DIR / "selected.json").read_text(encoding="utf-8"))
    inventory = json.loads(Path("inventory.json").read_text(encoding="utf-8"))
    clients = {c["id"]: c for c in inventory["clients"]}

    env = Environment(
        loader=FileSystemLoader("templates"),
        autoescape=select_autoescape(["html"]),
    )
    today = date.today().isoformat()
    outbox = []

    for clientId, items in selected.items():
        if not items:
            print(f"{clientId}: nothing new, no bulletin")
            continue

        client = clients[clientId]
        for m in items:
            m["shortDescription"] = cleanDescription(m["description"])
            m["action"] = ACTIONS[m["priority"]]
            m["confirmed"] = m["matchType"] in ("exact", "range")
            m["patchLinks"] = safeLinks(m["patchLinks"])
            product = m["asset"].split(":")[1].split(" ")[0]          # e.g. "pan-os"
            norm = lambda s: s.lower().replace("-", "").replace("_", "")
            m["indirect"] = norm(product) not in norm(m["description"])

        urgentCount = sum(1 for m in items if m["priority"] == "URGENT")
        context = {
            "clientName": client["name"],
            "today": today,
            "items": items,
            "urgentCount": urgentCount,
        }

        htmlFile = OUT_DIR / f"{clientId}.html"
        textFile = OUT_DIR / f"{clientId}.txt"
        htmlFile.write_text(env.get_template("bulletin.html").render(**context), encoding="utf-8")
        textFile.write_text(env.get_template("bulletin.txt").render(**context), encoding="utf-8")

        prefix = "[URGENT] " if urgentCount else ""
        subject = f"{prefix}Security advisory: {len(items)} item(s) affecting your environment ({today})"
        outbox.append({
            "clientId": clientId,
            "to": client["contactEmail"],
            "subject": subject,
            "htmlFile": str(htmlFile),
            "textFile": str(textFile),
            "cveIds": [m["cveId"] for m in items],
        })
        print(f"{clientId}: bulletin with {len(items)} item(s) -> {htmlFile}")

    (DATA_DIR / "outbox.json").write_text(json.dumps(outbox, indent=2), encoding="utf-8")