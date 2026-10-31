import json
import os
import smtplib
from email.message import EmailMessage
from pathlib import Path

DATA_DIR = Path("data")
SENT_FILE = DATA_DIR / "sent.json"

SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ["SMTP_USER"]
SMTP_PASSWORD = os.environ["SMTP_PASSWORD"]


def buildEmail(item):
    msg = EmailMessage()
    msg["From"] = SMTP_USER
    msg["To"] = item["to"]
    msg["Subject"] = item["subject"]
    msg.set_content(Path(item["textFile"]).read_text(encoding="utf-8"))
    msg.add_alternative(Path(item["htmlFile"]).read_text(encoding="utf-8"), subtype="html")
    return msg


if __name__ == "__main__":
    outbox = json.loads((DATA_DIR / "outbox.json").read_text(encoding="utf-8"))
    sent = json.loads(SENT_FILE.read_text(encoding="utf-8")) if SENT_FILE.exists() else {}

    if not outbox:
        print("Nothing to send.")
        raise SystemExit

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)

        for item in outbox:
            try:
                server.send_message(buildEmail(item))
            except Exception as e:
                print(f'FAILED  {item["clientId"]}: {e}')
                continue

            sent.setdefault(item["clientId"], []).extend(item["cveIds"])
            SENT_FILE.write_text(json.dumps(sent, indent=2), encoding="utf-8")
            print(f'SENT    {item["clientId"]} -> {item["to"]} ({len(item["cveIds"])} CVEs)')