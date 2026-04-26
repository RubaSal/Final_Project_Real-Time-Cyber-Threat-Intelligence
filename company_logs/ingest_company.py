import json
import random
import uuid
from datetime import datetime, timedelta, timezone

OUTPUT_FILE = "company_logs_raw.json"

CUSTOMER_IDS = ["cust_001", "cust_002", "cust_003"]
USERNAMES = [
    "dana.levi",
    "itay.cohen",
    "maya.salem",
    "noa.benari",
    "omer.katz",
    "lior.haddad",
    "yael.oren"
]
APPLICATIONS = ["VPN", "Okta", "Office365", "AWS Console", "Internal Portal"]
EVENT_TYPES = [
    "login_success",
    "login_failed",
    "mfa_challenge",
    "password_reset",
    "admin_console_access",
    "vpn_connect"
]
DEVICE_TYPES = ["Windows Laptop", "MacBook", "Linux Workstation", "Mobile"]
STATUSES = ["success", "failure"]
GEO_HINTS = ["Israel", "Germany", "United States", "Netherlands", "Unknown"]


def random_public_ip():
    """
    Generate a random public IPv4 address.
    Avoid obvious private/reserved ranges.
    """
    while True:
        a = random.randint(1, 223)
        b = random.randint(0, 255)
        c = random.randint(0, 255)
        d = random.randint(1, 254)

        # Skip private / loopback / link-local / multicast-ish blocks
        if a == 10:
            continue
        if a == 127:
            continue
        if a == 169 and b == 254:
            continue
        if a == 172 and 16 <= b <= 31:
            continue
        if a == 192 and b == 168:
            continue
        if a >= 224:
            continue

        return f"{a}.{b}.{c}.{d}"


def generate_company_logs(num_records=100):
    now = datetime.now(timezone.utc)
    records = []

    repeated_ips = [random_public_ip() for _ in range(5)]

    for _ in range(num_records):
        event_time = now - timedelta(
            hours=random.randint(0, 72),
            minutes=random.randint(0, 59),
            seconds=random.randint(0, 59)
        )

        event_type = random.choice(EVENT_TYPES)

        if event_type == "login_failed":
            status = "failure"
        else:
            status = random.choices(
                population=STATUSES,
                weights=[85, 15],
                k=1
            )[0]

        ip_choice_pool = repeated_ips + [random_public_ip() for _ in range(3)]
        source_ip = random.choice(ip_choice_pool)

        record = {
            "log_id": str(uuid.uuid4()),
            "customer_id": random.choice(CUSTOMER_IDS),
            "event_time": event_time.isoformat(),
            "username": random.choice(USERNAMES),
            "source_ip": source_ip,
            "event_type": event_type,
            "application": random.choice(APPLICATIONS),
            "device_type": random.choice(DEVICE_TYPES),
            "status": status,
            "geo_hint": random.choice(GEO_HINTS),
            "ingestion_time": now.isoformat()
        }

        records.append(record)

    return records


def main():
    records = generate_company_logs(num_records=100)

    payload = {
        "source": "synthetic_company_logs",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "record_count": len(records),
        "data": records
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)

    print(f"Saved {len(records)} records to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()