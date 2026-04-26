import json
from datetime import datetime, timezone
import pandas as pd

INPUT_FILE = "otx_raw.json"
JSON_OUTPUT_FILE = "otx_processed.json"
PARQUET_OUTPUT_FILE = "otx_processed.parquet"


def extract_reputation(record):
    if "otx_reputation" in record:
        return record.get("otx_reputation")

    general = record.get("general", {})
    if isinstance(general, dict):
        return general.get("reputation")

    return None


def extract_pulses(record):
    if "pulse_count" in record and "pulse_names" in record:
        pulse_count = record.get("pulse_count", 0)
        pulse_names = record.get("pulse_names", []) or []
        return pulse_count, pulse_names

    general = record.get("general", {})
    if isinstance(general, dict):
        pulses = general.get("pulse_info", {}).get("pulses", []) or []
        pulse_names = [p.get("name") for p in pulses[:10] if p.get("name")]
        return len(pulses), pulse_names

    return 0, []


def extract_passive_dns_count(record):
    if "passive_dns_count" in record:
        return record.get("passive_dns_count", 0)

    passive_dns = record.get("passive_dns", {})
    if isinstance(passive_dns, dict):
        return len(passive_dns.get("passive_dns", []) or [])

    return 0


def extract_general_status(record):
    if "general_status" in record:
        return record.get("general_status")

    general = record.get("general", {})
    if isinstance(general, dict):
        return general.get("error", "ok")

    return "unknown"


def extract_passive_dns_status(record):
    if "passive_dns_status" in record:
        return record.get("passive_dns_status")

    passive_dns = record.get("passive_dns", {})
    if isinstance(passive_dns, dict):
        return passive_dns.get("error", "ok")

    return "unknown"


with open(INPUT_FILE, "r", encoding="utf-8") as f:
    raw_data = json.load(f)

records = raw_data.get("data", [])

processed_records = []
processing_time = datetime.now(timezone.utc).isoformat()

for record in records:
    pulse_count, pulse_names = extract_pulses(record)

    processed_record = {
        "ip_address": record.get("ip"),
        "otx_reputation": extract_reputation(record),
        "otx_pulse_count": pulse_count,
        "otx_pulse_names": pulse_names,
        "otx_passive_dns_count": extract_passive_dns_count(record),
        "otx_general_status": extract_general_status(record),
        "otx_passive_dns_status": extract_passive_dns_status(record),
        "first_ingestion_time": record.get("first_ingestion_time"),
        "last_ingestion_time": record.get("last_ingestion_time"),
        "processed_at": processing_time
    }

    processed_records.append(processed_record)

output_payload = {
    "source": "otx_processed",
    "processed_at": processing_time,
    "record_count": len(processed_records),
    "data": processed_records
}

# Save JSON
with open(JSON_OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(output_payload, f, ensure_ascii=False, indent=2)

# Save Parquet
df = pd.DataFrame(processed_records)
df.to_parquet(PARQUET_OUTPUT_FILE, index=False, engine="pyarrow")

print(f"Saved {len(processed_records)} transformed records to {JSON_OUTPUT_FILE}")
print(f"Saved {len(processed_records)} transformed records to {PARQUET_OUTPUT_FILE}")