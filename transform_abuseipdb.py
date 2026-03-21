import json
from datetime import datetime

# load raw data from file
with open("abuseipdb_raw.json", "r", encoding="utf-8") as f:
    data = json.load(f)

raw_records = data.get("data", [])
ingestion_time = datetime.utcnow().isoformat()

processed_records = []

for record in raw_records:
    processed_record = {
        "ip_address": record.get("ipAddress"),
        "country_code": record.get("countryCode"),
        "abuse_confidence_score": record.get("abuseConfidenceScore"),
        "last_reported_at": record.get("lastReportedAt"),
        "ingestion_time": ingestion_time
    }
    processed_records.append(processed_record)

with open("abuseipdb_processed.json", "w", encoding="utf-8") as f:
    json.dump(processed_records, f, indent=2)

print("Saved processed data to abuseipdb_processed.json")
print(processed_records[:5])