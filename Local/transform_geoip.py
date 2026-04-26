import json
from datetime import datetime, timezone
import pandas as pd

INPUT_FILE = "geoip_raw.json"
JSON_OUTPUT_FILE = "geoip_processed.json"
PARQUET_OUTPUT_FILE = "geoip_processed.parquet"


def to_float(value):
    try:
        return float(value) if value is not None else None
    except (ValueError, TypeError):
        return None


with open(INPUT_FILE, "r", encoding="utf-8") as f:
    raw_data = json.load(f)

records = raw_data.get("data", [])

processed_records = []
processing_time = datetime.now(timezone.utc).isoformat()

for record in records:
    location = record.get("location", {})
    asn = record.get("asn", {})
    time_zone = record.get("time_zone", {})

    processed_record = {
        "ip_address": record.get("ip"),
        "geo_continent_name": location.get("continent_name"),
        "geo_country_code2": location.get("country_code2"),
        "geo_country_name": location.get("country_name"),
        "geo_state_province": location.get("state_prov"),
        "geo_city": location.get("city"),
        "geo_latitude": to_float(location.get("latitude")),
        "geo_longitude": to_float(location.get("longitude")),
        "geo_is_eu": location.get("is_eu"),
        "geo_asn_number": asn.get("as_number"),
        "geo_asn_organization": asn.get("organization"),
        "geo_asn_country": asn.get("country"),
        "geo_timezone_name": time_zone.get("name"),
        "geo_timezone_offset": time_zone.get("offset"),
        "processed_at": processing_time
    }

    processed_records.append(processed_record)

output_payload = {
    "source": "geoip_processed",
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