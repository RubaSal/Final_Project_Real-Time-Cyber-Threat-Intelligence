import json
from datetime import datetime

with open("geoip_raw.json", "r", encoding="utf-8") as f:
    data = json.load(f)

ingestion_time = datetime.utcnow().isoformat() + "Z"

processed_record = {
    "ip": data.get("ip"),
    "continent_code": data.get("location", {}).get("continent_code"),
    "continent_name": data.get("location", {}).get("continent_name"),
    "country_code2": data.get("location", {}).get("country_code2"),
    "country_code3": data.get("location", {}).get("country_code3"),
    "country_name": data.get("location", {}).get("country_name"),
    "country_official_name": data.get("location", {}).get("country_name_official"),
    "country_capital": data.get("location", {}).get("country_capital"),
    "state_province": data.get("location", {}).get("state_prov"),
    "state_code": data.get("location", {}).get("state_code"),
    "district": data.get("location", {}).get("district"),
    "city": data.get("location", {}).get("city"),
    "zipcode": data.get("location", {}).get("zipcode"),
    "latitude": data.get("location", {}).get("latitude"),
    "longitude": data.get("location", {}).get("longitude"),
    "is_eu": data.get("location", {}).get("is_eu"),
    "geoname_id": data.get("location", {}).get("geoname_id"),
    "country_emoji": data.get("location", {}).get("country_emoji"),
    "calling_code": data.get("country_metadata", {}).get("calling_code"),
    "tld": data.get("country_metadata", {}).get("tld"),
    "languages": ", ".join(data.get("country_metadata", {}).get("languages", [])),
    "currency_code": data.get("currency", {}).get("code"),
    "currency_name": data.get("currency", {}).get("name"),
    "currency_symbol": data.get("currency", {}).get("symbol"),
    "ingestion_time": ingestion_time
}

with open("geoip_processed.json", "w", encoding="utf-8") as f:
    json.dump(processed_record, f, indent=2, ensure_ascii=False)

print("Saved processed data to geoip_processed.json")
print(processed_record)