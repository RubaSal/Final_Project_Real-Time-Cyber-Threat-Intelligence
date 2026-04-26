# import os
# import json
# import requests
# from dotenv import load_dotenv

# load_dotenv()

# API_KEY = os.getenv("ABUSE_API_KEY")

# url = "https://api.abuseipdb.com/api/v2/blacklist"
# headers = {
#     "Key": API_KEY,
#     "Accept": "application/json"
# }

# response = requests.get(url, headers=headers)
# data = response.json()

# with open("abuseipdb_raw.json", "w", encoding="utf-8") as f:
#     json.dump(data, f, indent=2)

# print("Saved response to abuseipdb_raw.json")

# import os
# import json
# import requests
# from datetime import datetime, timezone
# from dotenv import load_dotenv

# load_dotenv()

# API_KEY = os.getenv("ABUSE_API_KEY")
# OUTPUT_FILE = "abuseipdb_raw.json"

# url = "https://api.abuseipdb.com/api/v2/blacklist"
# headers = {
#     "Key": API_KEY,
#     "Accept": "application/json"
# }

# response = requests.get(url, headers=headers, timeout=30)
# response.raise_for_status()
# data = response.json()

# new_batch = {
#     "ingestion_time": datetime.now(timezone.utc).isoformat(),
#     "source": "abuseipdb_blacklist",
#     "data": data
# }

# if os.path.exists(OUTPUT_FILE):
#     with open(OUTPUT_FILE, "r", encoding="utf-8") as f:
#         try:
#             existing_data = json.load(f)
#         except json.JSONDecodeError:
#             existing_data = []
# else:
#     existing_data = []

# if not isinstance(existing_data, list):
#     existing_data = [existing_data]

# existing_data.append(new_batch)

# with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
#     json.dump(existing_data, f, ensure_ascii=False, indent=2)

# print(f"Appended new batch to {OUTPUT_FILE}")

import os
import json
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("ABUSE_API_KEY")
OUTPUT_FILE = "abuseipdb_raw.json"

url = "https://api.abuseipdb.com/api/v2/blacklist"
headers = {
    "Key": API_KEY,
    "Accept": "application/json"
}


def load_existing_records(file_path):
    if not os.path.exists(file_path):
        return []

    with open(file_path, "r", encoding="utf-8") as f:
        try:
            content = json.load(f)
        except json.JSONDecodeError:
            return []

    # פורמט חדש: {"source": ..., "last_ingestion_time": ..., "data": [...]}
    if isinstance(content, dict) and isinstance(content.get("data"), list):
        return content["data"]

    # פורמט ישן אפשרי: רשימה של רשומות IP
    if isinstance(content, list):
        return content

    return []


response = requests.get(url, headers=headers, timeout=30)
response.raise_for_status()
payload = response.json()

new_records = payload.get("data", [])
ingestion_time = datetime.now(timezone.utc).isoformat()

existing_records = load_existing_records(OUTPUT_FILE)

# אינדקס לפי IP
records_index = {}
for record in existing_records:
    ip = record.get("ipAddress")
    if ip:
        records_index[ip] = record

# merge / upsert
for record in new_records:
    ip = record.get("ipAddress")
    if not ip:
        continue

    if ip in records_index:
        old_record = records_index[ip]
        first_ingestion_time = old_record.get("first_ingestion_time", ingestion_time)
        seen_count = old_record.get("seen_count", 1) + 1

        updated_record = record.copy()
        updated_record["first_ingestion_time"] = first_ingestion_time
        updated_record["last_ingestion_time"] = ingestion_time
        updated_record["seen_count"] = seen_count

        records_index[ip] = updated_record
    else:
        new_entry = record.copy()
        new_entry["first_ingestion_time"] = ingestion_time
        new_entry["last_ingestion_time"] = ingestion_time
        new_entry["seen_count"] = 1

        records_index[ip] = new_entry

output_payload = {
    "source": "abuseipdb_blacklist",
    "last_ingestion_time": ingestion_time,
    "record_count": len(records_index),
    "data": list(records_index.values())
}

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(output_payload, f, ensure_ascii=False, indent=2)

print(f"Saved {len(records_index)} unique IP records to {OUTPUT_FILE}")