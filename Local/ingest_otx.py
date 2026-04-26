import os
import json
import ipaddress
import requests
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("OTX_API_KEY")

ABUSE_FILE = "abuseipdb_raw.json"
OUTPUT_FILE = "otx_raw.json"

BASE_URL = "https://otx.alienvault.com/api/v1"

TOP_N = 100
MAX_WORKERS = 5
SAVE_EVERY = 10
UPDATE_EXISTING = False  # אם תרצי לרענן גם IPs שכבר קיימים, תשני ל-True


def load_json_file(file_path, default):
    if not os.path.exists(file_path):
        return default

    with open(file_path, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return default


def extract_top_newest_ips_from_abuseipdb(file_path, top_n=100):
    content = load_json_file(file_path, {})

    if isinstance(content, dict) and isinstance(content.get("data"), list):
        records = content["data"]
    elif isinstance(content, list):
        records = content
    else:
        records = []

    records = [r for r in records if r.get("ipAddress")]
    records = sorted(
        records,
        key=lambda x: x.get("lastReportedAt", ""),
        reverse=True
    )

    top_records = records[:top_n]
    return [r["ipAddress"] for r in top_records]


def load_existing_otx_records(file_path):
    content = load_json_file(file_path, {})

    if isinstance(content, dict) and isinstance(content.get("data"), list):
        return content["data"]

    if isinstance(content, list):
        return content

    return []


def get_ip_version_path(ip):
    ip_obj = ipaddress.ip_address(ip)
    return "IPv4" if ip_obj.version == 4 else "IPv6"


def safe_get_json(session, path, timeout=30):
    try:
        response = session.get(f"{BASE_URL}{path}", timeout=timeout)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ReadTimeout:
        return {"error": "ReadTimeout"}
    except requests.exceptions.HTTPError as e:
        return {"error": f"HTTPError: {str(e)}"}
    except requests.exceptions.RequestException as e:
        return {"error": f"RequestException: {str(e)}"}


def fetch_otx_for_ip(ip, ingestion_time, api_key):
    try:
        version_path = get_ip_version_path(ip)
    except ValueError:
        return {
            "ip": ip,
            "otx_reputation": None,
            "pulse_count": 0,
            "pulse_names": [],
            "passive_dns_count": 0,
            "general_status": "Invalid IP",
            "passive_dns_status": "Invalid IP",
            "first_ingestion_time": ingestion_time,
            "last_ingestion_time": ingestion_time,
            "seen_count": 1
        }

    session = requests.Session()
    session.headers.update({
        "X-OTX-API-KEY": api_key,
        "Accept": "application/json",
    })

    general = safe_get_json(
        session,
        f"/indicators/{version_path}/{ip}/general",
        timeout=30
    )
    passive_dns = safe_get_json(
        session,
        f"/indicators/{version_path}/{ip}/passive_dns",
        timeout=60
    )

    pulses = []
    if isinstance(general, dict):
        pulses = general.get("pulse_info", {}).get("pulses", [])

    passive_dns_records = []
    if isinstance(passive_dns, dict):
        passive_dns_records = passive_dns.get("passive_dns", [])

    return {
        "ip": ip,
        "otx_reputation": general.get("reputation") if isinstance(general, dict) else None,
        "pulse_count": len(pulses),
        "pulse_names": [p.get("name") for p in pulses[:10] if p.get("name")],
        "passive_dns_count": len(passive_dns_records),
        "general_status": general.get("error", "ok") if isinstance(general, dict) else "unknown",
        "passive_dns_status": passive_dns.get("error", "ok") if isinstance(passive_dns, dict) else "unknown",
        "first_ingestion_time": ingestion_time,
        "last_ingestion_time": ingestion_time,
        "seen_count": 1
    }


def save_otx_records(file_path, records_index, ingestion_time):
    output_payload = {
        "source": "otx_enrichment",
        "last_ingestion_time": ingestion_time,
        "record_count": len(records_index),
        "data": list(records_index.values())
    }

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(output_payload, f, ensure_ascii=False, indent=2)


if not API_KEY:
    raise SystemExit("Please set OTX_API_KEY")

source_ips = extract_top_newest_ips_from_abuseipdb(ABUSE_FILE, TOP_N)
if not source_ips:
    raise SystemExit(f"No IPs found in {ABUSE_FILE}")

existing_records = load_existing_otx_records(OUTPUT_FILE)
records_index = {}

for record in existing_records:
    ip = record.get("ip")
    if ip:
        records_index[ip] = record

candidate_ips = []
skipped_count = 0

for ip in source_ips:
    if ip in records_index and not UPDATE_EXISTING:
        skipped_count += 1
    else:
        candidate_ips.append(ip)

ingestion_time = datetime.now(timezone.utc).isoformat()

new_count = 0
updated_count = 0
processed_count = 0

if candidate_ips:
    print(f"Starting OTX enrichment for {len(candidate_ips)} IPs with {MAX_WORKERS} workers...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_ip = {
            executor.submit(fetch_otx_for_ip, ip, ingestion_time, API_KEY): ip
            for ip in candidate_ips
        }

        for future in as_completed(future_to_ip):
            ip = future_to_ip[future]

            try:
                fresh_record = future.result()
            except Exception as e:
                fresh_record = {
                    "ip": ip,
                    "otx_reputation": None,
                    "pulse_count": 0,
                    "pulse_names": [],
                    "passive_dns_count": 0,
                    "general_status": f"Unhandled exception: {str(e)}",
                    "passive_dns_status": f"Unhandled exception: {str(e)}",
                    "first_ingestion_time": ingestion_time,
                    "last_ingestion_time": ingestion_time,
                    "seen_count": 1
                }

            if ip in records_index and UPDATE_EXISTING:
                old_record = records_index[ip]
                fresh_record["first_ingestion_time"] = old_record.get("first_ingestion_time", ingestion_time)
                fresh_record["seen_count"] = old_record.get("seen_count", 1) + 1
                records_index[ip] = fresh_record
                updated_count += 1
            else:
                records_index[ip] = fresh_record
                new_count += 1

            processed_count += 1
            print(f"[{processed_count}/{len(candidate_ips)}] Processed IP: {ip}")

            if processed_count % SAVE_EVERY == 0:
                save_otx_records(OUTPUT_FILE, records_index, ingestion_time)
                print(f"Checkpoint saved after {processed_count} processed IPs")

else:
    print("No new IPs to fetch from OTX.")

save_otx_records(OUTPUT_FILE, records_index, ingestion_time)

print(f"Saved {len(records_index)} unique IP records to {OUTPUT_FILE}")
print(f"New: {new_count} | Updated: {updated_count} | Skipped existing: {skipped_count}")