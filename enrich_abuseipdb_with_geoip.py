import os
import json
import time
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv

# =========================
# Configuration
# =========================
INPUT_FILE = "abuseipdb_processed.json"
OUTPUT_FILE = "abuseipdb_geoip_enriched.json"
ERROR_FILE = "abuseipdb_geoip_enrichment_errors.json"

GEOIP_URL = "https://api.ipgeolocation.io/v2/ipgeo"
REQUEST_DELAY_SECONDS = 1
MAX_RECORDS = None


# =========================
# Utility Functions
# =========================
def get_current_utc_time() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_geoip_api_key() -> str:
    load_dotenv()
    api_key = os.getenv("GEOIP_API_KEY")

    if not api_key:
        raise ValueError("Missing GEOIP_API_KEY in .env file")

    return api_key


def load_abuseipdb_processed_data(file_path: str) -> list:
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError(f"{file_path} must contain a list of records")

    return data


def save_json_file(data, file_path: str) -> None:
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


# =========================
# GeoIP Functions
# =========================
def fetch_geoip_data(ip_address: str, api_key: str) -> dict:
    params = {
        "apiKey": api_key,
        "ip": ip_address
    }

    response = requests.get(GEOIP_URL, params=params, timeout=30)
    response.raise_for_status()

    return response.json()


def build_enriched_record(abuse_record: dict, geo_record: dict) -> dict:
    location = geo_record.get("location", {})

    return {
        "ip_address": abuse_record.get("ip_address"),
        "abuse_country_code": abuse_record.get("country_code"),
        "abuse_confidence_score": abuse_record.get("abuse_confidence_score"),
        "last_reported_at": abuse_record.get("last_reported_at"),
        "abuse_ingestion_time": abuse_record.get("ingestion_time"),

        "geo_continent_name": location.get("continent_name"),
        "geo_country_code2": location.get("country_code2"),
        "geo_country_name": location.get("country_name"),
        "geo_state_province": location.get("state_prov"),
        "geo_city": location.get("city"),
        "geo_latitude": location.get("latitude"),
        "geo_longitude": location.get("longitude"),
        "geo_is_eu": location.get("is_eu"),

        "enrichment_time": get_current_utc_time()
    }


# =========================
# Main Enrichment Logic
# =========================
def enrich_abuseipdb_with_geoip(records: list, api_key: str) -> tuple[list, list]:
    enriched_records = []
    error_records = []
    geoip_cache = {}

    total_records = len(records)

    for index, abuse_record in enumerate(records, start=1):
        ip_address = abuse_record.get("ip_address")

        if not ip_address:
            error_records.append({
                "record_index": index,
                "ip_address": None,
                "error": "Missing ip_address in abuse record"
            })
            continue

        try:
            if ip_address not in geoip_cache:
                geoip_cache[ip_address] = fetch_geoip_data(ip_address, api_key)
                time.sleep(REQUEST_DELAY_SECONDS)

            geo_record = geoip_cache[ip_address]
            enriched_record = build_enriched_record(abuse_record, geo_record)
            enriched_records.append(enriched_record)

            print(f"[{index}/{total_records}] Enriched IP: {ip_address}")

        except requests.exceptions.RequestException as e:
            error_records.append({
                "record_index": index,
                "ip_address": ip_address,
                "error": str(e)
            })
            print(f"[{index}/{total_records}] Failed to enrich IP {ip_address}: {e}")

    return enriched_records, error_records


# =========================
# Main
# =========================
def main() -> None:
    try:
        api_key = load_geoip_api_key()
        abuse_records = load_abuseipdb_processed_data(INPUT_FILE)

        if MAX_RECORDS is not None:
            abuse_records = abuse_records[:MAX_RECORDS]

        enriched_records, error_records = enrich_abuseipdb_with_geoip(abuse_records, api_key)

        save_json_file(enriched_records, OUTPUT_FILE)
        save_json_file(error_records, ERROR_FILE)

        print("\nEnrichment completed successfully.")
        print(f"Enriched records saved to: {OUTPUT_FILE}")
        print(f"Error records saved to: {ERROR_FILE}")
        print(f"Total enriched records: {len(enriched_records)}")
        print(f"Total errors: {len(error_records)}")

    except ValueError as e:
        print(f"Configuration error: {e}")
    except FileNotFoundError as e:
        print(f"File error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")


if __name__ == "__main__":
    main()