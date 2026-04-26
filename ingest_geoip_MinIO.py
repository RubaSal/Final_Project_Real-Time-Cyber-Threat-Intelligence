import os
import json
import time
from io import BytesIO
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv
from minio import Minio
from minio.error import S3Error

load_dotenv()

# ---------- GEOIP API ----------
GEOIP_API_KEY = os.getenv("GEOIP_API_KEY")
GEOIP_URL = "https://api.ipgeolocation.io/v3/ipgeo"
REQUEST_SLEEP_SECONDS = float(os.getenv("GEOIP_REQUEST_SLEEP_SECONDS", "0.5"))

MAX_IPS = int(os.getenv("MAX_IPS", "100"))
UPDATE_EXISTING = os.getenv("UPDATE_EXISTING", "false").lower() == "true"

# ---------- MinIO ----------
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY") or os.getenv("MINIO_ROOT_USER")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY") or os.getenv("MINIO_ROOT_PASSWORD")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "cyber-threat-intelligence")

ABUSE_PREFIX = os.getenv("ABUSE_MINIO_PREFIX", "raw/abuseipdb/")
GEO_PREFIX = os.getenv("GEO_MINIO_PREFIX", "raw/geoip/")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def get_minio_client() -> Minio:
    return Minio(
        MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=MINIO_SECURE,
    )


def ensure_bucket_exists(client: Minio, bucket_name: str) -> None:
    if not client.bucket_exists(bucket_name):
        client.make_bucket(bucket_name)
        print(f"Created bucket: {bucket_name}")


def get_latest_object_name(client: Minio, bucket_name: str, prefix: str) -> str | None:
    latest_obj = None

    for obj in client.list_objects(bucket_name, prefix=prefix, recursive=True):
        if obj.is_dir:
            continue
        if latest_obj is None or obj.last_modified > latest_obj.last_modified:
            latest_obj = obj

    return latest_obj.object_name if latest_obj else None


def load_json_from_minio(client: Minio, bucket_name: str, object_name: str):
    response = client.get_object(bucket_name, object_name)
    try:
        raw_bytes = response.read()
        return json.loads(raw_bytes.decode("utf-8"))
    finally:
        response.close()
        response.release_conn()


def extract_ips_from_abuseipdb_payload(content, max_ips=100):
    if isinstance(content, dict) and isinstance(content.get("data"), list):
        records = content["data"]
    elif isinstance(content, list):
        records = content
    else:
        records = []

    records = [r for r in records if r.get("ipAddress")]
    records = sorted(records, key=lambda x: x.get("lastReportedAt", ""), reverse=True)

    if max_ips is not None:
        records = records[:max_ips]

    return [r["ipAddress"] for r in records]


def load_existing_geoip_records_from_payload(content):
    if isinstance(content, dict) and isinstance(content.get("data"), list):
        return content["data"]

    if isinstance(content, list):
        return content

    return []


def safe_geoip_lookup(ip, api_key, timeout=30, max_retries=3):
    for attempt in range(max_retries):
        try:
            response = requests.get(
                GEOIP_URL,
                params={"apiKey": api_key, "ip": ip},
                timeout=timeout
            )

            if response.status_code == 429:
                wait_time = 2 ** attempt
                print(f"Rate limit hit for {ip}. Waiting {wait_time} seconds...")
                time.sleep(wait_time)
                continue

            response.raise_for_status()
            return response.json()

        except requests.exceptions.ReadTimeout:
            return {"ip": ip, "error": "ReadTimeout"}
        except requests.exceptions.HTTPError as e:
            return {"ip": ip, "error": f"HTTPError: {str(e)}"}
        except requests.exceptions.RequestException as e:
            return {"ip": ip, "error": f"RequestException: {str(e)}"}

    return {"ip": ip, "error": "HTTPError: 429 Too Many Requests"}


def fetch_geoip_for_ip(ip, ingestion_time, api_key):
    geoip_data = safe_geoip_lookup(ip, api_key, timeout=30)

    if geoip_data.get("error"):
        return {
            "ip": ip,
            "status": geoip_data["error"],
            "continent_name": None,
            "country_code2": None,
            "country_name": None,
            "state_prov": None,
            "city": None,
            "latitude": None,
            "longitude": None,
            "is_eu": None,
            "asn_number": None,
            "asn_organization": None,
            "asn_country": None,
            "timezone_name": None,
            "timezone_offset": None,
            "first_ingestion_time": ingestion_time,
            "last_ingestion_time": ingestion_time,
            "seen_count": 1
        }

    location = geoip_data.get("location", {})
    asn = geoip_data.get("asn", {})
    time_zone = geoip_data.get("time_zone", {})

    return {
        "ip": geoip_data.get("ip", ip),
        "status": "ok",
        "continent_name": location.get("continent_name"),
        "country_code2": location.get("country_code2"),
        "country_name": location.get("country_name"),
        "state_prov": location.get("state_prov"),
        "city": location.get("city"),
        "latitude": location.get("latitude"),
        "longitude": location.get("longitude"),
        "is_eu": location.get("is_eu"),
        "asn_number": asn.get("as_number"),
        "asn_organization": asn.get("organization"),
        "asn_country": asn.get("country"),
        "timezone_name": time_zone.get("name"),
        "timezone_offset": time_zone.get("offset"),
        "first_ingestion_time": ingestion_time,
        "last_ingestion_time": ingestion_time,
        "seen_count": 1
    }


def build_output_payload(records_index, ingestion_time, source_object):
    return {
        "source": "geoip_enrichment",
        "source_abuse_object": source_object,
        "last_ingestion_time": ingestion_time,
        "record_count": len(records_index),
        "data": list(records_index.values())
    }


def build_partitioned_object_name(ingestion_dt: datetime) -> str:
    year = ingestion_dt.strftime("%Y")
    month = ingestion_dt.strftime("%m")
    day = ingestion_dt.strftime("%d")
    timestamp = ingestion_dt.strftime("%Y%m%d_%H%M%S")

    return f"raw/geoip/year={year}/month={month}/day={day}/geoip_raw_{timestamp}.json"


def upload_payload_to_minio(client: Minio, payload: dict, object_name: str) -> None:
    body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")

    client.put_object(
        bucket_name=MINIO_BUCKET,
        object_name=object_name,
        data=BytesIO(body),
        length=len(body),
        content_type="application/json"
    )


def main():
    if not GEOIP_API_KEY:
        raise SystemExit("Please set GEOIP_API_KEY")

    minio_client = get_minio_client()
    ensure_bucket_exists(minio_client, MINIO_BUCKET)

    # latest AbuseIPDB raw from MinIO
    latest_abuse_object = get_latest_object_name(minio_client, MINIO_BUCKET, ABUSE_PREFIX)
    if not latest_abuse_object:
        raise SystemExit(f"No AbuseIPDB raw file found in MinIO under prefix: {ABUSE_PREFIX}")

    abuse_payload = load_json_from_minio(minio_client, MINIO_BUCKET, latest_abuse_object)
    source_ips = extract_ips_from_abuseipdb_payload(abuse_payload, MAX_IPS)

    if not source_ips:
        raise SystemExit(f"No IPs found in latest AbuseIPDB raw object: {latest_abuse_object}")

    # latest GeoIP raw from MinIO (optional)
    latest_geo_object = get_latest_object_name(minio_client, MINIO_BUCKET, GEO_PREFIX)
    existing_records = []
    if latest_geo_object:
        geo_payload = load_json_from_minio(minio_client, MINIO_BUCKET, latest_geo_object)
        existing_records = load_existing_geoip_records_from_payload(geo_payload)

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

    ingestion_dt = utc_now()
    ingestion_time = ingestion_dt.isoformat()

    new_count = 0
    updated_count = 0

    if candidate_ips:
        print(f"Starting GeoIP enrichment for {len(candidate_ips)} IPs...")

        for i, ip in enumerate(candidate_ips, start=1):
            print(f"[{i}/{len(candidate_ips)}] Fetching GEOIP for {ip}")
            fresh_record = fetch_geoip_for_ip(ip, ingestion_time, GEOIP_API_KEY)

            if ip in records_index and UPDATE_EXISTING:
                old_record = records_index[ip]
                fresh_record["first_ingestion_time"] = old_record.get("first_ingestion_time", ingestion_time)
                fresh_record["seen_count"] = old_record.get("seen_count", 1) + 1
                records_index[ip] = fresh_record
                updated_count += 1
            else:
                records_index[ip] = fresh_record
                new_count += 1

            if i < len(candidate_ips) and REQUEST_SLEEP_SECONDS > 0:
                time.sleep(REQUEST_SLEEP_SECONDS)

    else:
        print("No new IPs to fetch from GeoIP.")

    final_payload = build_output_payload(records_index, ingestion_time, latest_abuse_object)
    final_object_name = build_partitioned_object_name(ingestion_dt)
    upload_payload_to_minio(minio_client, final_payload, final_object_name)

    print(f"Source AbuseIPDB object: {latest_abuse_object}")
    print(f"Previous GeoIP object: {latest_geo_object}")
    print(f"Uploaded final raw payload to MinIO: {final_object_name}")
    print(f"Total unique records in snapshot: {len(records_index)}")
    print(f"New: {new_count} | Updated: {updated_count} | Skipped existing: {skipped_count}")


if __name__ == "__main__":
    try:
        main()
    except S3Error as e:
        print(f"MinIO error: {e}")
        raise
    except Exception as e:
        print(f"Unexpected error: {e}")
        raise