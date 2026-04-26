import os
import json
import time
import ipaddress
from io import BytesIO
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

import pandas as pd
import requests
from dotenv import load_dotenv
from minio import Minio
from minio.error import S3Error

load_dotenv()

# ---------- OTX ----------
OTX_API_KEY = os.getenv("OTX_API_KEY")
OTX_BASE_URL = os.getenv("OTX_BASE_URL", "https://otx.alienvault.com/api/v1")
REQUEST_TIMEOUT = int(os.getenv("OTX_REQUEST_TIMEOUT", "25"))
MAX_WORKERS = int(os.getenv("OTX_MAX_WORKERS", "5"))

# Optional limit for development/testing
OTX_MAX_IPS = os.getenv("OTX_MAX_IPS")
OTX_MAX_IPS = int(OTX_MAX_IPS) if OTX_MAX_IPS else None

# ---------- MinIO ----------
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY") or os.getenv("MINIO_ROOT_USER")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY") or os.getenv("MINIO_ROOT_PASSWORD")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "cyber-threat-intelligence")

ABUSE_PROCESSED_PREFIX = os.getenv("ABUSE_PROCESSED_PREFIX", "processed/abuseipdb/")
OTX_RAW_PREFIX = os.getenv("OTX_RAW_PREFIX", "raw/otx/")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def utc_now_iso() -> str:
    return utc_now().isoformat()


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
        if not obj.object_name.endswith(".parquet"):
            continue

        if latest_obj is None or obj.last_modified > latest_obj.last_modified:
            latest_obj = obj

    return latest_obj.object_name if latest_obj else None


def load_parquet_from_minio(client: Minio, bucket_name: str, object_name: str) -> pd.DataFrame:
    response = client.get_object(bucket_name, object_name)
    try:
        raw_bytes = response.read()
    finally:
        response.close()
        response.release_conn()

    df = pd.read_parquet(BytesIO(raw_bytes), engine="pyarrow")
    df = df.astype(object).where(pd.notnull(df), None)
    return df


def build_raw_object_name(run_dt: datetime) -> str:
    year = run_dt.strftime("%Y")
    month = run_dt.strftime("%m")
    day = run_dt.strftime("%d")
    timestamp = run_dt.strftime("%Y%m%d_%H%M%S")

    return (
        f"{OTX_RAW_PREFIX}"
        f"year={year}/month={month}/day={day}/"
        f"otx_raw_{timestamp}.json"
    )


def upload_json_to_minio(client: Minio, bucket_name: str, object_name: str, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    data_stream = BytesIO(body)

    client.put_object(
        bucket_name=bucket_name,
        object_name=object_name,
        data=data_stream,
        length=len(body),
        content_type="application/json"
    )


def get_ip_version_path(ip: str) -> str:
    ip_obj = ipaddress.ip_address(ip)
    return "IPv4" if ip_obj.version == 4 else "IPv6"


def otx_get(session: requests.Session, url: str, retries: int = 3) -> tuple[dict, str]:
    for attempt in range(1, retries + 1):
        try:
            response = session.get(url, timeout=REQUEST_TIMEOUT)

            if response.status_code == 429:
                if attempt < retries:
                    sleep_seconds = attempt * 2
                    time.sleep(sleep_seconds)
                    continue
                return {}, "rate_limited"

            if response.status_code == 404:
                return {}, "not_found"

            response.raise_for_status()
            return response.json(), "ok"

        except requests.RequestException:
            if attempt < retries:
                time.sleep(attempt)
                continue
            return {}, "request_failed"

    return {}, "unknown_error"


def fetch_otx_for_ip(ip: str) -> dict:
    lookup_time = utc_now_iso()

    try:
        version_path = get_ip_version_path(ip)
    except ValueError:
        return {
            "ip": ip,
            "otx_reputation": None,
            "pulse_count": 0,
            "pulse_names": [],
            "passive_dns_count": 0,
            "general_status": "invalid_ip",
            "passive_dns_status": "invalid_ip",
            "first_ingestion_time": lookup_time,
            "last_ingestion_time": lookup_time,
            "seen_count": 1
        }

    session = requests.Session()
    session.headers.update({
        "X-OTX-API-KEY": OTX_API_KEY,
        "Accept": "application/json"
    })

    general_url = f"{OTX_BASE_URL}/indicators/{version_path}/{ip}/general"
    passive_dns_url = f"{OTX_BASE_URL}/indicators/{version_path}/{ip}/passive_dns"

    general_data, general_status = otx_get(session, general_url)
    passive_dns_data, passive_dns_status = otx_get(session, passive_dns_url)

    pulses = []
    if isinstance(general_data, dict):
        pulses = general_data.get("pulse_info", {}).get("pulses", []) or []

    passive_dns_records = []
    if isinstance(passive_dns_data, dict):
        passive_dns_records = passive_dns_data.get("passive_dns", []) or []

    pulse_names = [p.get("name") for p in pulses if p.get("name")]

    return {
        "ip": ip,
        "otx_reputation": general_data.get("reputation") if isinstance(general_data, dict) else None,
        "pulse_count": len(pulses),
        "pulse_names": pulse_names,
        "passive_dns_count": len(passive_dns_records),
        "general_status": general_status,
        "passive_dns_status": passive_dns_status,
        "first_ingestion_time": lookup_time,
        "last_ingestion_time": lookup_time,
        "seen_count": 1
    }


def main():
    if not OTX_API_KEY:
        raise ValueError("Missing OTX_API_KEY in environment variables")

    run_dt = utc_now()

    print("Connecting to MinIO...")
    client = get_minio_client()
    ensure_bucket_exists(client, MINIO_BUCKET)

    latest_abuse_object = get_latest_object_name(client, MINIO_BUCKET, ABUSE_PROCESSED_PREFIX)
    if not latest_abuse_object:
        raise FileNotFoundError(
            f"No processed AbuseIPDB parquet file found under prefix: {ABUSE_PROCESSED_PREFIX}"
        )

    print(f"Reading latest AbuseIPDB processed parquet from MinIO: {latest_abuse_object}")
    abuse_df = load_parquet_from_minio(client, MINIO_BUCKET, latest_abuse_object)

    if "ip_address" not in abuse_df.columns:
        raise KeyError("The processed AbuseIPDB parquet does not contain 'ip_address' column")

    ip_list = (
        abuse_df["ip_address"]
        .dropna()
        .astype(str)
        .str.strip()
        .replace("", pd.NA)
        .dropna()
        .drop_duplicates()
        .tolist()
    )

    if OTX_MAX_IPS:
        ip_list = ip_list[:OTX_MAX_IPS]
        print(f"OTX_MAX_IPS is set. Processing first {len(ip_list)} IPs only.")
    else:
        print(f"Processing all {len(ip_list)} unique IPs.")

    otx_records = []
    completed = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(fetch_otx_for_ip, ip): ip for ip in ip_list}

        for future in as_completed(futures):
            record = future.result()
            otx_records.append(record)
            completed += 1

            if completed % 100 == 0 or completed == len(ip_list):
                print(f"Processed {completed}/{len(ip_list)} IPs")

    payload = {
        "source": "otx_raw",
        "ingestion_time": run_dt.isoformat(),
        "source_abuse_processed_object": latest_abuse_object,
        "record_count": len(otx_records),
        "data": otx_records
    }

    object_name = build_raw_object_name(run_dt)

    print(f"Uploading OTX raw data to MinIO: {object_name}")
    upload_json_to_minio(client, MINIO_BUCKET, object_name, payload)

    print("OTX ingest completed successfully.")
    print(f"Bucket: {MINIO_BUCKET}")
    print(f"Object: {object_name}")
    print(f"Records: {len(otx_records)}")
    print(otx_records[:3])


if __name__ == "__main__":
    try:
        main()
    except S3Error as e:
        print(f"MinIO error: {e}")
        raise
    except Exception as e:
        print(f"Unexpected error: {e}")
        raise