import os
import json
from io import BytesIO
import time
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv
from minio import Minio
from minio.error import S3Error

load_dotenv()

# ---------- API ----------
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")
ABUSE_URL = "https://api.abuseipdb.com/api/v2/blacklist"

# ---------- MinIO ----------
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY") or os.getenv("MINIO_ROOT_USER")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY") or os.getenv("MINIO_ROOT_PASSWORD")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "cyber-threat-intelligence")


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


def fetch_abuseipdb_blacklist() -> dict:
    if not ABUSE_API_KEY:
        raise ValueError("Missing ABUSE_API_KEY in environment variables")

    headers = {
        "Key": ABUSE_API_KEY,
        "Accept": "application/json"
    }

    max_retries = 5

    for attempt in range(1, max_retries + 1):
        response = requests.get(ABUSE_URL, headers=headers, timeout=60)

        if response.status_code == 429:
            retry_after = response.headers.get("Retry-After")
            if retry_after and retry_after.isdigit():
                sleep_seconds = int(retry_after)
            else:
                sleep_seconds = attempt * 60

            print(f"AbuseIPDB rate limit hit (429). Sleeping {sleep_seconds} seconds before retry {attempt}/{max_retries}...")
            time.sleep(sleep_seconds)
            continue

        response.raise_for_status()

        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("Unexpected response format from AbuseIPDB")

        return data

    raise RuntimeError("AbuseIPDB blacklist request failed after retries due to rate limiting")


def build_partitioned_object_name(now_utc: datetime) -> str:
    year = now_utc.strftime("%Y")
    month = now_utc.strftime("%m")
    day = now_utc.strftime("%d")
    timestamp = now_utc.strftime("%Y%m%d_%H%M%S")

    return (
        f"raw/abuseipdb/"
        f"year={year}/month={month}/day={day}/"
        f"abuseipdb_raw_{timestamp}.json"
    )


def upload_json_to_minio(client: Minio, bucket_name: str, object_name: str, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")

    client.put_object(
        bucket_name=bucket_name,
        object_name=object_name,
        data=BytesIO(body),
        length=len(body),
        content_type="application/json"
    )


def main():
    now_utc = datetime.now(timezone.utc)

    print("Fetching data from AbuseIPDB...")
    raw_data = fetch_abuseipdb_blacklist()

    record_count = len(raw_data.get("data", [])) if isinstance(raw_data.get("data"), list) else 0

    payload = {
        "source": "abuseipdb_blacklist",
        "ingestion_time": now_utc.isoformat(),
        "record_count": record_count,
        "data": raw_data.get("data", [])
    }

    object_name = build_partitioned_object_name(now_utc)

    print("Connecting to MinIO...")
    client = get_minio_client()
    ensure_bucket_exists(client, MINIO_BUCKET)

    print(f"Uploading to MinIO: {object_name}")
    upload_json_to_minio(client, MINIO_BUCKET, object_name, payload)

    print("Ingest completed successfully.")
    print(f"Bucket: {MINIO_BUCKET}")
    print(f"Object: {object_name}")
    print(f"Records: {record_count}")


if __name__ == "__main__":
    try:
        main()
    except requests.HTTPError as e:
        print(f"HTTP error while calling AbuseIPDB: {e}")
        raise
    except S3Error as e:
        print(f"MinIO error: {e}")
        raise
    except Exception as e:
        print(f"Unexpected error: {e}")
        raise