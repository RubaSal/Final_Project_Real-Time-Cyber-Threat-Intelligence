import json
from io import BytesIO
from datetime import datetime, timezone
import os

import pandas as pd
from dotenv import load_dotenv
from minio import Minio
from minio.error import S3Error

load_dotenv()

# ---------- MinIO ----------
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY") or os.getenv("MINIO_ROOT_USER")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY") or os.getenv("MINIO_ROOT_PASSWORD")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "cyber-threat-intelligence")

GEO_RAW_PREFIX = os.getenv("GEO_RAW_PREFIX", "raw/geoip/")
GEO_PROCESSED_PREFIX = os.getenv("GEO_PROCESSED_PREFIX", "processed/geoip/")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def to_float(value):
    try:
        return float(value) if value is not None else None
    except (ValueError, TypeError):
        return None


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


def build_processed_parquet_object_name(processed_dt: datetime) -> str:
    year = processed_dt.strftime("%Y")
    month = processed_dt.strftime("%m")
    day = processed_dt.strftime("%d")
    timestamp = processed_dt.strftime("%Y%m%d_%H%M%S")

    return (
        f"{GEO_PROCESSED_PREFIX}"
        f"year={year}/month={month}/day={day}/"
        f"geoip_processed_{timestamp}.parquet"
    )


def upload_parquet_to_minio(client: Minio, bucket_name: str, object_name: str, df: pd.DataFrame) -> None:
    buffer = BytesIO()
    df.to_parquet(buffer, index=False, engine="pyarrow")
    buffer.seek(0)

    client.put_object(
        bucket_name=bucket_name,
        object_name=object_name,
        data=buffer,
        length=buffer.getbuffer().nbytes,
        content_type="application/octet-stream"
    )


def main():
    client = get_minio_client()
    ensure_bucket_exists(client, MINIO_BUCKET)

    latest_raw_object = get_latest_object_name(client, MINIO_BUCKET, GEO_RAW_PREFIX)
    if not latest_raw_object:
        raise SystemExit(f"No GeoIP raw file found in MinIO under prefix: {GEO_RAW_PREFIX}")

    print(f"Reading latest raw file from MinIO: {latest_raw_object}")
    raw_payload = load_json_from_minio(client, MINIO_BUCKET, latest_raw_object)

    records = raw_payload.get("data", []) if isinstance(raw_payload, dict) else []
    raw_ingestion_time = raw_payload.get("last_ingestion_time") if isinstance(raw_payload, dict) else None
    processed_at = utc_now().isoformat()

    processed_records = []

    for record in records:
        processed_record = {
            "ip_address": record.get("ip"),
            "geo_continent_name": record.get("continent_name"),
            "geo_country_code2": record.get("country_code2"),
            "geo_country_name": record.get("country_name"),
            "geo_state_province": record.get("state_prov"),
            "geo_city": record.get("city"),
            "geo_latitude": to_float(record.get("latitude")),
            "geo_longitude": to_float(record.get("longitude")),
            "geo_is_eu": record.get("is_eu"),
            "geo_asn_number": record.get("asn_number"),
            "geo_asn_organization": record.get("asn_organization"),
            "geo_asn_country": record.get("asn_country"),
            "geo_timezone_name": record.get("timezone_name"),
            "geo_timezone_offset": record.get("timezone_offset"),
            "geo_status": record.get("status"),
            "first_ingestion_time": record.get("first_ingestion_time"),
            "last_ingestion_time": record.get("last_ingestion_time"),
            "seen_count": record.get("seen_count"),
            "raw_ingestion_time": raw_ingestion_time,
            "processed_at": processed_at
        }
        processed_records.append(processed_record)

    df = pd.DataFrame(processed_records)

    parquet_object_name = build_processed_parquet_object_name(utc_now())

    print(f"Uploading processed Parquet to MinIO: {parquet_object_name}")
    upload_parquet_to_minio(client, MINIO_BUCKET, parquet_object_name, df)

    print("Transform completed successfully.")
    print(f"Bucket: {MINIO_BUCKET}")
    print(f"RAW source: {latest_raw_object}")
    print(f"Processed Parquet: {parquet_object_name}")
    print(f"Records: {len(processed_records)}")
    print(processed_records[:5])


if __name__ == "__main__":
    try:
        main()
    except S3Error as e:
        print(f"MinIO error: {e}")
        raise
    except Exception as e:
        print(f"Unexpected error: {e}")
        raise