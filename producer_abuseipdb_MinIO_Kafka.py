import os
from io import BytesIO

import pandas as pd
from dotenv import load_dotenv
from kafka import KafkaProducer
from minio import Minio
from minio.error import S3Error
import json

load_dotenv()

# ---------- Kafka ----------
TOPIC_NAME = os.getenv("KAFKA_TOPIC", "abuseipdb_blacklist_topic")
BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:29092")

# ---------- MinIO ----------
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY") or os.getenv("MINIO_ROOT_USER")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY") or os.getenv("MINIO_ROOT_PASSWORD")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "cyber-threat-intelligence")

ABUSE_PROCESSED_PREFIX = os.getenv("ABUSE_PROCESSED_PREFIX", "processed/abuseipdb/")


def get_minio_client() -> Minio:
    return Minio(
        MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=MINIO_SECURE,
    )


def get_latest_parquet_object_name(client: Minio, bucket_name: str, prefix: str) -> str | None:
    latest_obj = None

    for obj in client.list_objects(bucket_name, prefix=prefix, recursive=True):
        if obj.is_dir:
            continue
        if not obj.object_name.endswith(".parquet"):
            continue
        if latest_obj is None or obj.last_modified > latest_obj.last_modified:
            latest_obj = obj

    return latest_obj.object_name if latest_obj else None


def load_records_from_minio_parquet(client: Minio, bucket_name: str, object_name: str):
    response = client.get_object(bucket_name, object_name)
    try:
        raw_bytes = response.read()
    finally:
        response.close()
        response.release_conn()

    df = pd.read_parquet(BytesIO(raw_bytes), engine="pyarrow")

    # Convert NaN/NaT to None for clean JSON serialization
    df = df.astype(object).where(pd.notnull(df), None)

    return df.to_dict(orient="records")


def main():
    client = get_minio_client()

    latest_object = get_latest_parquet_object_name(
        client,
        MINIO_BUCKET,
        ABUSE_PROCESSED_PREFIX
    )

    if not latest_object:
        print(f"No parquet file found in MinIO under prefix: {ABUSE_PROCESSED_PREFIX}")
        return

    print(f"Reading latest parquet from MinIO: {latest_object}")
    records = load_records_from_minio_parquet(client, MINIO_BUCKET, latest_object)

    if not records:
        print(f"No records found in MinIO object: {latest_object}")
        return

    producer = KafkaProducer(
        bootstrap_servers=BOOTSTRAP_SERVERS,
        value_serializer=lambda v: json.dumps(v, ensure_ascii=False).encode("utf-8")
    )

    sent_count = 0

    for record in records:
        producer.send(TOPIC_NAME, value=record)
        sent_count += 1

    producer.flush()
    producer.close()

    print(f"Sent {sent_count} records to Kafka topic '{TOPIC_NAME}'")
    print(f"Source parquet: {latest_object}")


if __name__ == "__main__":
    try:
        main()
    except S3Error as e:
        print(f"MinIO error: {e}")
        raise
    except Exception as e:
        print(f"Unexpected error: {e}")
        raise