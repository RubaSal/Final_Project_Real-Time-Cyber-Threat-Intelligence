import json
import os
import time

from dotenv import load_dotenv
from kafka import KafkaProducer
from minio import Minio
from minio.error import S3Error

load_dotenv()

MINIO_ENDPOINT = "localhost:9000"
MINIO_ACCESS_KEY = os.getenv("MINIO_ROOT_USER")
MINIO_SECRET_KEY = os.getenv("MINIO_ROOT_PASSWORD")
MINIO_SECURE = False

MINIO_BUCKET = "cyber-threat-intelligence"
MINIO_OBJECT = "enriched/abuseipdb_geoip_enriched.json"

TOPIC_NAME = "abuseipdb_geoip_topic"
BOOTSTRAP_SERVERS = ["localhost:29092"]


def load_records_from_minio():
    if not MINIO_ACCESS_KEY or not MINIO_SECRET_KEY:
        raise ValueError("MinIO credentials were not loaded from .env")

    client = Minio(
        MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=MINIO_SECURE,
    )

    response = None
    try:
        response = client.get_object(MINIO_BUCKET, MINIO_OBJECT)
        raw_data = response.read().decode("utf-8")
        data = json.loads(raw_data)

        if not isinstance(data, list):
            raise ValueError("Expected a list of JSON records in the MinIO object.")

        return data

    except S3Error as e:
        raise RuntimeError(f"MinIO S3 error: {e}") from e
    finally:
        if response:
            response.close()
            response.release_conn()


def main():
    records = load_records_from_minio()

    producer = KafkaProducer(
        bootstrap_servers=BOOTSTRAP_SERVERS,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        key_serializer=lambda k: k.encode("utf-8") if k else None,
        acks="all",
        retries=3,
    )

    print(
        f"Loaded {len(records)} records from MinIO "
        f"(bucket={MINIO_BUCKET}, object={MINIO_OBJECT})"
    )

    for i, record in enumerate(records, start=1):
        key = record.get("ip_address", f"record-{i}")

        future = producer.send(
            TOPIC_NAME,
            key=key,
            value=record,
        )

        metadata = future.get(timeout=10)

        print(
            f"[{i}] Sent message | "
            f"topic={metadata.topic}, partition={metadata.partition}, "
            f"offset={metadata.offset}, key={key}"
        )

        time.sleep(0.2)

    producer.flush()
    producer.close()
    print("Producer finished successfully.")


if __name__ == "__main__":
    main()