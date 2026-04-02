import os
from minio import Minio
from minio.error import S3Error

client = Minio(
    "localhost:9000",
    access_key=os.getenv("MINIO_ROOT_USER"),
    secret_key=os.getenv("MINIO_ROOT_PASSWORD"),
    secure=False
)

bucket_name = "cyber-threat-intelligence"

files_to_upload = [
    # Raw
    ("abuseipdb_raw.json", "raw/abuseipdb/abuseipdb_raw.json"),
    ("geoip_raw.json", "raw/geoip/geoip_raw.json"),
    ("security_news_raw.json", "raw/security_news/security_news_raw.json"),

     # Processed
    ("abuseipdb_processed.json", "processed/abuseipdb/abuseipdb_processed.json"),
    ("geoip_processed.json", "processed/geoip/geoip_processed.json"),
    ("security_news_processed.json", "processed/security_news/security_news_processed.json"),

    # Enriched
    ("abuseipdb_geoip_enriched.json", "enriched/abuseipdb_geoip_enriched.json"),
]

try:
    if not client.bucket_exists(bucket_name):
        client.make_bucket(bucket_name)
        print(f"Bucket '{bucket_name}' created.")
    else:
        print(f"Bucket '{bucket_name}' already exists.")

    for local_file, object_name in files_to_upload:
        client.fput_object(
            bucket_name,
            object_name,
            local_file,
            content_type="application/json"
        )
        print(f"Uploaded: {local_file} -> {object_name}")

    print("All files uploaded successfully.")

except S3Error as e:
    print("MinIO error:", e)
except Exception as e:
    print("General error:", e)