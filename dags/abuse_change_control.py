import os
import json
import hashlib
from io import BytesIO
from datetime import datetime, timezone

from dotenv import load_dotenv
from minio import Minio
from minio.error import S3Error

load_dotenv()

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY") or os.getenv("MINIO_ROOT_USER")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY") or os.getenv("MINIO_ROOT_PASSWORD")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "cyber-threat-intelligence")

ABUSE_RAW_PREFIX = os.getenv("ABUSE_RAW_PREFIX", "raw/abuseipdb/")
ABUSE_STATE_OBJECT = os.getenv("ABUSE_STATE_OBJECT", "control/abuseipdb/committed_state.json")


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_minio_client() -> Minio:
    return Minio(
        MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=MINIO_SECURE,
    )


def get_latest_raw_object_name(client: Minio, bucket_name: str, prefix: str) -> str | None:
    latest_obj = None

    for obj in client.list_objects(bucket_name, prefix=prefix, recursive=True):
        if obj.is_dir:
            continue
        if not obj.object_name.endswith(".json"):
            continue

        if latest_obj is None or obj.last_modified > latest_obj.last_modified:
            latest_obj = obj

    return latest_obj.object_name if latest_obj else None


def read_json_object(client: Minio, bucket_name: str, object_name: str) -> dict:
    response = client.get_object(bucket_name, object_name)
    try:
        raw_bytes = response.read()
    finally:
        response.close()
        response.release_conn()

    return json.loads(raw_bytes.decode("utf-8"))


def upload_json_object(client: Minio, bucket_name: str, object_name: str, payload: dict) -> None:
    body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    data_stream = BytesIO(body)

    client.put_object(
        bucket_name=bucket_name,
        object_name=object_name,
        data=data_stream,
        length=len(body),
        content_type="application/json"
    )


def normalize_abuse_records(raw_payload: dict) -> list[dict]:
    records = raw_payload.get("data", []) or []

    normalized = []
    for record in records:
        ip_address = record.get("ipAddress")
        if not ip_address:
            continue

        normalized.append({
            "ip_address": ip_address,
            "abuse_confidence_score": record.get("abuseConfidenceScore"),
            "last_reported_at": record.get("lastReportedAt"),
            "country_code": record.get("countryCode"),
        })

    normalized.sort(key=lambda x: x["ip_address"])
    return normalized


def build_state_from_raw(raw_payload: dict, source_object_name: str) -> dict:
    normalized_records = normalize_abuse_records(raw_payload)

    fingerprint_source = json.dumps(
        normalized_records,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":")
    ).encode("utf-8")

    fingerprint = hashlib.sha256(fingerprint_source).hexdigest()

    return {
        "generated_at": utc_now_iso(),
        "source_object_name": source_object_name,
        "record_count": len(normalized_records),
        "fingerprint": fingerprint,
        "records": normalized_records
    }


def summarize_differences(previous_state: dict, current_state: dict) -> dict:
    previous_records = {
        r["ip_address"]: r for r in previous_state.get("records", [])
    }
    current_records = {
        r["ip_address"]: r for r in current_state.get("records", [])
    }

    previous_ips = set(previous_records.keys())
    current_ips = set(current_records.keys())

    new_ips = sorted(current_ips - previous_ips)
    removed_ips = sorted(previous_ips - current_ips)

    changed_ips = []
    for ip in sorted(current_ips & previous_ips):
        if current_records[ip] != previous_records[ip]:
            changed_ips.append(ip)

    return {
        "new_ip_count": len(new_ips),
        "changed_ip_count": len(changed_ips),
        "removed_ip_count": len(removed_ips),
        "sample_new_ips": new_ips[:10],
        "sample_changed_ips": changed_ips[:10],
        "sample_removed_ips": removed_ips[:10],
    }


def detect_abuse_changes() -> bool:
    client = get_minio_client()

    latest_raw_object = get_latest_raw_object_name(client, MINIO_BUCKET, ABUSE_RAW_PREFIX)
    if not latest_raw_object:
        raise FileNotFoundError(f"No AbuseIPDB raw file found under prefix: {ABUSE_RAW_PREFIX}")

    print(f"Latest raw AbuseIPDB object: {latest_raw_object}")

    raw_payload = read_json_object(client, MINIO_BUCKET, latest_raw_object)
    current_state = build_state_from_raw(raw_payload, latest_raw_object)

    try:
        previous_state = read_json_object(client, MINIO_BUCKET, ABUSE_STATE_OBJECT)
    except S3Error as e:
        if e.code in {"NoSuchKey", "NoSuchObject", "NoSuchBucket"}:
            print("No committed state found. First run will continue.")
            return True
        raise

    previous_fingerprint = previous_state.get("fingerprint")
    current_fingerprint = current_state.get("fingerprint")

    if previous_fingerprint == current_fingerprint:
        print("No new or changed AbuseIPDB records detected.")
        print("Downstream tasks will be skipped.")
        return False

    diff_summary = summarize_differences(previous_state, current_state)

    print("Changes detected in AbuseIPDB snapshot:")
    print(json.dumps(diff_summary, ensure_ascii=False, indent=2))

    return True


def commit_abuse_state() -> None:
    client = get_minio_client()

    latest_raw_object = get_latest_raw_object_name(client, MINIO_BUCKET, ABUSE_RAW_PREFIX)
    if not latest_raw_object:
        raise FileNotFoundError(f"No AbuseIPDB raw file found under prefix: {ABUSE_RAW_PREFIX}")

    raw_payload = read_json_object(client, MINIO_BUCKET, latest_raw_object)
    current_state = build_state_from_raw(raw_payload, latest_raw_object)

    upload_json_object(client, MINIO_BUCKET, ABUSE_STATE_OBJECT, current_state)

    print("Committed AbuseIPDB state successfully.")
    print(f"State object: {ABUSE_STATE_OBJECT}")
    print(f"Source raw object: {latest_raw_object}")
    print(f"Fingerprint: {current_state['fingerprint']}")
    print(f"Record count: {current_state['record_count']}")