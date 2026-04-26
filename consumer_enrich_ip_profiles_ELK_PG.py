import os
import json
import math
from io import BytesIO
from datetime import datetime, timezone

import pandas as pd
import psycopg2
from psycopg2.extras import execute_values
from elasticsearch import Elasticsearch, helpers
from minio import Minio
from minio.error import S3Error

from pyspark.sql import SparkSession
from pyspark.sql.functions import col, from_json, current_timestamp
from pyspark.sql.types import (
    StructType,
    StructField,
    StringType,
    IntegerType,
    DoubleType,
    BooleanType,
    ArrayType
)

# ---------- Kafka ----------
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_TOPIC = os.getenv("KAFKA_TOPIC", "abuseipdb_blacklist_topic")

# ---------- MinIO ----------
MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "minio:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY") or os.getenv("MINIO_ROOT_USER")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY") or os.getenv("MINIO_ROOT_PASSWORD")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"
MINIO_BUCKET = os.getenv("MINIO_BUCKET", "cyber-threat-intelligence")

OTX_PROCESSED_PREFIX = os.getenv("OTX_PROCESSED_PREFIX", "processed/otx/")
GEO_PROCESSED_PREFIX = os.getenv("GEO_PROCESSED_PREFIX", "processed/geoip/")

# ---------- Elasticsearch ----------
ES_HOST = os.getenv("ES_HOST", "http://elasticsearch:9200")
ES_INDEX = os.getenv("ES_INDEX", "ip_profiles_enriched")

# ---------- PostgreSQL ----------
PG_HOST = os.getenv("PG_HOST", "postgres")
PG_PORT = int(os.getenv("PG_PORT", "5432"))
PG_DB = os.getenv("PG_DB", "cyber_threat_intelligence")
PG_USER = os.getenv("PG_USER", "postgres")
PG_PASSWORD = os.getenv("PG_PASSWORD", "postgres")
PG_TABLE = os.getenv("PG_TABLE", "ip_profiles_enriched")

# ---------- Checkpoint ----------
CHECKPOINT_LOCATION = os.getenv(
    "CHECKPOINT_LOCATION",
    "checkpoints/ip_profiles_enriched_direct_sinks"
)

ATTACK_KEYWORDS = {
    "Brute Force": [
        "brute force", "bruteforce", "ssh", "telnet", "rdp", "login attempt"
    ],
    "Phishing": [
        "phishing", "credential", "spoof", "email lure"
    ],
    "Botnet / C2": [
        "botnet", "c2", "command and control", "cnc", "beacon"
    ],
    "Scanning": [
        "scan", "scanner", "masscan", "zmap", "recon"
    ],
    "Malware": [
        "malware", "trojan", "loader", "backdoor", "stealer"
    ],
    "Ransomware": [
        "ransomware", "locker", "encryptor"
    ],
    "Exploitation": [
        "exploit", "vulnerability", "rce", "remote code execution"
    ]
}

GEO_FIELDS = {
    "geo_continent_name",
    "geo_country_code2",
    "geo_country_name",
    "geo_state_province",
    "geo_city",
    "geo_latitude",
    "geo_longitude",
    "geo_is_eu",
    "geo_asn_number",
    "geo_asn_organization",
    "geo_asn_country",
    "geo_timezone_name",
    "geo_timezone_offset",
    "geo_location",
}

ABUSE_SCHEMA = StructType([
    StructField("ip_address", StringType(), True),
    StructField("country_code", StringType(), True),
    StructField("abuse_confidence_score", IntegerType(), True),
    StructField("last_reported_at", StringType(), True),
    StructField("ingestion_time", StringType(), True),
    StructField("processed_at", StringType(), True),
])

OTX_SCHEMA = StructType([
    StructField("ip_address", StringType(), True),
    StructField("otx_reputation", DoubleType(), True),
    StructField("otx_pulse_count", IntegerType(), True),
    StructField("otx_pulse_names", ArrayType(StringType()), True),
    StructField("otx_passive_dns_count", IntegerType(), True),
    StructField("otx_general_status", StringType(), True),
    StructField("otx_passive_dns_status", StringType(), True),
    StructField("first_ingestion_time", StringType(), True),
    StructField("last_ingestion_time", StringType(), True),
    StructField("seen_count", IntegerType(), True),
    StructField("raw_ingestion_time", StringType(), True),
    StructField("processed_at", StringType(), True),
])

GEO_SCHEMA = StructType([
    StructField("ip_address", StringType(), True),
    StructField("geo_continent_name", StringType(), True),
    StructField("geo_country_code2", StringType(), True),
    StructField("geo_country_name", StringType(), True),
    StructField("geo_state_province", StringType(), True),
    StructField("geo_city", StringType(), True),
    StructField("geo_latitude", DoubleType(), True),
    StructField("geo_longitude", DoubleType(), True),
    StructField("geo_is_eu", BooleanType(), True),
    StructField("geo_asn_number", StringType(), True),
    StructField("geo_asn_organization", StringType(), True),
    StructField("geo_asn_country", StringType(), True),
    StructField("geo_timezone_name", StringType(), True),
    StructField("geo_timezone_offset", DoubleType(), True),
    StructField("geo_status", StringType(), True),
    StructField("first_ingestion_time", StringType(), True),
    StructField("last_ingestion_time", StringType(), True),
    StructField("seen_count", IntegerType(), True),
    StructField("raw_ingestion_time", StringType(), True),
    StructField("processed_at", StringType(), True),
])


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def has_value(value):
    return value is not None and value != ""


def normalize_value(value):
    if value is None:
        return None

    if isinstance(value, dict):
        return {k: normalize_value(v) for k, v in value.items()}

    if isinstance(value, (list, tuple, set)):
        return [normalize_value(v) for v in value]

    if isinstance(value, (pd.Timestamp, datetime)):
        return value.isoformat()

    if hasattr(value, "item"):
        try:
            value = value.item()
        except Exception:
            pass

    if isinstance(value, float) and math.isnan(value):
        return None

    try:
        if pd.isna(value):
            return None
    except Exception:
        pass

    return value


def normalize_record(record):
    return {key: normalize_value(value) for key, value in record.items()}


def safe_int(value, default=0):
    try:
        value = normalize_value(value)
        if value is None:
            return default
        return int(float(value))
    except Exception:
        return default


def safe_float(value, default=None):
    try:
        value = normalize_value(value)
        if value is None:
            return default
        return float(value)
    except Exception:
        return default


def safe_bool(value, default=None):
    value = normalize_value(value)

    if value is None:
        return default

    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        value_lower = value.strip().lower()
        if value_lower in {"true", "1", "yes", "y"}:
            return True
        if value_lower in {"false", "0", "no", "n"}:
            return False

    return default


def safe_string(value, default=None):
    value = normalize_value(value)

    if value is None:
        return default

    return str(value)


def normalize_string_array(value):
    value = normalize_value(value)

    if value is None:
        return []

    if isinstance(value, str):
        value = value.strip()
        if not value:
            return []

        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [str(item) for item in parsed if item is not None and str(item).strip()]
        except Exception:
            pass

        return [value]

    if isinstance(value, (list, tuple, set)):
        return [
            str(item)
            for item in value
            if item is not None and str(item).strip()
        ]

    return [str(value)]


def normalize_otx_record(record):
    record = normalize_record(record)

    normalized = {
        "ip_address": safe_string(record.get("ip_address")),
        "otx_reputation": safe_float(record.get("otx_reputation"), None),
        "otx_pulse_count": safe_int(record.get("otx_pulse_count"), None),
        "otx_pulse_names": normalize_string_array(record.get("otx_pulse_names")),
        "otx_passive_dns_count": safe_int(record.get("otx_passive_dns_count"), None),
        "otx_general_status": safe_string(record.get("otx_general_status")),
        "otx_passive_dns_status": safe_string(record.get("otx_passive_dns_status")),
        "first_ingestion_time": safe_string(record.get("first_ingestion_time")),
        "last_ingestion_time": safe_string(record.get("last_ingestion_time")),
        "seen_count": safe_int(record.get("seen_count"), None),
        "raw_ingestion_time": safe_string(record.get("raw_ingestion_time")),
        "processed_at": safe_string(record.get("processed_at")),
    }

    return normalized


def normalize_geo_record(record):
    record = normalize_record(record)

    normalized = {
        "ip_address": safe_string(record.get("ip_address")),
        "geo_continent_name": safe_string(record.get("geo_continent_name")),
        "geo_country_code2": safe_string(record.get("geo_country_code2")),
        "geo_country_name": safe_string(record.get("geo_country_name")),
        "geo_state_province": safe_string(record.get("geo_state_province")),
        "geo_city": safe_string(record.get("geo_city")),
        "geo_latitude": safe_float(record.get("geo_latitude"), None),
        "geo_longitude": safe_float(record.get("geo_longitude"), None),
        "geo_is_eu": safe_bool(record.get("geo_is_eu"), None),
        "geo_asn_number": safe_string(record.get("geo_asn_number")),
        "geo_asn_organization": safe_string(record.get("geo_asn_organization")),
        "geo_asn_country": safe_string(record.get("geo_asn_country")),
        "geo_timezone_name": safe_string(record.get("geo_timezone_name")),
        "geo_timezone_offset": safe_float(record.get("geo_timezone_offset"), None),
        "geo_status": safe_string(record.get("geo_status")),
        "first_ingestion_time": safe_string(record.get("first_ingestion_time")),
        "last_ingestion_time": safe_string(record.get("last_ingestion_time")),
        "seen_count": safe_int(record.get("seen_count"), None),
        "raw_ingestion_time": safe_string(record.get("raw_ingestion_time")),
        "processed_at": safe_string(record.get("processed_at")),
    }

    return normalized


def normalize_sink_record(record):
    record = normalize_record(record)

    record["ip_address"] = safe_string(record.get("ip_address"))

    record["abuse_confidence_score"] = safe_int(record.get("abuse_confidence_score"), None)
    record["abuse_total_reports"] = safe_int(record.get("abuse_total_reports"), None)

    record["otx_reputation"] = safe_float(record.get("otx_reputation"), None)
    record["otx_pulse_count"] = safe_int(record.get("otx_pulse_count"), None)
    record["otx_pulse_names"] = normalize_string_array(record.get("otx_pulse_names"))
    record["otx_passive_dns_count"] = safe_int(record.get("otx_passive_dns_count"), None)

    record["geo_latitude"] = safe_float(record.get("geo_latitude"), None)
    record["geo_longitude"] = safe_float(record.get("geo_longitude"), None)
    record["geo_is_eu"] = safe_bool(record.get("geo_is_eu"), None)
    record["geo_timezone_offset"] = safe_float(record.get("geo_timezone_offset"), None)

    record["risk_score"] = safe_float(record.get("risk_score"), None)

    record["attack_categories"] = normalize_string_array(record.get("attack_categories"))
    record["attack_keywords_matched"] = normalize_string_array(record.get("attack_keywords_matched"))

    return record


def derive_attack_categories(otx_pulse_names):
    if not otx_pulse_names:
        return [], []

    if isinstance(otx_pulse_names, str):
        pulse_text = otx_pulse_names.lower()
    else:
        pulse_text = " | ".join(str(x).lower() for x in otx_pulse_names if x)

    matched_categories = set()
    matched_keywords = set()

    for category, keywords in ATTACK_KEYWORDS.items():
        for keyword in keywords:
            if keyword in pulse_text:
                matched_categories.add(category)
                matched_keywords.add(keyword)

    return sorted(matched_categories), sorted(matched_keywords)


def calculate_risk_score(
    abuse_score,
    otx_pulse_count,
    passive_dns_count,
    attack_categories=None,
    attack_keywords=None
):
    attack_categories = attack_categories or []
    attack_keywords = attack_keywords or []

    score = 0.0

    # 1) AbuseIPDB contribution
    score += min(abuse_score, 100) * 0.6

    # 2) OTX pulse volume contribution
    if otx_pulse_count >= 50:
        score += 35
    elif otx_pulse_count >= 20:
        score += 25
    elif otx_pulse_count >= 10:
        score += 18
    elif otx_pulse_count >= 5:
        score += 10
    elif otx_pulse_count > 0:
        score += 5

    # 3) Passive DNS contribution
    score += min(passive_dns_count, 20) * 0.5

    # 4) Category-based bonuses
    category_bonus_map = {
        "Brute Force": 12,
        "Phishing": 18,
        "Botnet / C2": 25,
        "Scanning": 8,
        "Malware": 20,
        "Ransomware": 30,
        "Exploitation": 25
    }

    for category in attack_categories:
        score += category_bonus_map.get(category, 0)

    # 5) Keyword-based bonuses
    keyword_bonus_map = {
        "rce": 20,
        "remote code execution": 20,
        "exploit": 12,
        "brute force": 10,
        "bruteforce": 10,
        "ssh": 6,
        "telnet": 8,
        "rdp": 10,
        "botnet": 18,
        "c2": 18,
        "command and control": 18,
        "ransomware": 25,
        "malware": 15,
        "phishing": 15
    }

    for keyword in attack_keywords:
        score += keyword_bonus_map.get(str(keyword).lower(), 0)

    # 6) Rule-based minimum floors
    categories_set = set(attack_categories)
    keywords_set = {str(k).lower() for k in attack_keywords}

    if otx_pulse_count >= 20 and attack_categories:
        score = max(score, 55)

    if "Exploitation" in categories_set or "rce" in keywords_set or "remote code execution" in keywords_set:
        score = max(score, 70)

    if "Botnet / C2" in categories_set or "Ransomware" in categories_set:
        score = max(score, 80)

    if abuse_score >= 40 and attack_categories:
        score = max(score, 65)

    return round(min(score, 100), 2)


def derive_status(risk_score):
    if risk_score >= 70:
        return "High Risk"
    if risk_score >= 30:
        return "Medium Risk"
    return "Low Risk"


def get_minio_client():
    return Minio(
        MINIO_ENDPOINT,
        access_key=MINIO_ACCESS_KEY,
        secret_key=MINIO_SECRET_KEY,
        secure=MINIO_SECURE,
    )


def get_latest_object_name(client: Minio, bucket_name: str, prefix: str):
    latest_obj = None

    for obj in client.list_objects(bucket_name, prefix=prefix, recursive=True):
        if obj.is_dir:
            continue

        if not obj.object_name.endswith(".parquet"):
            continue

        if latest_obj is None or obj.last_modified > latest_obj.last_modified:
            latest_obj = obj

    return latest_obj.object_name if latest_obj else None


def load_parquet_records_from_minio(prefix: str):
    client = get_minio_client()
    latest_object = get_latest_object_name(client, MINIO_BUCKET, prefix)

    if not latest_object:
        return [], None

    response = client.get_object(MINIO_BUCKET, latest_object)

    try:
        raw_bytes = response.read()
    finally:
        response.close()
        response.release_conn()

    df = pd.read_parquet(BytesIO(raw_bytes), engine="pyarrow")
    records = df.to_dict(orient="records")
    records = [normalize_record(record) for record in records]

    return records, latest_object


def get_es_client():
    return Elasticsearch([ES_HOST])


def ensure_es_index(es: Elasticsearch):
    properties = {
        "ip_address": {"type": "keyword"},
        "abuse_confidence_score": {"type": "integer"},
        "abuse_country_code": {"type": "keyword"},
        "abuse_country_name": {"type": "keyword"},
        "abuse_last_reported_at": {"type": "date"},
        "abuse_total_reports": {"type": "integer"},
        "otx_reputation": {"type": "double"},
        "otx_pulse_count": {"type": "integer"},
        "otx_pulse_names": {"type": "keyword"},
        "otx_passive_dns_count": {"type": "integer"},
        "otx_general_status": {"type": "keyword"},
        "otx_passive_dns_status": {"type": "keyword"},
        "geo_continent_name": {"type": "keyword"},
        "geo_country_code2": {"type": "keyword"},
        "geo_country_name": {"type": "keyword"},
        "geo_state_province": {"type": "keyword"},
        "geo_city": {"type": "keyword"},
        "geo_latitude": {"type": "float"},
        "geo_longitude": {"type": "float"},
        "geo_is_eu": {"type": "boolean"},
        "geo_asn_number": {"type": "keyword"},
        "geo_asn_organization": {"type": "keyword"},
        "geo_asn_country": {"type": "keyword"},
        "geo_timezone_name": {"type": "keyword"},
        "geo_timezone_offset": {"type": "float"},
        "risk_score": {"type": "float"},
        "status": {"type": "keyword"},
        "attack_categories": {"type": "keyword"},
        "attack_keywords_matched": {"type": "keyword"},
        "profile_source": {"type": "keyword"},
        "first_seen_at": {"type": "date"},
        "last_merged_at": {"type": "date"},
        "enriched_at": {"type": "date"},
        "geo_location": {"type": "geo_point"}
    }

    if not es.indices.exists(index=ES_INDEX):
        es.indices.create(index=ES_INDEX, body={"mappings": {"properties": properties}})
    else:
        es.indices.put_mapping(
            index=ES_INDEX,
            body={
                "properties": {
                    "attack_categories": {"type": "keyword"},
                    "attack_keywords_matched": {"type": "keyword"},
                    "first_seen_at": {"type": "date"},
                    "last_merged_at": {"type": "date"},
                    "geo_location": {"type": "geo_point"}
                }
            }
        )


def get_existing_es_docs(es: Elasticsearch, ids):
    if not ids:
        return {}

    docs = es.mget(index=ES_INDEX, body={"ids": ids}).get("docs", [])
    result = {}

    for doc in docs:
        if doc.get("found"):
            result[doc["_id"]] = doc["_source"]

    return result


def enrich_geo_location(record):
    lat = record.get("geo_latitude")
    lon = record.get("geo_longitude")

    if lat is not None and lon is not None:
        record["geo_location"] = {"lat": lat, "lon": lon}

    return record


def merge_ip_profile(existing_doc, incoming_doc):
    incoming = incoming_doc.copy()
    merged = existing_doc.copy() if existing_doc else {}

    for field, value in incoming.items():
        if field in {"risk_score", "status", "attack_categories", "attack_keywords_matched"}:
            continue

        if field in GEO_FIELDS:
            if has_value(value):
                merged[field] = value
            continue

        if field == "otx_pulse_names":
            if value is not None:
                merged[field] = value
            continue

        if value is not None:
            merged[field] = value

    merged["ip_address"] = incoming.get("ip_address") or merged.get("ip_address")

    attack_categories, attack_keywords_matched = derive_attack_categories(
        merged.get("otx_pulse_names", [])
    )
    merged["attack_categories"] = attack_categories
    merged["attack_keywords_matched"] = attack_keywords_matched

    abuse_score = safe_int(merged.get("abuse_confidence_score"), 0)
    otx_pulse_count = safe_int(merged.get("otx_pulse_count"), 0)
    passive_dns_count = safe_int(merged.get("otx_passive_dns_count"), 0)

    merged["risk_score"] = calculate_risk_score(
        abuse_score=abuse_score,
        otx_pulse_count=otx_pulse_count,
        passive_dns_count=passive_dns_count,
        attack_categories=attack_categories,
        attack_keywords=attack_keywords_matched
    )
    merged["status"] = derive_status(merged["risk_score"])

    now = utc_now()
    merged["last_merged_at"] = now

    if not merged.get("first_seen_at"):
        merged["first_seen_at"] = incoming.get("enriched_at") or now

    if not merged.get("profile_source"):
        merged["profile_source"] = "pipeline"

    return enrich_geo_location(merged)


def ensure_pg_table(conn):
    with conn.cursor() as cur:
        cur.execute(f"""
        CREATE TABLE IF NOT EXISTS {PG_TABLE} (
            ip_address TEXT PRIMARY KEY,
            abuse_confidence_score INTEGER,
            abuse_country_code TEXT,
            abuse_country_name TEXT,
            abuse_last_reported_at TIMESTAMPTZ,
            abuse_total_reports INTEGER,
            otx_reputation DOUBLE PRECISION,
            otx_pulse_count INTEGER,
            otx_pulse_names TEXT[],
            otx_passive_dns_count INTEGER,
            otx_general_status TEXT,
            otx_passive_dns_status TEXT,
            geo_continent_name TEXT,
            geo_country_code2 TEXT,
            geo_country_name TEXT,
            geo_state_province TEXT,
            geo_city TEXT,
            geo_latitude DOUBLE PRECISION,
            geo_longitude DOUBLE PRECISION,
            geo_is_eu BOOLEAN,
            geo_asn_number TEXT,
            geo_asn_organization TEXT,
            geo_asn_country TEXT,
            geo_timezone_name TEXT,
            geo_timezone_offset DOUBLE PRECISION,
            risk_score DOUBLE PRECISION,
            status TEXT,
            attack_categories TEXT[],
            attack_keywords_matched TEXT[],
            profile_source TEXT,
            first_seen_at TIMESTAMPTZ,
            last_merged_at TIMESTAMPTZ,
            enriched_at TIMESTAMPTZ
        )
        """)

        cur.execute(f"""
        ALTER TABLE {PG_TABLE}
        ALTER COLUMN otx_reputation TYPE DOUBLE PRECISION
        USING otx_reputation::DOUBLE PRECISION
        """)

    conn.commit()


def upsert_to_postgres(records):
    if not records:
        return

    conn = psycopg2.connect(
        host=PG_HOST,
        port=PG_PORT,
        dbname=PG_DB,
        user=PG_USER,
        password=PG_PASSWORD
    )

    try:
        ensure_pg_table(conn)

        columns = [
            "ip_address",
            "abuse_confidence_score",
            "abuse_country_code",
            "abuse_country_name",
            "abuse_last_reported_at",
            "abuse_total_reports",
            "otx_reputation",
            "otx_pulse_count",
            "otx_pulse_names",
            "otx_passive_dns_count",
            "otx_general_status",
            "otx_passive_dns_status",
            "geo_continent_name",
            "geo_country_code2",
            "geo_country_name",
            "geo_state_province",
            "geo_city",
            "geo_latitude",
            "geo_longitude",
            "geo_is_eu",
            "geo_asn_number",
            "geo_asn_organization",
            "geo_asn_country",
            "geo_timezone_name",
            "geo_timezone_offset",
            "risk_score",
            "status",
            "attack_categories",
            "attack_keywords_matched",
            "profile_source",
            "first_seen_at",
            "last_merged_at",
            "enriched_at",
        ]

        normalized_records = [normalize_sink_record(record) for record in records]

        values = [
            tuple(record.get(col_name) for col_name in columns)
            for record in normalized_records
        ]

        insert_sql = f"""
        INSERT INTO {PG_TABLE} ({", ".join(columns)})
        VALUES %s
        ON CONFLICT (ip_address) DO UPDATE SET
            abuse_confidence_score = COALESCE(EXCLUDED.abuse_confidence_score, {PG_TABLE}.abuse_confidence_score),
            abuse_country_code = COALESCE(EXCLUDED.abuse_country_code, {PG_TABLE}.abuse_country_code),
            abuse_country_name = COALESCE(EXCLUDED.abuse_country_name, {PG_TABLE}.abuse_country_name),
            abuse_last_reported_at = COALESCE(EXCLUDED.abuse_last_reported_at, {PG_TABLE}.abuse_last_reported_at),
            abuse_total_reports = COALESCE(EXCLUDED.abuse_total_reports, {PG_TABLE}.abuse_total_reports),
            otx_reputation = COALESCE(EXCLUDED.otx_reputation, {PG_TABLE}.otx_reputation),
            otx_pulse_count = COALESCE(EXCLUDED.otx_pulse_count, {PG_TABLE}.otx_pulse_count),
            otx_pulse_names = COALESCE(EXCLUDED.otx_pulse_names, {PG_TABLE}.otx_pulse_names),
            otx_passive_dns_count = COALESCE(EXCLUDED.otx_passive_dns_count, {PG_TABLE}.otx_passive_dns_count),
            otx_general_status = COALESCE(EXCLUDED.otx_general_status, {PG_TABLE}.otx_general_status),
            otx_passive_dns_status = COALESCE(EXCLUDED.otx_passive_dns_status, {PG_TABLE}.otx_passive_dns_status),
            geo_continent_name = COALESCE(EXCLUDED.geo_continent_name, {PG_TABLE}.geo_continent_name),
            geo_country_code2 = COALESCE(EXCLUDED.geo_country_code2, {PG_TABLE}.geo_country_code2),
            geo_country_name = COALESCE(EXCLUDED.geo_country_name, {PG_TABLE}.geo_country_name),
            geo_state_province = COALESCE(EXCLUDED.geo_state_province, {PG_TABLE}.geo_state_province),
            geo_city = COALESCE(EXCLUDED.geo_city, {PG_TABLE}.geo_city),
            geo_latitude = COALESCE(EXCLUDED.geo_latitude, {PG_TABLE}.geo_latitude),
            geo_longitude = COALESCE(EXCLUDED.geo_longitude, {PG_TABLE}.geo_longitude),
            geo_is_eu = COALESCE(EXCLUDED.geo_is_eu, {PG_TABLE}.geo_is_eu),
            geo_asn_number = COALESCE(EXCLUDED.geo_asn_number, {PG_TABLE}.geo_asn_number),
            geo_asn_organization = COALESCE(EXCLUDED.geo_asn_organization, {PG_TABLE}.geo_asn_organization),
            geo_asn_country = COALESCE(EXCLUDED.geo_asn_country, {PG_TABLE}.geo_asn_country),
            geo_timezone_name = COALESCE(EXCLUDED.geo_timezone_name, {PG_TABLE}.geo_timezone_name),
            geo_timezone_offset = COALESCE(EXCLUDED.geo_timezone_offset, {PG_TABLE}.geo_timezone_offset),
            risk_score = EXCLUDED.risk_score,
            status = EXCLUDED.status,
            attack_categories = EXCLUDED.attack_categories,
            attack_keywords_matched = EXCLUDED.attack_keywords_matched,
            profile_source = COALESCE(EXCLUDED.profile_source, {PG_TABLE}.profile_source),
            first_seen_at = COALESCE({PG_TABLE}.first_seen_at, EXCLUDED.first_seen_at),
            last_merged_at = EXCLUDED.last_merged_at,
            enriched_at = EXCLUDED.enriched_at
        """

        with conn.cursor() as cur:
            execute_values(cur, insert_sql, values)

        conn.commit()

    finally:
        conn.close()


def upsert_to_elasticsearch(records):
    if not records:
        return

    es = get_es_client()
    ensure_es_index(es)

    normalized_records = [normalize_sink_record(record) for record in records]
    ids = [r["ip_address"] for r in normalized_records if r.get("ip_address")]
    existing_docs = get_existing_es_docs(es, ids)

    actions = []

    for record in normalized_records:
        ip_address = record.get("ip_address")
        if not ip_address:
            continue

        merged_doc = merge_ip_profile(existing_docs.get(ip_address), record)

        actions.append({
            "_op_type": "index",
            "_index": ES_INDEX,
            "_id": ip_address,
            "_source": merged_doc
        })

    if actions:
        helpers.bulk(es, actions)


def process_batch(batch_df, batch_id):
    if batch_df.rdd.isEmpty():
        return

    rows = [
        normalize_sink_record(row.asDict(recursive=True))
        for row in batch_df.dropDuplicates(["ip_address"]).collect()
    ]

    for row in rows:
        row["profile_source"] = "pipeline"

        if row.get("abuse_country_code") is None:
            row["abuse_country_code"] = row.get("country_code")

        if row.get("abuse_last_reported_at") is None:
            row["abuse_last_reported_at"] = row.get("last_reported_at")

        if not row.get("enriched_at"):
            row["enriched_at"] = utc_now()

        if not row.get("last_merged_at"):
            row["last_merged_at"] = row["enriched_at"]

        if not row.get("first_seen_at"):
            row["first_seen_at"] = row["enriched_at"]

        attack_categories, attack_keywords_matched = derive_attack_categories(
            row.get("otx_pulse_names", [])
        )
        row["attack_categories"] = attack_categories
        row["attack_keywords_matched"] = attack_keywords_matched

        abuse_score = safe_int(row.get("abuse_confidence_score"), 0)
        otx_pulse_count = safe_int(row.get("otx_pulse_count"), 0)
        passive_dns_count = safe_int(row.get("otx_passive_dns_count"), 0)

        row["risk_score"] = calculate_risk_score(
            abuse_score=abuse_score,
            otx_pulse_count=otx_pulse_count,
            passive_dns_count=passive_dns_count,
            attack_categories=attack_categories,
            attack_keywords=attack_keywords_matched
        )
        row["status"] = derive_status(row["risk_score"])

    upsert_to_elasticsearch(rows)
    upsert_to_postgres(rows)

    print(f"Processed batch {batch_id}: {len(rows)} records written to Elasticsearch + PostgreSQL")


def main():
    spark = (
        SparkSession.builder
        .appName("ConsumerEnrichIpProfilesDirectSinks")
        .config(
            "spark.jars.packages",
            "org.apache.spark:spark-sql-kafka-0-10_2.13:4.1.0"
        )
        .getOrCreate()
    )

    spark.sparkContext.setLogLevel("WARN")

    otx_records, otx_object = load_parquet_records_from_minio(OTX_PROCESSED_PREFIX)
    geo_records, geo_object = load_parquet_records_from_minio(GEO_PROCESSED_PREFIX)

    otx_records = [normalize_otx_record(record) for record in otx_records]
    geo_records = [normalize_geo_record(record) for record in geo_records]

    print(f"Loaded OTX snapshot: {otx_object}")
    print(f"Loaded GEO snapshot: {geo_object}")
    print(f"OTX records loaded: {len(otx_records)}")
    print(f"GEO records loaded: {len(geo_records)}")

    otx_df = (
        spark.createDataFrame(otx_records, schema=OTX_SCHEMA)
        if otx_records
        else spark.createDataFrame([], OTX_SCHEMA)
    )

    geo_df = (
        spark.createDataFrame(geo_records, schema=GEO_SCHEMA)
        if geo_records
        else spark.createDataFrame([], GEO_SCHEMA)
    )

    kafka_df = (
        spark.readStream
        .format("kafka")
        .option("kafka.bootstrap.servers", KAFKA_BOOTSTRAP_SERVERS)
        .option("subscribe", KAFKA_TOPIC)
        .option("startingOffsets", "earliest")
        .load()
    )

    parsed_stream = (
        kafka_df
        .selectExpr("CAST(value AS STRING) AS json_value")
        .select(from_json(col("json_value"), ABUSE_SCHEMA).alias("record"))
        .select("record.*")
    )

    enriched_df = (
        parsed_stream.alias("a")
        .join(otx_df.alias("o"), on="ip_address", how="left")
        .join(geo_df.alias("g"), on="ip_address", how="left")
        .fillna({
            "otx_reputation": 0.0,
            "otx_pulse_count": 0,
            "otx_passive_dns_count": 0,
            "abuse_confidence_score": 0
        })
        .withColumn("abuse_country_code", col("country_code"))
        .withColumn("abuse_country_name", col("geo_country_name"))
        .withColumn("abuse_last_reported_at", col("last_reported_at"))
        .withColumn("abuse_total_reports", col("abuse_confidence_score").cast(IntegerType()) * 0 + None)
        .withColumn("enriched_at", current_timestamp())
    )

    final_df = enriched_df.select(
        "ip_address",
        "abuse_confidence_score",
        "abuse_country_code",
        "abuse_country_name",
        "abuse_last_reported_at",
        "abuse_total_reports",
        "otx_reputation",
        "otx_pulse_count",
        "otx_pulse_names",
        "otx_passive_dns_count",
        "otx_general_status",
        "otx_passive_dns_status",
        "geo_continent_name",
        "geo_country_code2",
        "geo_country_name",
        "geo_state_province",
        "geo_city",
        "geo_latitude",
        "geo_longitude",
        "geo_is_eu",
        "geo_asn_number",
        "geo_asn_organization",
        "geo_asn_country",
        "geo_timezone_name",
        "geo_timezone_offset",
        "enriched_at"
    )

    query = (
        final_df.writeStream
        .foreachBatch(process_batch)
        .option("checkpointLocation", CHECKPOINT_LOCATION)
        .outputMode("append")
        .start()
    )

    query.awaitTermination()


if __name__ == "__main__":
    main()