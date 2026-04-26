import json
import glob
from datetime import datetime, timezone
from elasticsearch import Elasticsearch, helpers

ES_HOST = "http://localhost:9200"
INDEX_NAME = "ip_profiles_enriched"
INPUT_PATTERN = "output/ip_profiles_enriched/part-*.json"

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


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def safe_int(value, default=0):
    try:
        if value is None:
            return default
        return int(value)
    except (ValueError, TypeError):
        return default


def has_value(value):
    return value is not None and value != ""


def calculate_risk_score(abuse_score, otx_pulse_count, passive_dns_count):
    score = 0.0
    score += min(abuse_score, 100) * 0.7
    score += min(otx_pulse_count, 20) * 1.2
    score += min(passive_dns_count, 10) * 0.6
    return round(min(score, 100), 2)


def derive_status(risk_score):
    if risk_score >= 80:
        return "High Risk"
    if risk_score >= 40:
        return "Medium Risk"
    return "Low Risk"


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


def load_records():
    records = []

    for file_path in glob.glob(INPUT_PATTERN):
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                records.append(json.loads(line))

    return records


def enrich_geo_location(record):
    lat = record.get("geo_latitude")
    lon = record.get("geo_longitude")

    if lat is not None and lon is not None:
        record["geo_location"] = {
            "lat": lat,
            "lon": lon
        }

    return record


def ensure_index_exists(es):
    properties = {
        "ip_address": {"type": "keyword"},
        "abuse_confidence_score": {"type": "integer"},
        "abuse_total_reports": {"type": "integer"},
        "abuse_country_code": {"type": "keyword"},
        "abuse_country_name": {"type": "keyword"},
        "abuse_last_reported_at": {"type": "date"},
        "otx_reputation": {"type": "long"},
        "otx_pulse_count": {"type": "integer"},
        "otx_pulse_names": {"type": "keyword"},
        "otx_passive_dns_count": {"type": "integer"},
        "otx_general_status": {"type": "keyword"},
        "otx_passive_dns_status": {"type": "keyword"},
        "geo_continent_name": {"type": "keyword"},
        "geo_country_name": {"type": "keyword"},
        "geo_country_code2": {"type": "keyword"},
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
        "profile_source": {"type": "keyword"},
        "attack_categories": {"type": "keyword"},
        "attack_keywords_matched": {"type": "keyword"},
        "enriched_at": {"type": "date"},
        "first_seen_at": {"type": "date"},
        "last_merged_at": {"type": "date"},
        "geo_location": {"type": "geo_point"}
    }

    if not es.indices.exists(index=INDEX_NAME):
        mapping = {
            "mappings": {
                "properties": properties
            }
        }
        es.indices.create(index=INDEX_NAME, body=mapping)
    else:
        # באינדקס קיים מוסיפים רק שדות חדשים, לא מנסים לשנות טיפוסים קיימים
        es.indices.put_mapping(
            index=INDEX_NAME,
            body={
                "properties": {
                    "attack_categories": {"type": "keyword"},
                    "attack_keywords_matched": {"type": "keyword"},
                    "first_seen_at": {"type": "date"},
                    "last_merged_at": {"type": "date"}
                }
            }
        )


def get_existing_doc(es, ip_address):
    try:
        result = es.get(index=INDEX_NAME, id=ip_address)
        return result["_source"]
    except Exception:
        return None


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

    abuse_score = safe_int(merged.get("abuse_confidence_score"), 0)
    otx_pulse_count = safe_int(merged.get("otx_pulse_count"), 0)
    passive_dns_count = safe_int(merged.get("otx_passive_dns_count"), 0)

    merged["risk_score"] = calculate_risk_score(
        abuse_score=abuse_score,
        otx_pulse_count=otx_pulse_count,
        passive_dns_count=passive_dns_count,
    )
    merged["status"] = derive_status(merged["risk_score"])

    attack_categories, attack_keywords_matched = derive_attack_categories(
        merged.get("otx_pulse_names", [])
    )
    merged["attack_categories"] = attack_categories
    merged["attack_keywords_matched"] = attack_keywords_matched

    now = utc_now()
    merged["last_merged_at"] = now

    if not merged.get("first_seen_at"):
        merged["first_seen_at"] = now

    if not merged.get("profile_source"):
        merged["profile_source"] = "pipeline"

    return merged


def build_actions(es, records):
    for record in records:
        record = enrich_geo_location(record)
        record["profile_source"] = record.get("profile_source", "pipeline")

        ip_address = record.get("ip_address")
        if not ip_address:
            continue

        existing_doc = get_existing_doc(es, ip_address)
        merged_doc = merge_ip_profile(existing_doc, record)

        yield {
            "_op_type": "index",
            "_index": INDEX_NAME,
            "_id": ip_address,
            "_source": merged_doc
        }


def main():
    es = Elasticsearch([ES_HOST])

    if not es.ping():
        raise Exception("Cannot connect to Elasticsearch")

    ensure_index_exists(es)

    records = load_records()
    if not records:
        print("No records found")
        return

    actions = list(build_actions(es, records))
    helpers.bulk(es, actions)

    print(f"Merged {len(actions)} records into index '{INDEX_NAME}'")


if __name__ == "__main__":
    main()