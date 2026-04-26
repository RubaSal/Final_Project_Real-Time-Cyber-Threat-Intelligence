# from fastapi import FastAPI, Query
# from fastapi.responses import HTMLResponse, JSONResponse
# from elasticsearch import Elasticsearch
# from dotenv import load_dotenv
# from datetime import datetime, timezone
# import psycopg2
# import os
# import ipaddress
# import requests

# load_dotenv()

# app = FastAPI(title="IP Lookup Service")

# ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
# MAIN_INDEX = os.getenv("ES_INDEX", "ip_profiles_enriched")
# KIBANA_DASHBOARD_URL = os.getenv(
#     "KIBANA_DASHBOARD_URL",
#     "http://localhost:5601/app/dashboards#/view/74091a80-3f60-11f1-967e-9317607609a3?embed=true"
# )

# # ---------- PostgreSQL ----------
# PG_HOST = os.getenv("PG_HOST", "localhost")
# PG_PORT = int(os.getenv("PG_PORT", "5432"))
# PG_DB = os.getenv("PG_DB", "cyber_threat_intelligence")
# PG_USER = os.getenv("PG_USER", "postgres")
# PG_PASSWORD = os.getenv("PG_PASSWORD", "postgres")
# PG_TABLE = os.getenv("PG_TABLE", "ip_profiles_enriched")

# GEOIP_API_KEY = os.getenv("GEOIP_API_KEY")
# ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")
# OTX_API_KEY = os.getenv("OTX_API_KEY")

# GEOIP_URL = "https://api.ipgeolocation.io/v3/ipgeo"
# ABUSE_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
# OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

# ATTACK_KEYWORDS = {
#     "Brute Force": [
#         "brute force", "bruteforce", "ssh", "telnet", "rdp", "login attempt"
#     ],
#     "Phishing": [
#         "phishing", "credential", "spoof", "email lure"
#     ],
#     "Botnet / C2": [
#         "botnet", "c2", "command and control", "cnc", "beacon"
#     ],
#     "Scanning": [
#         "scan", "scanner", "masscan", "zmap", "recon"
#     ],
#     "Malware": [
#         "malware", "trojan", "loader", "backdoor", "stealer"
#     ],
#     "Ransomware": [
#         "ransomware", "locker", "encryptor"
#     ],
#     "Exploitation": [
#         "exploit", "vulnerability", "rce", "remote code execution"
#     ]
# }


# def utc_now():
#     return datetime.now(timezone.utc).isoformat()


# def is_valid_ip(ip: str) -> bool:
#     try:
#         ipaddress.ip_address(ip)
#         return True
#     except ValueError:
#         return False


# def get_ip_version_path(ip: str) -> str:
#     ip_obj = ipaddress.ip_address(ip)
#     return "IPv4" if ip_obj.version == 4 else "IPv6"


# def get_es_client():
#     return Elasticsearch([ES_HOST])


# def get_pg_connection():
#     return psycopg2.connect(
#         host=PG_HOST,
#         port=PG_PORT,
#         dbname=PG_DB,
#         user=PG_USER,
#         password=PG_PASSWORD
#     )


# def ensure_pg_table(conn):
#     with conn.cursor() as cur:
#         cur.execute(f"""
#         CREATE TABLE IF NOT EXISTS {PG_TABLE} (
#             ip_address TEXT PRIMARY KEY,
#             abuse_confidence_score INTEGER,
#             abuse_country_code TEXT,
#             abuse_country_name TEXT,
#             abuse_last_reported_at TIMESTAMPTZ,
#             abuse_total_reports INTEGER,
#             otx_reputation BIGINT,
#             otx_pulse_count INTEGER,
#             otx_pulse_names TEXT[],
#             otx_passive_dns_count INTEGER,
#             otx_general_status TEXT,
#             otx_passive_dns_status TEXT,
#             geo_continent_name TEXT,
#             geo_country_code2 TEXT,
#             geo_country_name TEXT,
#             geo_state_province TEXT,
#             geo_city TEXT,
#             geo_latitude DOUBLE PRECISION,
#             geo_longitude DOUBLE PRECISION,
#             geo_is_eu BOOLEAN,
#             geo_asn_number TEXT,
#             geo_asn_organization TEXT,
#             geo_asn_country TEXT,
#             geo_timezone_name TEXT,
#             geo_timezone_offset DOUBLE PRECISION,
#             risk_score DOUBLE PRECISION,
#             status TEXT,
#             attack_categories TEXT[],
#             attack_keywords_matched TEXT[],
#             profile_source TEXT,
#             first_seen_at TIMESTAMPTZ,
#             last_merged_at TIMESTAMPTZ,
#             enriched_at TIMESTAMPTZ
#         )
#         """)
#     conn.commit()


# def upsert_profile_to_postgres(profile: dict):
#     conn = get_pg_connection()
#     try:
#         ensure_pg_table(conn)

#         with conn.cursor() as cur:
#             cur.execute(f"""
#             INSERT INTO {PG_TABLE} (
#                 ip_address,
#                 abuse_confidence_score,
#                 abuse_country_code,
#                 abuse_country_name,
#                 abuse_last_reported_at,
#                 abuse_total_reports,
#                 otx_reputation,
#                 otx_pulse_count,
#                 otx_pulse_names,
#                 otx_passive_dns_count,
#                 otx_general_status,
#                 otx_passive_dns_status,
#                 geo_continent_name,
#                 geo_country_code2,
#                 geo_country_name,
#                 geo_state_province,
#                 geo_city,
#                 geo_latitude,
#                 geo_longitude,
#                 geo_is_eu,
#                 geo_asn_number,
#                 geo_asn_organization,
#                 geo_asn_country,
#                 geo_timezone_name,
#                 geo_timezone_offset,
#                 risk_score,
#                 status,
#                 attack_categories,
#                 attack_keywords_matched,
#                 profile_source,
#                 first_seen_at,
#                 last_merged_at,
#                 enriched_at
#             )
#             VALUES (
#                 %(ip_address)s,
#                 %(abuse_confidence_score)s,
#                 %(abuse_country_code)s,
#                 %(abuse_country_name)s,
#                 %(abuse_last_reported_at)s,
#                 %(abuse_total_reports)s,
#                 %(otx_reputation)s,
#                 %(otx_pulse_count)s,
#                 %(otx_pulse_names)s,
#                 %(otx_passive_dns_count)s,
#                 %(otx_general_status)s,
#                 %(otx_passive_dns_status)s,
#                 %(geo_continent_name)s,
#                 %(geo_country_code2)s,
#                 %(geo_country_name)s,
#                 %(geo_state_province)s,
#                 %(geo_city)s,
#                 %(geo_latitude)s,
#                 %(geo_longitude)s,
#                 %(geo_is_eu)s,
#                 %(geo_asn_number)s,
#                 %(geo_asn_organization)s,
#                 %(geo_asn_country)s,
#                 %(geo_timezone_name)s,
#                 %(geo_timezone_offset)s,
#                 %(risk_score)s,
#                 %(status)s,
#                 %(attack_categories)s,
#                 %(attack_keywords_matched)s,
#                 %(profile_source)s,
#                 %(first_seen_at)s,
#                 %(last_merged_at)s,
#                 %(enriched_at)s
#             )
#             ON CONFLICT (ip_address) DO UPDATE SET
#                 abuse_confidence_score = COALESCE(EXCLUDED.abuse_confidence_score, {PG_TABLE}.abuse_confidence_score),
#                 abuse_country_code = COALESCE(EXCLUDED.abuse_country_code, {PG_TABLE}.abuse_country_code),
#                 abuse_country_name = COALESCE(EXCLUDED.abuse_country_name, {PG_TABLE}.abuse_country_name),
#                 abuse_last_reported_at = COALESCE(EXCLUDED.abuse_last_reported_at, {PG_TABLE}.abuse_last_reported_at),
#                 abuse_total_reports = COALESCE(EXCLUDED.abuse_total_reports, {PG_TABLE}.abuse_total_reports),
#                 otx_reputation = COALESCE(EXCLUDED.otx_reputation, {PG_TABLE}.otx_reputation),
#                 otx_pulse_count = COALESCE(EXCLUDED.otx_pulse_count, {PG_TABLE}.otx_pulse_count),
#                 otx_pulse_names = COALESCE(EXCLUDED.otx_pulse_names, {PG_TABLE}.otx_pulse_names),
#                 otx_passive_dns_count = COALESCE(EXCLUDED.otx_passive_dns_count, {PG_TABLE}.otx_passive_dns_count),
#                 otx_general_status = COALESCE(EXCLUDED.otx_general_status, {PG_TABLE}.otx_general_status),
#                 otx_passive_dns_status = COALESCE(EXCLUDED.otx_passive_dns_status, {PG_TABLE}.otx_passive_dns_status),
#                 geo_continent_name = COALESCE(EXCLUDED.geo_continent_name, {PG_TABLE}.geo_continent_name),
#                 geo_country_code2 = COALESCE(EXCLUDED.geo_country_code2, {PG_TABLE}.geo_country_code2),
#                 geo_country_name = COALESCE(EXCLUDED.geo_country_name, {PG_TABLE}.geo_country_name),
#                 geo_state_province = COALESCE(EXCLUDED.geo_state_province, {PG_TABLE}.geo_state_province),
#                 geo_city = COALESCE(EXCLUDED.geo_city, {PG_TABLE}.geo_city),
#                 geo_latitude = COALESCE(EXCLUDED.geo_latitude, {PG_TABLE}.geo_latitude),
#                 geo_longitude = COALESCE(EXCLUDED.geo_longitude, {PG_TABLE}.geo_longitude),
#                 geo_is_eu = COALESCE(EXCLUDED.geo_is_eu, {PG_TABLE}.geo_is_eu),
#                 geo_asn_number = COALESCE(EXCLUDED.geo_asn_number, {PG_TABLE}.geo_asn_number),
#                 geo_asn_organization = COALESCE(EXCLUDED.geo_asn_organization, {PG_TABLE}.geo_asn_organization),
#                 geo_asn_country = COALESCE(EXCLUDED.geo_asn_country, {PG_TABLE}.geo_asn_country),
#                 geo_timezone_name = COALESCE(EXCLUDED.geo_timezone_name, {PG_TABLE}.geo_timezone_name),
#                 geo_timezone_offset = COALESCE(EXCLUDED.geo_timezone_offset, {PG_TABLE}.geo_timezone_offset),
#                 risk_score = EXCLUDED.risk_score,
#                 status = EXCLUDED.status,
#                 attack_categories = EXCLUDED.attack_categories,
#                 attack_keywords_matched = EXCLUDED.attack_keywords_matched,
#                 profile_source = COALESCE(EXCLUDED.profile_source, {PG_TABLE}.profile_source),
#                 first_seen_at = COALESCE({PG_TABLE}.first_seen_at, EXCLUDED.first_seen_at),
#                 last_merged_at = EXCLUDED.last_merged_at,
#                 enriched_at = COALESCE(EXCLUDED.enriched_at, {PG_TABLE}.enriched_at)
#             """, profile)

#         conn.commit()
#     finally:
#         conn.close()


# def ensure_main_index_exists(es: Elasticsearch):
#     if es.indices.exists(index=MAIN_INDEX):
#         return

#     mapping = {
#         "mappings": {
#             "properties": {
#                 "ip_address": {"type": "keyword"},
#                 "abuse_confidence_score": {"type": "integer"},
#                 "abuse_total_reports": {"type": "integer"},
#                 "abuse_country_code": {"type": "keyword"},
#                 "abuse_country_name": {"type": "keyword"},
#                 "abuse_last_reported_at": {"type": "date"},
#                 "otx_reputation": {"type": "long"},
#                 "otx_pulse_count": {"type": "integer"},
#                 "otx_pulse_names": {"type": "keyword"},
#                 "otx_passive_dns_count": {"type": "integer"},
#                 "otx_general_status": {"type": "keyword"},
#                 "otx_passive_dns_status": {"type": "keyword"},
#                 "geo_continent_name": {"type": "keyword"},
#                 "geo_country_code2": {"type": "keyword"},
#                 "geo_country_name": {"type": "keyword"},
#                 "geo_state_province": {"type": "keyword"},
#                 "geo_city": {"type": "keyword"},
#                 "geo_latitude": {"type": "float"},
#                 "geo_longitude": {"type": "float"},
#                 "geo_is_eu": {"type": "boolean"},
#                 "geo_asn_number": {"type": "keyword"},
#                 "geo_asn_organization": {"type": "keyword"},
#                 "geo_asn_country": {"type": "keyword"},
#                 "geo_timezone_name": {"type": "keyword"},
#                 "geo_timezone_offset": {"type": "float"},
#                 "risk_score": {"type": "float"},
#                 "status": {"type": "keyword"},
#                 "profile_source": {"type": "keyword"},
#                 "attack_categories": {"type": "keyword"},
#                 "attack_keywords_matched": {"type": "keyword"},
#                 "enriched_at": {"type": "date"},
#                 "first_seen_at": {"type": "date"},
#                 "last_merged_at": {"type": "date"},
#                 "geo_location": {"type": "geo_point"}
#             }
#         }
#     }

#     es.indices.create(index=MAIN_INDEX, body=mapping)


# def search_ip_in_main_index(es: Elasticsearch, ip: str):
#     query = {
#         "query": {
#             "term": {
#                 "ip_address": ip
#             }
#         },
#         "size": 1
#     }

#     result = es.search(index=MAIN_INDEX, body=query)
#     hits = result.get("hits", {}).get("hits", [])
#     if not hits:
#         return None

#     return hits[0]["_source"]


# def geoip_lookup(ip: str):
#     if not GEOIP_API_KEY:
#         return {}

#     try:
#         response = requests.get(
#             GEOIP_URL,
#             params={"apiKey": GEOIP_API_KEY, "ip": ip},
#             timeout=20
#         )
#         response.raise_for_status()
#         return response.json()
#     except Exception:
#         return {}


# def abuseipdb_lookup(ip: str):
#     if not ABUSE_API_KEY:
#         return {}

#     headers = {
#         "Key": ABUSE_API_KEY,
#         "Accept": "application/json"
#     }

#     params = {
#         "ipAddress": ip,
#         "maxAgeInDays": 90
#     }

#     try:
#         response = requests.get(
#             ABUSE_CHECK_URL,
#             headers=headers,
#             params=params,
#             timeout=20
#         )
#         response.raise_for_status()
#         return response.json().get("data", {})
#     except Exception:
#         return {}


# def otx_get(session: requests.Session, path: str):
#     try:
#         response = session.get(path, timeout=25)
#         response.raise_for_status()
#         return response.json()
#     except Exception:
#         return {}


# def otx_lookup(ip: str):
#     if not OTX_API_KEY:
#         return {}

#     try:
#         version_path = get_ip_version_path(ip)
#     except ValueError:
#         return {}

#     session = requests.Session()
#     session.headers.update({
#         "X-OTX-API-KEY": OTX_API_KEY,
#         "Accept": "application/json"
#     })

#     general = otx_get(session, f"{OTX_BASE_URL}/indicators/{version_path}/{ip}/general")
#     passive_dns = otx_get(session, f"{OTX_BASE_URL}/indicators/{version_path}/{ip}/passive_dns")

#     pulses = general.get("pulse_info", {}).get("pulses", []) if isinstance(general, dict) else []
#     passive_dns_records = passive_dns.get("passive_dns", []) if isinstance(passive_dns, dict) else []

#     return {
#         "otx_reputation": general.get("reputation") if isinstance(general, dict) else None,
#         "otx_pulse_count": len(pulses),
#         "otx_pulse_names": [p.get("name") for p in pulses if p.get("name")],
#         "otx_passive_dns_count": len(passive_dns_records),
#         "otx_general_status": "ok" if general else "unavailable",
#         "otx_passive_dns_status": "ok" if passive_dns else "unavailable"
#     }


# def safe_float(value):
#     try:
#         if value is None:
#             return None
#         return float(value)
#     except Exception:
#         return None


# def safe_int(value, default=0):
#     try:
#         if value is None:
#             return default
#         return int(value)
#     except Exception:
#         return default


# def calculate_risk_score(abuse_score: int, otx_pulse_count: int, passive_dns_count: int) -> float:
#     score = 0.0
#     score += min(abuse_score, 100) * 0.7
#     score += min(otx_pulse_count, 20) * 1.2
#     score += min(passive_dns_count, 10) * 0.6
#     return round(min(score, 100), 2)


# def derive_status(risk_score: float) -> str:
#     if risk_score >= 80:
#         return "High Risk"
#     if risk_score >= 40:
#         return "Medium Risk"
#     return "Low Risk"


# def derive_attack_categories(otx_pulse_names):
#     if not otx_pulse_names:
#         return [], []

#     if isinstance(otx_pulse_names, str):
#         pulse_text = otx_pulse_names.lower()
#     else:
#         pulse_text = " | ".join(str(x).lower() for x in otx_pulse_names if x)

#     matched_categories = set()
#     matched_keywords = set()

#     for category, keywords in ATTACK_KEYWORDS.items():
#         for keyword in keywords:
#             if keyword in pulse_text:
#                 matched_categories.add(category)
#                 matched_keywords.add(keyword)

#     return sorted(matched_categories), sorted(matched_keywords)


# def enrich_computed_fields(profile: dict):
#     abuse_score = safe_int(profile.get("abuse_confidence_score"), 0)
#     otx_pulse_count = safe_int(profile.get("otx_pulse_count"), 0)
#     passive_dns_count = safe_int(profile.get("otx_passive_dns_count"), 0)

#     profile["risk_score"] = calculate_risk_score(
#         abuse_score=abuse_score,
#         otx_pulse_count=otx_pulse_count,
#         passive_dns_count=passive_dns_count
#     )
#     profile["status"] = derive_status(profile["risk_score"])

#     attack_categories, attack_keywords_matched = derive_attack_categories(
#         profile.get("otx_pulse_names", [])
#     )
#     profile["attack_categories"] = attack_categories
#     profile["attack_keywords_matched"] = attack_keywords_matched

#     if not profile.get("first_seen_at"):
#         profile["first_seen_at"] = utc_now()

#     profile["last_merged_at"] = utc_now()

#     return profile


# def build_live_profile(ip: str, geoip_data: dict, abuse_data: dict, otx_data: dict):
#     location = geoip_data.get("location", {})
#     asn = geoip_data.get("asn", {})
#     time_zone = geoip_data.get("time_zone", {})

#     profile = {
#         "ip_address": ip,
#         "abuse_confidence_score": abuse_data.get("abuseConfidenceScore", 0) or 0,
#         "abuse_country_code": abuse_data.get("countryCode"),
#         "abuse_country_name": abuse_data.get("countryName"),
#         "abuse_last_reported_at": abuse_data.get("lastReportedAt"),
#         "abuse_total_reports": abuse_data.get("totalReports", 0) or 0,
#         "otx_reputation": otx_data.get("otx_reputation"),
#         "otx_pulse_count": otx_data.get("otx_pulse_count", 0) or 0,
#         "otx_pulse_names": otx_data.get("otx_pulse_names", []),
#         "otx_passive_dns_count": otx_data.get("otx_passive_dns_count", 0) or 0,
#         "otx_general_status": otx_data.get("otx_general_status"),
#         "otx_passive_dns_status": otx_data.get("otx_passive_dns_status"),
#         "geo_continent_name": location.get("continent_name"),
#         "geo_country_code2": location.get("country_code2"),
#         "geo_country_name": location.get("country_name"),
#         "geo_state_province": location.get("state_prov"),
#         "geo_city": location.get("city"),
#         "geo_latitude": safe_float(location.get("latitude")),
#         "geo_longitude": safe_float(location.get("longitude")),
#         "geo_is_eu": location.get("is_eu"),
#         "geo_asn_number": asn.get("as_number"),
#         "geo_asn_organization": asn.get("organization"),
#         "geo_asn_country": asn.get("country"),
#         "geo_timezone_name": time_zone.get("name"),
#         "geo_timezone_offset": time_zone.get("offset"),
#         "enriched_at": utc_now(),
#         "profile_source": "live_lookup"
#     }

#     if profile["geo_latitude"] is not None and profile["geo_longitude"] is not None:
#         profile["geo_location"] = {
#             "lat": profile["geo_latitude"],
#             "lon": profile["geo_longitude"]
#         }

#     return enrich_computed_fields(profile)


# def save_profile_to_main_index(es: Elasticsearch, profile: dict):
#     es.index(
#         index=MAIN_INDEX,
#         id=profile["ip_address"],
#         body=profile
#     )


# def save_profile(profile: dict):
#     es = get_es_client()
#     save_profile_to_main_index(es, profile)
#     upsert_profile_to_postgres(profile)


# @app.get("/api/lookup")
# def lookup_ip(ip: str = Query(..., description="IPv4 or IPv6 address")):
#     if not is_valid_ip(ip):
#         return JSONResponse(status_code=400, content={"error": "Invalid IP address"})

#     es = get_es_client()
#     if not es.ping():
#         return JSONResponse(status_code=500, content={"error": "Cannot connect to Elasticsearch"})

#     ensure_main_index_exists(es)

#     existing_doc = search_ip_in_main_index(es, ip)
#     if existing_doc:
#         needs_update = (
#             "attack_categories" not in existing_doc or
#             "attack_keywords_matched" not in existing_doc or
#             "risk_score" not in existing_doc or
#             "status" not in existing_doc
#         )

#         if needs_update:
#             existing_doc = enrich_computed_fields(existing_doc)

#         save_profile(existing_doc)
#         return existing_doc

#     geoip_data = geoip_lookup(ip)
#     abuse_data = abuseipdb_lookup(ip)
#     otx_data = otx_lookup(ip)

#     profile = build_live_profile(ip, geoip_data, abuse_data, otx_data)
#     save_profile(profile)

#     return profile


# @app.get("/", response_class=HTMLResponse)
# def home():
#     html = """
#     <!DOCTYPE html>
#     <html>
#     <head>
#         <meta charset="utf-8"/>
#         <title>IP Lookup</title>
#         <style>
#             :root {
#                 --bg: #0b0f14;
#                 --panel: #131a24;
#                 --panel-2: #1a2332;
#                 --border: #2a3441;
#                 --text: #e5e7eb;
#                 --muted: #9ca3af;
#                 --accent: #1ea7fd;
#                 --accent-hover: #3bb3ff;
#                 --success: #22c55e;
#                 --warning: #f59e0b;
#                 --danger: #ef4444;
#                 --input-bg: #0f1722;
#             }

#             * {
#                 box-sizing: border-box;
#             }

#             body {
#                 font-family: Inter, Arial, sans-serif;
#                 margin: 0;
#                 background: var(--bg);
#                 color: var(--text);
#             }

#             .page {
#                 padding: 20px;
#                 background: var(--bg);
#             }

#             .dashboard-card {
#                 background: var(--panel);
#                 border: 1px solid var(--border);
#                 border-radius: 14px;
#                 box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
#                 overflow: hidden;
#                 margin-bottom: 20px;
#             }

#             .dashboard-header {
#                 display: flex;
#                 justify-content: space-between;
#                 align-items: center;
#                 padding: 16px 20px;
#                 border-bottom: 1px solid var(--border);
#                 background: var(--panel-2);
#             }

#             .dashboard-title {
#                 font-size: 20px;
#                 font-weight: 700;
#                 color: var(--text);
#             }

#             .dashboard-header a {
#                 color: var(--accent);
#                 text-decoration: none;
#                 font-size: 14px;
#                 font-weight: 600;
#             }

#             .dashboard-header a:hover {
#                 color: var(--accent-hover);
#             }

#             iframe {
#                 width: 100%;
#                 height: 1100px;
#                 border: none;
#                 background: #0b0f14;
#             }

#             .lookup-card {
#                 background: var(--panel);
#                 border: 1px solid var(--border);
#                 padding: 24px;
#                 border-radius: 14px;
#                 box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
#                 max-width: 980px;
#             }

#             .lookup-title {
#                 margin: 0 0 16px 0;
#                 font-size: 24px;
#                 font-weight: 700;
#                 color: var(--text);
#             }

#             .lookup-controls {
#                 display: flex;
#                 gap: 10px;
#                 flex-wrap: wrap;
#                 align-items: center;
#                 margin-bottom: 12px;
#             }

#             input {
#                 width: 360px;
#                 max-width: 100%;
#                 padding: 12px 14px;
#                 font-size: 15px;
#                 color: var(--text);
#                 background: var(--input-bg);
#                 border: 1px solid var(--border);
#                 border-radius: 10px;
#                 outline: none;
#             }

#             input::placeholder {
#                 color: #6b7280;
#             }

#             input:focus {
#                 border-color: var(--accent);
#                 box-shadow: 0 0 0 3px rgba(30, 167, 253, 0.15);
#             }

#             button {
#                 padding: 12px 16px;
#                 font-size: 14px;
#                 font-weight: 600;
#                 cursor: pointer;
#                 border: none;
#                 border-radius: 10px;
#                 transition: 0.2s ease;
#             }

#             .primary-btn {
#                 background: var(--accent);
#                 color: white;
#             }

#             .primary-btn:hover {
#                 background: var(--accent-hover);
#             }

#             .secondary-btn {
#                 background: #1f2937;
#                 color: var(--text);
#                 border: 1px solid var(--border);
#             }

#             .secondary-btn:hover {
#                 background: #273244;
#             }

#             .muted {
#                 color: var(--muted);
#                 margin-top: 8px;
#                 font-size: 14px;
#             }

#             hr {
#                 border: none;
#                 border-top: 1px solid var(--border);
#                 margin: 18px 0;
#             }

#             .result-card {
#                 background: #101722;
#                 border: 1px solid var(--border);
#                 border-radius: 12px;
#                 padding: 18px 20px;
#             }

#             .result-grid {
#                 display: grid;
#                 grid-template-columns: 220px 1fr;
#                 gap: 12px 24px;
#             }

#             .label {
#                 font-weight: 700;
#                 color: #cbd5e1;
#             }

#             .value {
#                 color: var(--text);
#                 word-break: break-word;
#             }

#             .status-badge {
#                 display: inline-block;
#                 padding: 6px 10px;
#                 border-radius: 999px;
#                 font-size: 13px;
#                 font-weight: 700;
#             }

#             .status-low {
#                 background: rgba(34, 197, 94, 0.15);
#                 color: #86efac;
#                 border: 1px solid rgba(34, 197, 94, 0.35);
#             }

#             .status-medium {
#                 background: rgba(245, 158, 11, 0.15);
#                 color: #fcd34d;
#                 border: 1px solid rgba(245, 158, 11, 0.35);
#             }

#             .status-high {
#                 background: rgba(239, 68, 68, 0.15);
#                 color: #fca5a5;
#                 border: 1px solid rgba(239, 68, 68, 0.35);
#             }

#             .loading {
#                 color: var(--accent);
#                 font-weight: 600;
#             }

#             .error {
#                 color: #fca5a5;
#                 margin-top: 12px;
#                 background: rgba(239, 68, 68, 0.12);
#                 border: 1px solid rgba(239, 68, 68, 0.28);
#                 padding: 12px 14px;
#                 border-radius: 10px;
#             }
#         </style>
#     </head>
#     <body>
#         <div class="page">

#             <div class="dashboard-card">
#                 <div class="dashboard-header">
#                     <div class="dashboard-title">Cyber Threat Intelligence Dashboard</div>
#                     <a href="__KIBANA_URL__" target="_blank">Open in Kibana</a>
#                 </div>
#                 <iframe id="kibanaFrame" src="__KIBANA_URL__"></iframe>
#             </div>

#             <div class="lookup-card">
#                 <h2 class="lookup-title">IP Lookup</h2>

#                 <div class="lookup-controls">
#                     <input id="ipInput" placeholder="Enter IP address" />
#                     <button class="primary-btn" onclick="lookupIp()">Search</button>
#                     <button class="secondary-btn" onclick="refreshDashboardFrame()">Refresh Dashboard</button>
#                 </div>

#                 <div class="muted">
#                     Searches ip_profiles_enriched first. If not found, performs live lookup and saves it back to the same index.
#                 </div>

#                 <hr/>
#                 <div id="result"></div>
#             </div>

#         </div>

#         <script>
#             function refreshDashboardFrame() {
#                 const frame = document.getElementById("kibanaFrame");
#                 const currentUrl = new URL(frame.src);
#                 currentUrl.searchParams.set("ts", Date.now());
#                 frame.src = currentUrl.toString();
#             }

#             function getStatusClass(status) {
#                 const s = (status || "").toLowerCase();
#                 if (s.includes("high")) return "status-badge status-high";
#                 if (s.includes("medium")) return "status-badge status-medium";
#                 return "status-badge status-low";
#             }

#             async function lookupIp() {
#                 const ip = document.getElementById("ipInput").value.trim();
#                 const resultDiv = document.getElementById("result");
#                 resultDiv.innerHTML = '<div class="loading">Loading...</div>';

#                 try {
#                     const response = await fetch(`/api/lookup?ip=${encodeURIComponent(ip)}`);
#                     const data = await response.json();

#                     if (!response.ok) {
#                         resultDiv.innerHTML = `<div class="error">${data.error || "Request failed"}</div>`;
#                         return;
#                     }

#                     const attackCategories = Array.isArray(data.attack_categories)
#                         ? data.attack_categories.join(", ")
#                         : (data.attack_categories ?? "None");

#                     const attackKeywords = Array.isArray(data.attack_keywords_matched)
#                         ? data.attack_keywords_matched.join(", ")
#                         : (data.attack_keywords_matched ?? "None");

#                     const statusClass = getStatusClass(data.status);

#                     resultDiv.innerHTML = `
#                         <div class="result-card">
#                             <div class="result-grid">
#                                 <div class="label">IP Address</div>
#                                 <div class="value">${data.ip_address ?? ""}</div>

#                                 <div class="label">Country</div>
#                                 <div class="value">${data.geo_country_name ?? data.abuse_country_name ?? "Unknown"}</div>

#                                 <div class="label">City</div>
#                                 <div class="value">${data.geo_city ?? "Unknown"}</div>

#                                 <div class="label">ASN / Organization</div>
#                                 <div class="value">${data.geo_asn_organization ?? "Unknown"}</div>

#                                 <div class="label">Abuse Confidence Score</div>
#                                 <div class="value">${data.abuse_confidence_score ?? 0}</div>

#                                 <div class="label">OTX Pulse Count</div>
#                                 <div class="value">${data.otx_pulse_count ?? 0}</div>

#                                 <div class="label">Passive DNS Count</div>
#                                 <div class="value">${data.otx_passive_dns_count ?? 0}</div>

#                                 <div class="label">Risk Score</div>
#                                 <div class="value">${data.risk_score ?? 0}</div>

#                                 <div class="label">Status</div>
#                                 <div class="value"><span class="${statusClass}">${data.status ?? "Low Risk"}</span></div>

#                                 <div class="label">Attack Categories</div>
#                                 <div class="value">${attackCategories}</div>

#                                 <div class="label">Matched Keywords</div>
#                                 <div class="value">${attackKeywords}</div>

#                                 <div class="label">Profile Source</div>
#                                 <div class="value">${data.profile_source ?? "pipeline"}</div>
#                             </div>
#                         </div>
#                     `;

#                     refreshDashboardFrame();
#                 } catch (err) {
#                     resultDiv.innerHTML = `<div class="error">Unexpected error</div>`;
#                 }
#             }
#         </script>
#     </body>
#     </html>
#     """
#     return html.replace("__KIBANA_URL__", KIBANA_DASHBOARD_URL)


from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse, JSONResponse
from elasticsearch import Elasticsearch
from dotenv import load_dotenv
from datetime import datetime, timezone
import psycopg2
import os
import ipaddress
import requests

load_dotenv()

app = FastAPI(title="IP Lookup Service")

ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
MAIN_INDEX = os.getenv("ES_INDEX", "ip_profiles_enriched")
KIBANA_DASHBOARD_URL = os.getenv(
    "KIBANA_DASHBOARD_URL",
    "http://localhost:5601/app/dashboards#/view/74091a80-3f60-11f1-967e-9317607609a3?embed=true"
)

# ---------- PostgreSQL ----------
PG_HOST = os.getenv("PG_HOST", "localhost")
PG_PORT = int(os.getenv("PG_PORT", "5432"))
PG_DB = os.getenv("PG_DB", "cyber_threat_intelligence")
PG_USER = os.getenv("PG_USER", "postgres")
PG_PASSWORD = os.getenv("PG_PASSWORD", "postgres")
PG_TABLE = os.getenv("PG_TABLE", "ip_profiles_enriched")

GEOIP_API_KEY = os.getenv("GEOIP_API_KEY")
ABUSE_API_KEY = os.getenv("ABUSE_API_KEY")
OTX_API_KEY = os.getenv("OTX_API_KEY")

GEOIP_URL = "https://api.ipgeolocation.io/v3/ipgeo"
ABUSE_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
OTX_BASE_URL = "https://otx.alienvault.com/api/v1"

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


def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def get_ip_version_path(ip: str) -> str:
    ip_obj = ipaddress.ip_address(ip)
    return "IPv4" if ip_obj.version == 4 else "IPv6"


def get_es_client():
    return Elasticsearch([ES_HOST])


def get_pg_connection():
    return psycopg2.connect(
        host=PG_HOST,
        port=PG_PORT,
        dbname=PG_DB,
        user=PG_USER,
        password=PG_PASSWORD
    )


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
            otx_reputation BIGINT,
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
    conn.commit()


def upsert_profile_to_postgres(profile: dict):
    conn = get_pg_connection()
    try:
        ensure_pg_table(conn)

        with conn.cursor() as cur:
            cur.execute(f"""
            INSERT INTO {PG_TABLE} (
                ip_address,
                abuse_confidence_score,
                abuse_country_code,
                abuse_country_name,
                abuse_last_reported_at,
                abuse_total_reports,
                otx_reputation,
                otx_pulse_count,
                otx_pulse_names,
                otx_passive_dns_count,
                otx_general_status,
                otx_passive_dns_status,
                geo_continent_name,
                geo_country_code2,
                geo_country_name,
                geo_state_province,
                geo_city,
                geo_latitude,
                geo_longitude,
                geo_is_eu,
                geo_asn_number,
                geo_asn_organization,
                geo_asn_country,
                geo_timezone_name,
                geo_timezone_offset,
                risk_score,
                status,
                attack_categories,
                attack_keywords_matched,
                profile_source,
                first_seen_at,
                last_merged_at,
                enriched_at
            )
            VALUES (
                %(ip_address)s,
                %(abuse_confidence_score)s,
                %(abuse_country_code)s,
                %(abuse_country_name)s,
                %(abuse_last_reported_at)s,
                %(abuse_total_reports)s,
                %(otx_reputation)s,
                %(otx_pulse_count)s,
                %(otx_pulse_names)s,
                %(otx_passive_dns_count)s,
                %(otx_general_status)s,
                %(otx_passive_dns_status)s,
                %(geo_continent_name)s,
                %(geo_country_code2)s,
                %(geo_country_name)s,
                %(geo_state_province)s,
                %(geo_city)s,
                %(geo_latitude)s,
                %(geo_longitude)s,
                %(geo_is_eu)s,
                %(geo_asn_number)s,
                %(geo_asn_organization)s,
                %(geo_asn_country)s,
                %(geo_timezone_name)s,
                %(geo_timezone_offset)s,
                %(risk_score)s,
                %(status)s,
                %(attack_categories)s,
                %(attack_keywords_matched)s,
                %(profile_source)s,
                %(first_seen_at)s,
                %(last_merged_at)s,
                %(enriched_at)s
            )
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
                enriched_at = COALESCE(EXCLUDED.enriched_at, {PG_TABLE}.enriched_at)
            """, profile)

        conn.commit()
    finally:
        conn.close()


def ensure_main_index_exists(es: Elasticsearch):
    if es.indices.exists(index=MAIN_INDEX):
        return

    mapping = {
        "mappings": {
            "properties": {
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
                "profile_source": {"type": "keyword"},
                "attack_categories": {"type": "keyword"},
                "attack_keywords_matched": {"type": "keyword"},
                "enriched_at": {"type": "date"},
                "first_seen_at": {"type": "date"},
                "last_merged_at": {"type": "date"},
                "geo_location": {"type": "geo_point"}
            }
        }
    }

    es.indices.create(index=MAIN_INDEX, body=mapping)


def search_ip_in_main_index(es: Elasticsearch, ip: str):
    query = {
        "query": {
            "term": {
                "ip_address": ip
            }
        },
        "size": 1
    }

    result = es.search(index=MAIN_INDEX, body=query)
    hits = result.get("hits", {}).get("hits", [])
    if not hits:
        return None

    return hits[0]["_source"]


def geoip_lookup(ip: str):
    if not GEOIP_API_KEY:
        return {}

    try:
        response = requests.get(
            GEOIP_URL,
            params={"apiKey": GEOIP_API_KEY, "ip": ip},
            timeout=20
        )
        response.raise_for_status()
        return response.json()
    except Exception:
        return {}


def abuseipdb_lookup(ip: str):
    if not ABUSE_API_KEY:
        return {}

    headers = {
        "Key": ABUSE_API_KEY,
        "Accept": "application/json"
    }

    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        response = requests.get(
            ABUSE_CHECK_URL,
            headers=headers,
            params=params,
            timeout=20
        )
        response.raise_for_status()
        return response.json().get("data", {})
    except Exception:
        return {}


def otx_get(session: requests.Session, path: str):
    try:
        response = session.get(path, timeout=25)
        response.raise_for_status()
        return response.json()
    except Exception:
        return {}


def otx_lookup(ip: str):
    if not OTX_API_KEY:
        return {}

    try:
        version_path = get_ip_version_path(ip)
    except ValueError:
        return {}

    session = requests.Session()
    session.headers.update({
        "X-OTX-API-KEY": OTX_API_KEY,
        "Accept": "application/json"
    })

    general = otx_get(session, f"{OTX_BASE_URL}/indicators/{version_path}/{ip}/general")
    passive_dns = otx_get(session, f"{OTX_BASE_URL}/indicators/{version_path}/{ip}/passive_dns")

    pulses = general.get("pulse_info", {}).get("pulses", []) if isinstance(general, dict) else []
    passive_dns_records = passive_dns.get("passive_dns", []) if isinstance(passive_dns, dict) else []

    return {
        "otx_reputation": general.get("reputation") if isinstance(general, dict) else None,
        "otx_pulse_count": len(pulses),
        "otx_pulse_names": [p.get("name") for p in pulses if p.get("name")],
        "otx_passive_dns_count": len(passive_dns_records),
        "otx_general_status": "ok" if general else "unavailable",
        "otx_passive_dns_status": "ok" if passive_dns else "unavailable"
    }


def safe_float(value):
    try:
        if value is None:
            return None
        return float(value)
    except Exception:
        return None


def safe_int(value, default=0):
    try:
        if value is None:
            return default
        return int(float(value))
    except Exception:
        return default


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
    abuse_score: int,
    otx_pulse_count: int,
    passive_dns_count: int,
    attack_categories=None,
    attack_keywords=None
) -> float:
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

    if (
        "Exploitation" in categories_set
        or "rce" in keywords_set
        or "remote code execution" in keywords_set
    ):
        score = max(score, 70)

    if "Botnet / C2" in categories_set or "Ransomware" in categories_set:
        score = max(score, 80)

    if abuse_score >= 40 and attack_categories:
        score = max(score, 65)

    return round(min(score, 100), 2)


def derive_status(risk_score: float) -> str:
    if risk_score >= 70:
        return "High Risk"
    if risk_score >= 30:
        return "Medium Risk"
    return "Low Risk"


def enrich_computed_fields(profile: dict):
    attack_categories, attack_keywords_matched = derive_attack_categories(
        profile.get("otx_pulse_names", [])
    )

    profile["attack_categories"] = attack_categories
    profile["attack_keywords_matched"] = attack_keywords_matched

    abuse_score = safe_int(profile.get("abuse_confidence_score"), 0)
    otx_pulse_count = safe_int(profile.get("otx_pulse_count"), 0)
    passive_dns_count = safe_int(profile.get("otx_passive_dns_count"), 0)

    profile["risk_score"] = calculate_risk_score(
        abuse_score=abuse_score,
        otx_pulse_count=otx_pulse_count,
        passive_dns_count=passive_dns_count,
        attack_categories=attack_categories,
        attack_keywords=attack_keywords_matched
    )

    profile["status"] = derive_status(profile["risk_score"])

    if not profile.get("first_seen_at"):
        profile["first_seen_at"] = utc_now()

    profile["last_merged_at"] = utc_now()

    return profile


def build_live_profile(ip: str, geoip_data: dict, abuse_data: dict, otx_data: dict):
    location = geoip_data.get("location", {})
    asn = geoip_data.get("asn", {})
    time_zone = geoip_data.get("time_zone", {})

    profile = {
        "ip_address": ip,
        "abuse_confidence_score": abuse_data.get("abuseConfidenceScore", 0) or 0,
        "abuse_country_code": abuse_data.get("countryCode"),
        "abuse_country_name": abuse_data.get("countryName"),
        "abuse_last_reported_at": abuse_data.get("lastReportedAt"),
        "abuse_total_reports": abuse_data.get("totalReports", 0) or 0,
        "otx_reputation": otx_data.get("otx_reputation"),
        "otx_pulse_count": otx_data.get("otx_pulse_count", 0) or 0,
        "otx_pulse_names": otx_data.get("otx_pulse_names", []),
        "otx_passive_dns_count": otx_data.get("otx_passive_dns_count", 0) or 0,
        "otx_general_status": otx_data.get("otx_general_status"),
        "otx_passive_dns_status": otx_data.get("otx_passive_dns_status"),
        "geo_continent_name": location.get("continent_name"),
        "geo_country_code2": location.get("country_code2"),
        "geo_country_name": location.get("country_name"),
        "geo_state_province": location.get("state_prov"),
        "geo_city": location.get("city"),
        "geo_latitude": safe_float(location.get("latitude")),
        "geo_longitude": safe_float(location.get("longitude")),
        "geo_is_eu": location.get("is_eu"),
        "geo_asn_number": asn.get("as_number"),
        "geo_asn_organization": asn.get("organization"),
        "geo_asn_country": asn.get("country"),
        "geo_timezone_name": time_zone.get("name"),
        "geo_timezone_offset": time_zone.get("offset"),
        "enriched_at": utc_now(),
        "profile_source": "live_lookup"
    }

    if profile["geo_latitude"] is not None and profile["geo_longitude"] is not None:
        profile["geo_location"] = {
            "lat": profile["geo_latitude"],
            "lon": profile["geo_longitude"]
        }

    return enrich_computed_fields(profile)


def save_profile_to_main_index(es: Elasticsearch, profile: dict):
    es.index(
        index=MAIN_INDEX,
        id=profile["ip_address"],
        body=profile
    )


def save_profile(profile: dict):
    es = get_es_client()
    save_profile_to_main_index(es, profile)
    upsert_profile_to_postgres(profile)


@app.get("/api/lookup")
def lookup_ip(ip: str = Query(..., description="IPv4 or IPv6 address")):
    if not is_valid_ip(ip):
        return JSONResponse(status_code=400, content={"error": "Invalid IP address"})

    es = get_es_client()
    if not es.ping():
        return JSONResponse(status_code=500, content={"error": "Cannot connect to Elasticsearch"})

    ensure_main_index_exists(es)

    existing_doc = search_ip_in_main_index(es, ip)

    # Important:
    # Even if the IP already exists in Elasticsearch,
    # we recalculate risk_score, status, attack_categories and attack_keywords_matched
    # using the latest logic.
    if existing_doc:
        existing_doc = enrich_computed_fields(existing_doc)
        save_profile(existing_doc)
        return existing_doc

    geoip_data = geoip_lookup(ip)
    abuse_data = abuseipdb_lookup(ip)
    otx_data = otx_lookup(ip)

    profile = build_live_profile(ip, geoip_data, abuse_data, otx_data)
    save_profile(profile)

    return profile


@app.get("/", response_class=HTMLResponse)
def home():
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8"/>
        <title>IP Lookup</title>
        <style>
            :root {
                --bg: #0b0f14;
                --panel: #131a24;
                --panel-2: #1a2332;
                --border: #2a3441;
                --text: #e5e7eb;
                --muted: #9ca3af;
                --accent: #1ea7fd;
                --accent-hover: #3bb3ff;
                --success: #22c55e;
                --warning: #f59e0b;
                --danger: #ef4444;
                --input-bg: #0f1722;
            }

            * {
                box-sizing: border-box;
            }

            body {
                font-family: Inter, Arial, sans-serif;
                margin: 0;
                background: var(--bg);
                color: var(--text);
            }

            .page {
                padding: 20px;
                background: var(--bg);
            }

            .dashboard-card {
                background: var(--panel);
                border: 1px solid var(--border);
                border-radius: 14px;
                box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
                overflow: hidden;
                margin-bottom: 20px;
            }

            .dashboard-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                padding: 16px 20px;
                border-bottom: 1px solid var(--border);
                background: var(--panel-2);
            }

            .dashboard-title {
                font-size: 20px;
                font-weight: 700;
                color: var(--text);
            }

            .dashboard-header a {
                color: var(--accent);
                text-decoration: none;
                font-size: 14px;
                font-weight: 600;
            }

            .dashboard-header a:hover {
                color: var(--accent-hover);
            }

            iframe {
                width: 100%;
                height: 1100px;
                border: none;
                background: #0b0f14;
            }

            .lookup-card {
                background: var(--panel);
                border: 1px solid var(--border);
                padding: 24px;
                border-radius: 14px;
                box-shadow: 0 8px 24px rgba(0, 0, 0, 0.35);
                max-width: 980px;
            }

            .lookup-title {
                margin: 0 0 16px 0;
                font-size: 24px;
                font-weight: 700;
                color: var(--text);
            }

            .lookup-controls {
                display: flex;
                gap: 10px;
                flex-wrap: wrap;
                align-items: center;
                margin-bottom: 12px;
            }

            input {
                width: 360px;
                max-width: 100%;
                padding: 12px 14px;
                font-size: 15px;
                color: var(--text);
                background: var(--input-bg);
                border: 1px solid var(--border);
                border-radius: 10px;
                outline: none;
            }

            input::placeholder {
                color: #6b7280;
            }

            input:focus {
                border-color: var(--accent);
                box-shadow: 0 0 0 3px rgba(30, 167, 253, 0.15);
            }

            button {
                padding: 12px 16px;
                font-size: 14px;
                font-weight: 600;
                cursor: pointer;
                border: none;
                border-radius: 10px;
                transition: 0.2s ease;
            }

            .primary-btn {
                background: var(--accent);
                color: white;
            }

            .primary-btn:hover {
                background: var(--accent-hover);
            }

            .secondary-btn {
                background: #1f2937;
                color: var(--text);
                border: 1px solid var(--border);
            }

            .secondary-btn:hover {
                background: #273244;
            }

            .muted {
                color: var(--muted);
                margin-top: 8px;
                font-size: 14px;
            }

            hr {
                border: none;
                border-top: 1px solid var(--border);
                margin: 18px 0;
            }

            .result-card {
                background: #101722;
                border: 1px solid var(--border);
                border-radius: 12px;
                padding: 18px 20px;
            }

            .result-grid {
                display: grid;
                grid-template-columns: 220px 1fr;
                gap: 12px 24px;
            }

            .label {
                font-weight: 700;
                color: #cbd5e1;
            }

            .value {
                color: var(--text);
                word-break: break-word;
            }

            .status-badge {
                display: inline-block;
                padding: 6px 10px;
                border-radius: 999px;
                font-size: 13px;
                font-weight: 700;
            }

            .status-low {
                background: rgba(34, 197, 94, 0.15);
                color: #86efac;
                border: 1px solid rgba(34, 197, 94, 0.35);
            }

            .status-medium {
                background: rgba(245, 158, 11, 0.15);
                color: #fcd34d;
                border: 1px solid rgba(245, 158, 11, 0.35);
            }

            .status-high {
                background: rgba(239, 68, 68, 0.15);
                color: #fca5a5;
                border: 1px solid rgba(239, 68, 68, 0.35);
            }

            .loading {
                color: var(--accent);
                font-weight: 600;
            }

            .error {
                color: #fca5a5;
                margin-top: 12px;
                background: rgba(239, 68, 68, 0.12);
                border: 1px solid rgba(239, 68, 68, 0.28);
                padding: 12px 14px;
                border-radius: 10px;
            }
        </style>
    </head>
    <body>
        <div class="page">

            <div class="dashboard-card">
                <div class="dashboard-header">
                    <div class="dashboard-title">Cyber Threat Intelligence Dashboard</div>
                    <a href="__KIBANA_URL__" target="_blank">Open in Kibana</a>
                </div>
                <iframe id="kibanaFrame" src="__KIBANA_URL__"></iframe>
            </div>

            <div class="lookup-card">
                <h2 class="lookup-title">IP Lookup</h2>

                <div class="lookup-controls">
                    <input id="ipInput" placeholder="Enter IP address" />
                    <button class="primary-btn" onclick="lookupIp()">Search</button>
                    <button class="secondary-btn" onclick="refreshDashboardFrame()">Refresh Dashboard</button>
                </div>

                <div class="muted">
                    Searches ip_profiles_enriched first. If not found, performs live lookup and saves it back to the same index.
                </div>

                <hr/>
                <div id="result"></div>
            </div>

        </div>

        <script>
            function refreshDashboardFrame() {
                const frame = document.getElementById("kibanaFrame");
                const currentUrl = new URL(frame.src);
                currentUrl.searchParams.set("ts", Date.now());
                frame.src = currentUrl.toString();
            }

            function getStatusClass(status) {
                const s = (status || "").toLowerCase();
                if (s.includes("high")) return "status-badge status-high";
                if (s.includes("medium")) return "status-badge status-medium";
                return "status-badge status-low";
            }

            async function lookupIp() {
                const ip = document.getElementById("ipInput").value.trim();
                const resultDiv = document.getElementById("result");
                resultDiv.innerHTML = '<div class="loading">Loading...</div>';

                try {
                    const response = await fetch(`/api/lookup?ip=${encodeURIComponent(ip)}`);
                    const data = await response.json();

                    if (!response.ok) {
                        resultDiv.innerHTML = `<div class="error">${data.error || "Request failed"}</div>`;
                        return;
                    }

                    const attackCategories = Array.isArray(data.attack_categories)
                        ? data.attack_categories.join(", ")
                        : (data.attack_categories ?? "None");

                    const attackKeywords = Array.isArray(data.attack_keywords_matched)
                        ? data.attack_keywords_matched.join(", ")
                        : (data.attack_keywords_matched ?? "None");

                    const statusClass = getStatusClass(data.status);

                    resultDiv.innerHTML = `
                        <div class="result-card">
                            <div class="result-grid">
                                <div class="label">IP Address</div>
                                <div class="value">${data.ip_address ?? ""}</div>

                                <div class="label">Country</div>
                                <div class="value">${data.geo_country_name ?? data.abuse_country_name ?? "Unknown"}</div>

                                <div class="label">City</div>
                                <div class="value">${data.geo_city ?? "Unknown"}</div>

                                <div class="label">ASN / Organization</div>
                                <div class="value">${data.geo_asn_organization ?? "Unknown"}</div>

                                <div class="label">Abuse Confidence Score</div>
                                <div class="value">${data.abuse_confidence_score ?? 0}</div>

                                <div class="label">OTX Pulse Count</div>
                                <div class="value">${data.otx_pulse_count ?? 0}</div>

                                <div class="label">Passive DNS Count</div>
                                <div class="value">${data.otx_passive_dns_count ?? 0}</div>

                                <div class="label">Risk Score</div>
                                <div class="value">${data.risk_score ?? 0}</div>

                                <div class="label">Status</div>
                                <div class="value"><span class="${statusClass}">${data.status ?? "Low Risk"}</span></div>

                                <div class="label">Attack Categories</div>
                                <div class="value">${attackCategories}</div>

                                <div class="label">Matched Keywords</div>
                                <div class="value">${attackKeywords}</div>

                                <div class="label">Profile Source</div>
                                <div class="value">${data.profile_source ?? "pipeline"}</div>
                            </div>
                        </div>
                    `;

                    refreshDashboardFrame();
                } catch (err) {
                    resultDiv.innerHTML = `<div class="error">Unexpected error</div>`;
                }
            }
        </script>
    </body>
    </html>
    """
    return html.replace("__KIBANA_URL__", KIBANA_DASHBOARD_URL)