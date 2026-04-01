# Cyber Threat Intelligence Platform

## Project Overview
This project implements a cyber threat intelligence pipeline that collects, processes, enriches, stores, and orchestrates threat-related data from external APIs.

The main purpose of the system is to identify suspicious IP addresses, enrich them with geolocation data, and add broader cybersecurity context from security news sources.

The project is built as a modular pipeline and is designed to simulate a real-world cyber threat data flow.

---

## Business Goal
The business goal of this platform is to enable an organization to collect, process, and analyze cyber threat data from multiple external sources in order to identify high-risk IP addresses and improve the ability to detect patterns, anomalies, geographic trends, and broader cyber activity context in near real time.

A practical example is enriching suspicious IPs from a blacklist source with geolocation data, while also collecting cybersecurity news to provide broader visibility into current attack types, incidents, and threat trends.

---

## Project Architecture
The project architecture is based on the following logical flow:

1. **Data Collection**  
   Pull raw data from external APIs:
   - AbuseIPDB API
   - GeoIP API
   - Security News API

2. **Data Transformation**  
   Convert raw API responses into cleaner and flatter processed datasets.

3. **Data Enrichment**  
   Enrich suspicious IP addresses with geolocation information.

4. **Contextual Intelligence Layer**  
   Collect and process cybersecurity news as a broader contextual source for threat analysis.

5. **Storage Layer**  
   Store raw, processed, and enriched data in MinIO as a data lake.

6. **Streaming Layer**  
   Send enriched records through Kafka for near real-time processing.

7. **Orchestration Layer**  
   Use Airflow to orchestrate the pipeline and manage execution order.

---

## Data Sources

### 1. AbuseIPDB API
Used to retrieve suspicious / blacklisted IP addresses.

Example fields extracted:
- `ip_address`
- `country_code`
- `abuse_confidence_score`
- `last_reported_at`
- `ingestion_time`

### 2. GeoIP API
Used to retrieve geolocation and metadata about IP addresses.

Example fields extracted:
- `ip`
- `continent_name`
- `country_name`
- `state_province`
- `city`
- `latitude`
- `longitude`
- `currency_code`
- `languages`
- `ingestion_time`

### 3. Security News API
Used to retrieve cybersecurity-related news articles for broader threat context.

Example fields extracted:
- `source_name`
- `title`
- `description`
- `published_at`
- `attack_type`
- `mentioned_countries`
- `primary_geographic_context`
- `ingestion_time`

---

## Current Project Structure

```text
Cyber-Threat-Intelligence-Platform/
│
├── ingest_abuseipdb.py
├── transform_abuseipdb.py
├── ingest_geoip.py
├── transform_geoip.py
├── enrich_abuseipdb_with_geoip.py
├── ingest_security_news.py
├── transform_security_news.py
├── requirements.txt
├── .gitignore
├── .env
├── abuseipdb_raw.json
├── abuseipdb_processed.json
├── geoip_raw.json
├── geoip_processed.json
├── abuseipdb_geoip_enriched.json
├── abuseipdb_geoip_enrichment_errors.json
├── security_news_raw.json
├── security_news_processed.json
└── README.md
```

---

## Files Description

### 1. `ingest_abuseipdb.py`
Connects to the AbuseIPDB API and pulls raw blacklist data.  
The response is saved locally as:
- `abuseipdb_raw.json`

### 2. `transform_abuseipdb.py`
Reads the raw AbuseIPDB response and transforms it into a simplified processed dataset.  
The processed output is saved as:
- `abuseipdb_processed.json`

### 3. `ingest_geoip.py`
Connects to the GeoIP API and pulls geolocation data for an IP address.  
The response is saved locally as:
- `geoip_raw.json`

### 4. `transform_geoip.py`
Reads the raw GeoIP response and transforms it into a flatter processed structure.  
The processed output is saved as:
- `geoip_processed.json`

### 5. `enrich_abuseipdb_with_geoip.py`
Combines threat intelligence data from AbuseIPDB with geolocation context from the GeoIP API using the IP address as the join key.

The output is saved locally as:
- `abuseipdb_geoip_enriched.json`

Failed enrichment attempts are saved locally as:
- `abuseipdb_geoip_enrichment_errors.json`

### 6. `ingest_security_news.py`
Connects to the NewsAPI service and pulls cybersecurity-related news articles based on predefined security keywords.  
The response is saved locally as:
- `security_news_raw.json`

### 7. `transform_security_news.py`
Reads the raw security news response and transforms it into a simplified processed dataset containing the most relevant article fields, attack categories, and geographic context.  
The processed output is saved as:
- `security_news_processed.json`

---

## Environment Variables
Create a `.env` file in the project root directory and add the following variables:

```env
ABUSE_API_KEY=your_abuseipdb_api_key
GEOIP_API_KEY=your_geoip_api_key
SECURITY_NEWS_API_KEY=your_security_news_api_key
```

These variables are used to authenticate requests to the external APIs.

- `ABUSE_API_KEY` – API key for AbuseIPDB
- `GEOIP_API_KEY` – API key for the GeoIP service
- `SECURITY_NEWS_API_KEY` – API key for the Security News service

Additional variables for MinIO, Kafka, and Airflow may be added in later stages of the project.

---

## Installation

### 1. Clone the repository
```bash
git clone https://github.com/RubaSal/Final_Project_Real-Time-Cyber-Threat-Intelligence
cd Final_Project_Real-Time-Cyber-Threat-Intelligence
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Create a `.env` file
Create a `.env` file in the project root directory and add your actual API keys using the following format:

```env
ABUSE_API_KEY=your_actual_abuseipdb_api_key
GEOIP_API_KEY=your_actual_geoip_api_key
SECURITY_NEWS_API_KEY=your_actual_security_news_api_key
```

---

## How to Run the Current Pipeline

### Step 1 - Pull raw data from AbuseIPDB
```bash
python ingest_abuseipdb.py
```

### Step 2 - Transform AbuseIPDB data
```bash
python transform_abuseipdb.py
```

### Step 3 - Pull raw data from GeoIP
```bash
python ingest_geoip.py
```

### Step 4 - Transform GeoIP data
```bash
python transform_geoip.py
```

### Step 5 - Enrich AbuseIPDB data with GeoIP
```bash
python enrich_abuseipdb_with_geoip.py
```

### Step 6 - Pull raw security news data
```bash
python ingest_security_news.py
```

### Step 7 - Transform security news data
```bash
python transform_security_news.py
```

---

## Current Workflow
At the current stage, the project performs the following steps:

1. Pulls suspicious IP data from AbuseIPDB
2. Stores the raw AbuseIPDB response as JSON
3. Transforms AbuseIPDB data into a processed dataset
4. Pulls geolocation data from GeoIP API
5. Stores the raw GeoIP response as JSON
6. Transforms GeoIP data into a processed dataset
7. Enriches AbuseIPDB IP addresses with geolocation data from GeoIP
8. Saves the enriched output as a flat JSON dataset
9. Pulls cybersecurity-related news from the Security News API
10. Stores the raw security news response as JSON
11. Transforms security news data into a processed contextual intelligence dataset

---

## Enrichment Logic

### 1. IP Enrichment
The IP enrichment stage combines threat intelligence data from AbuseIPDB with geolocation context from the GeoIP API.

The two sources are joined using the IP address as the common key.

The final enriched output is a flat JSON structure that includes threat-related fields, geolocation fields, and pipeline timestamps for traceability and downstream processing.

Current output:
- `abuseipdb_geoip_enriched.json`

### 2. Contextual Security News Enrichment
Security News is not directly joined to the IP-level dataset.

Instead, it is used as a contextual intelligence source that complements the technical threat data.

While AbuseIPDB and GeoIP are directly joined using the IP address, Security News is correlated with the existing data through attack-related topics and geographic context, such as countries mentioned in cyber-related articles.

Current output:
- `security_news_processed.json`

---

## Planned Next Steps

### 1. MinIO Integration
Store raw, processed, enriched, and contextual datasets in MinIO as a data lake.

Planned logical folder structure:

```text
raw/abuseipdb/
processed/abuseipdb/
raw/geoip/
processed/geoip/
enriched/
raw/security_news/
processed/security_news/
```

### 2. Kafka Streaming
Send enriched records into Kafka for near real-time streaming and downstream consumption.

### 3. Airflow Orchestration
Create an Airflow DAG to orchestrate the pipeline execution order.

Expected DAG flow:

```text
ingest_abuseipdb
    -> transform_abuseipdb
    -> enrich_with_geoip
    -> upload_to_minio
    -> send_to_kafka
```

A separate contextual flow may also be added for security news ingestion and transformation.

---

## Why This Architecture
This architecture separates responsibilities into different layers:

- API ingestion for collecting external data
- Transformation for cleaning and structuring data
- IP-level enrichment for combining AbuseIPDB and GeoIP data
- Contextual intelligence processing for cybersecurity news
- MinIO for centralized storage and data lake management
- Kafka for streaming data between pipeline components
- Airflow for orchestration and scheduling

This approach makes the project modular, scalable, and easier to extend.

---

## Technologies Used
- Python
- Requests
- python-dotenv
- JSON
- GitHub
- NewsAPI

### Planned / upcoming technologies
- MinIO
- Kafka
- Airflow

---

## Output Datasets

### Raw datasets
- `abuseipdb_raw.json`
- `geoip_raw.json`
- `security_news_raw.json`

### Processed datasets
- `abuseipdb_processed.json`
- `geoip_processed.json`
- `security_news_processed.json`

### Enriched datasets
- `abuseipdb_geoip_enriched.json`
- `abuseipdb_geoip_enrichment_errors.json`

---

## Notes
- API keys are stored in `.env` and should not be committed to GitHub.
- `.env` is excluded using `.gitignore`.
- Raw datasets are kept separately from processed datasets to preserve original responses and support reproducibility.
- The project is being developed incrementally, with each component tested independently before being integrated into the full pipeline.
- Security News currently acts as a contextual intelligence source rather than a direct IP-level enrichment source.

---

## Future Improvements
Possible future enhancements include:
- Enriching multiple IPs dynamically instead of testing only a single IP
- Improving country detection in security news articles
- Adding more advanced threat topic classification
- Writing data directly to MinIO
- Adding Kafka producer and consumer scripts
- Adding Airflow scheduling
- Adding data validation and error handling improvements
- Adding analytics or dashboards on top of the enriched data

---

## Author
Ruba Saleh

Final Project - Cyber Threat Intelligence Platform