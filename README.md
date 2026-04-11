# Cyber Threat Intelligence Platform

## Project Overview

This project implements a cyber threat intelligence pipeline that collects, processes, enriches, stores, streams, and prepares threat-related data from external APIs.

The main purpose of the system is to identify suspicious IP addresses, enrich them with geolocation data, store the different data layers in a data lake, and stream enriched records through Kafka for near real-time processing.

The project is built as a modular pipeline and is designed to simulate a real-world cyber threat intelligence workflow.

---

## Business Goal

The business goal of this platform is to enable an organization to collect, process, enrich, store, and stream cyber threat data from multiple external sources in order to identify high-risk IP addresses and improve the ability to detect patterns, anomalies, geographic trends, and broader cyber activity context in near real time.

A practical example is enriching suspicious IPs from a blacklist source with geolocation data, storing the results in a structured data lake, and sending enriched records through Kafka for downstream consumption and analysis.

---

## Current Status

At the current stage, the project already supports:

* Ingestion of suspicious IP data from AbuseIPDB
* Transformation of raw API responses into processed datasets
* Enrichment of AbuseIPDB records with GeoIP context
* Ingestion and transformation of security news data
* Storage of raw, processed, and enriched datasets in MinIO
* Kafka local streaming pipeline using:

  * ZooKeeper
  * Kafka broker
  * Kafdrop
* Kafka producer that reads enriched records directly from MinIO
* Kafka consumer that reads topic messages and stores them locally

The current streaming flow that was validated is:

```text
MinIO -> Kafka -> Consumer
```

---

## Project Architecture

The project architecture is based on the following logical flow:

1. **Data Collection**
   Pull raw data from external APIs:

   * AbuseIPDB API
   * GeoIP API
   * Security News API

2. **Data Transformation**
   Convert raw API responses into cleaner and flatter processed datasets.

3. **Data Enrichment**
   Enrich suspicious IP addresses with geolocation information.

4. **Contextual Intelligence Layer**
   Collect and process cybersecurity news as a broader contextual source for threat analysis.

5. **Storage Layer**
   Store raw, processed, and enriched data in MinIO as a local data lake.

6. **Streaming Layer**
   Read enriched records from MinIO and publish them to Kafka for near real-time processing.

7. **Consumption Layer**
   Consume Kafka messages and validate downstream delivery.

8. **Orchestration Layer**
   Use Airflow in a later stage to orchestrate the pipeline and manage execution order.

---

## Data Sources

### 1. AbuseIPDB API

Used to retrieve suspicious / blacklisted IP addresses.

Example fields extracted:

* `ip_address`
* `country_code`
* `abuse_confidence_score`
* `last_reported_at`
* `ingestion_time`

### 2. GeoIP API

Used to retrieve geolocation and metadata about IP addresses.

Example fields extracted:

* `continent_name`
* `country_name`
* `state_province`
* `city`
* `latitude`
* `longitude`
* `country_code2`
* `is_eu`

### 3. Security News API

Used to retrieve cybersecurity-related news articles for broader threat context.

Example fields extracted:

* `source_name`
* `title`
* `description`
* `published_at`
* `attack_type`
* `mentioned_countries`
* `primary_geographic_context`
* `ingestion_time`

---

## Current Project Structure

```text
Final_Project_Real-Time-Cyber-Threat-Intelligence/
│
├── data/
├── .env
├── .gitignore
├── docker-compose.yaml
├── ingest_abuseipdb.py
├── transform_abuseipdb.py
├── ingest_geoip.py
├── transform_geoip.py
├── enrich_abuseipdb_with_geoip.py
├── ingest_security_news.py
├── transform_security_news.py
├── upload_to_minio.py
├── producer_abuseipdb_geoip.py
├── consumer_abuseipdb_geoip.py
├── requirements.txt
├── abuseipdb_raw.json
├── abuseipdb_processed.json
├── geoip_raw.json
├── geoip_processed.json
├── abuseipdb_geoip_enriched.json
├── abuseipdb_geoip_enrichment_errors.json
├── security_news_raw.json
├── security_news_processed.json
├── consumer_output.jsonl
└── README.md
```

---

## Files Description

### 1. `ingest_abuseipdb.py`

Connects to the AbuseIPDB API and pulls raw blacklist data.
The response is saved locally as:

* `abuseipdb_raw.json`

### 2. `transform_abuseipdb.py`

Reads the raw AbuseIPDB response and transforms it into a simplified processed dataset.
The processed output is saved as:

* `abuseipdb_processed.json`

### 3. `ingest_geoip.py`

Connects to the GeoIP API and pulls geolocation data for an IP address.
The response is saved locally as:

* `geoip_raw.json`

### 4. `transform_geoip.py`

Reads the raw GeoIP response and transforms it into a flatter processed structure.
The processed output is saved as:

* `geoip_processed.json`

### 5. `enrich_abuseipdb_with_geoip.py`

Combines threat intelligence data from AbuseIPDB with geolocation context from the GeoIP API using the IP address as the join key.

The output is saved locally as:

* `abuseipdb_geoip_enriched.json`

Failed enrichment attempts are saved locally as:

* `abuseipdb_geoip_enrichment_errors.json`

### 6. `ingest_security_news.py`

Connects to the NewsAPI service and pulls cybersecurity-related news articles based on predefined security keywords.
The response is saved locally as:

* `security_news_raw.json`

### 7. `transform_security_news.py`

Reads the raw security news response and transforms it into a simplified processed dataset containing the most relevant article fields, attack categories, and geographic context.
The processed output is saved as:

* `security_news_processed.json`

### 8. `upload_to_minio.py`

Connects to MinIO and uploads the project datasets into the data lake bucket using an organized folder structure for raw, processed, and enriched layers.

### 9. `producer_abuseipdb_geoip.py`

Reads the enriched JSON dataset directly from MinIO and publishes each record as a separate Kafka message to the topic:

* `abuseipdb_geoip_topic`

### 10. `consumer_abuseipdb_geoip.py`

Consumes messages from the Kafka topic, prints them, and saves them locally as:

* `consumer_output.jsonl`

### 11. `docker-compose.yaml`

Defines the local infrastructure services used by the project:

* MinIO
* ZooKeeper
* Kafka
* Kafdrop

---

## Environment Variables

Create a `.env` file in the project root directory and add the following variables:

```env
ABUSE_API_KEY=your_abuseipdb_api_key
GEOIP_API_KEY=your_geoip_api_key
SECURITY_NEWS_API_KEY=your_security_news_api_key
MINIO_ROOT_USER=your_minio_username
MINIO_ROOT_PASSWORD=your_minio_password
```

These variables are used to authenticate requests to the external APIs and to configure MinIO access.

* `ABUSE_API_KEY` – API key for AbuseIPDB
* `GEOIP_API_KEY` – API key for the GeoIP service
* `SECURITY_NEWS_API_KEY` – API key for the Security News service
* `MINIO_ROOT_USER` – username for the local MinIO service
* `MINIO_ROOT_PASSWORD` – password for the local MinIO service

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

Create a `.env` file in the project root directory and add your actual keys and credentials:

```env
ABUSE_API_KEY=your_actual_abuseipdb_api_key
GEOIP_API_KEY=your_actual_geoip_api_key
SECURITY_NEWS_API_KEY=your_actual_security_news_api_key
MINIO_ROOT_USER=your_actual_minio_username
MINIO_ROOT_PASSWORD=your_actual_minio_password
```

### 4. Start the local infrastructure

```bash
docker compose up -d
```

---

## Docker Services

The local environment currently includes:

* **MinIO** – local object storage / data lake
* **ZooKeeper** – coordination service for Kafka
* **Kafka** – message broker for streaming
* **Kafdrop** – web UI for viewing Kafka topics and brokers

Useful local endpoints:

* MinIO API: `http://localhost:9000`
* MinIO Console: `http://localhost:9001`
* Kafka external listener: `localhost:29092`
* Kafdrop UI: `http://localhost:9003`

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

### Step 8 - Upload datasets to MinIO

```bash
python upload_to_minio.py
```

### Step 9 - Create Kafka topic

```bash
docker exec -it kafka kafka-topics.sh --bootstrap-server localhost:9092 --create --if-not-exists --topic abuseipdb_geoip_topic --partitions 1 --replication-factor 1
```

### Step 10 - Produce enriched records from MinIO to Kafka

```bash
python producer_abuseipdb_geoip.py
```

### Step 11 - Consume Kafka messages

```bash
python consumer_abuseipdb_geoip.py
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
12. Starts local MinIO, ZooKeeper, Kafka, and Kafdrop services with Docker Compose
13. Uploads raw datasets to MinIO
14. Uploads processed datasets to MinIO
15. Uploads enriched datasets to MinIO in an organized bucket structure
16. Creates a Kafka topic for streaming
17. Reads enriched data directly from MinIO and sends it to Kafka
18. Consumes Kafka messages and stores them locally for validation

---

## Enrichment Logic

### 1. IP Enrichment

The IP enrichment stage combines threat intelligence data from AbuseIPDB with geolocation context from the GeoIP API.

The two sources are joined using the IP address as the common key.

The final enriched output is a flat JSON structure that includes threat-related fields, geolocation fields, and pipeline timestamps for traceability and downstream processing.

Current output:

* `abuseipdb_geoip_enriched.json`

### 2. Contextual Security News Enrichment

Security News is not directly joined to the IP-level dataset.

Instead, it is used as a contextual intelligence source that complements the technical threat data.

While AbuseIPDB and GeoIP are directly joined using the IP address, Security News is correlated with the existing data through attack-related topics and geographic context, such as countries mentioned in cyber-related articles.

Current output:

* `security_news_processed.json`

---

## MinIO Data Lake Storage

The project stores all data layers in MinIO using a structured bucket-based layout.

Bucket name:

* `cyber-threat-intelligence`

Logical object structure:

```text
raw/abuseipdb/abuseipdb_raw.json
raw/geoip/geoip_raw.json
raw/security_news/security_news_raw.json

processed/abuseipdb/abuseipdb_processed.json
processed/geoip/geoip_processed.json
processed/security_news/security_news_processed.json

enriched/abuseipdb_geoip_enriched.json
```

This structure separates raw, processed, and enriched data layers and makes the pipeline easier to manage, validate, and extend.

---

## Kafka Streaming Layer

Kafka is currently used as the streaming layer for enriched IP-level threat records.

### Topic

* `abuseipdb_geoip_topic`

### Producer flow

The producer reads `abuseipdb_geoip_enriched.json` directly from MinIO:

* Bucket: `cyber-threat-intelligence`
* Object: `enriched/abuseipdb_geoip_enriched.json`

Each enriched record is sent as a separate Kafka message.

### Consumer flow

The consumer reads messages from `abuseipdb_geoip_topic`, prints them, and saves them locally in:

* `consumer_output.jsonl`

### End-to-end flow

```text
MinIO -> Kafka -> Consumer
```

This confirms that the local streaming pipeline is working correctly.

---

## Why This Architecture

This architecture separates responsibilities into different layers:

* API ingestion for collecting external data
* Transformation for cleaning and structuring data
* IP-level enrichment for combining AbuseIPDB and GeoIP data
* Contextual intelligence processing for cybersecurity news
* MinIO for centralized storage and data lake management
* Kafka for streaming data between pipeline components
* Kafdrop for monitoring Kafka topics and broker status
* Airflow for orchestration and scheduling in the next stage

This approach makes the project modular, scalable, and easier to extend.

---

## Technologies Used

* Python
* Requests
* python-dotenv
* JSON
* GitHub
* NewsAPI
* MinIO
* Docker
* Docker Compose
* Kafka
* ZooKeeper
* Kafdrop

### Planned / upcoming technologies

* Airflow

---

## Output Datasets

### Raw datasets

* `abuseipdb_raw.json`
* `geoip_raw.json`
* `security_news_raw.json`

### Processed datasets

* `abuseipdb_processed.json`
* `geoip_processed.json`
* `security_news_processed.json`

### Enriched datasets

* `abuseipdb_geoip_enriched.json`
* `abuseipdb_geoip_enrichment_errors.json`

### Streaming output

* `consumer_output.jsonl`

---

## Notes

* API keys and MinIO credentials are stored in `.env` and should not be committed to GitHub.
* `.env` is excluded using `.gitignore`.
* Raw datasets are kept separately from processed datasets to preserve original responses and support reproducibility.
* The project is being developed incrementally, with each component tested independently before being integrated into the full pipeline.
* Security News currently acts as a contextual intelligence source rather than a direct IP-level enrichment source.
* MinIO is used as the local data lake for storing raw, processed, and enriched datasets in a structured format.
* Kafka is currently used to stream enriched records for local end-to-end validation.
* The current enriched file used for streaming is the dataset available in MinIO at runtime.

---

## Future Improvements

Possible future enhancements include:

* Running full-scale enrichment for larger record volumes
* Saving enrichment progress incrementally during long API enrichment runs
* Improving country detection in security news articles
* Adding more advanced threat topic classification
* Extending the Kafka consumer to write into a database or data lake target
* Adding Airflow scheduling
* Adding data validation and error handling improvements
* Adding analytics or dashboards on top of the enriched data

---

## Author

Ruba Saleh

Final Project - Cyber Threat Intelligence Platform
