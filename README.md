# IP Threat Intelligence Monitoring Platform

## Project Overview

The **IP Threat Intelligence Monitoring Platform** is a cyber threat intelligence data engineering platform designed to collect, process, enrich, store, and visualize information about high-risk IP addresses.

The platform integrates external threat intelligence and geolocation data, processes the data through a streaming pipeline, enriches IP records in the consumer layer, and stores the final enriched IP profiles in PostgreSQL and Elasticsearch.

The main goal of the project is to help organizations monitor suspicious IP activity, analyze cyber threat patterns, and investigate IP addresses using dashboards and lookup capabilities.

---

## Business Goal

Organizations are constantly exposed to cyber threats such as:

- High-risk IP addresses
- Suspicious domains
- Brute-force attempts
- Bot traffic
- Botnets
- Phishing-related activity
- Abnormal spikes in threat reports

The business goal of this platform is to provide a centralized monitoring system that helps security teams answer questions such as:

- Which high-risk IP addresses are currently active?
- From which countries are the threats coming?
- What is the risk level of each IP address?
- Are there unusual spikes in reports from a specific country or source?
- What additional context is available for a specific IP address?
- Can analysts quickly investigate a specific IP?

For example, if many suspicious IPs are reported from the same country within a short time window, the platform can help identify this pattern and support faster investigation.

---

## Main Use Case

A security analyst wants to investigate suspicious IP activity.

The platform collects IP threat intelligence data from external sources, stores raw and processed data in MinIO, streams records through Kafka, enriches the records in the Consumer / PySpark layer, and writes the final enriched IP profiles to PostgreSQL and Elasticsearch.

The analyst can then use Kibana dashboards or an IP lookup interface to search for a specific IP address and view its risk score, country, source, timestamps, and enrichment details.

---

## Architecture

The platform is built using a layered data architecture.

```text
External Sources
AbuseIPDB / OTX / GeoIP API
        |
        v
Ingestion Layer
Python Collectors
        |
        v
Raw / Processed Storage
MinIO
        |
        v
Kafka Producer
        |
        v
Streaming Layer
Kafka Topic
        |
        v
Processing Layer
Consumer / PySpark
Clean, Enrich, Calculate Risk Score, Generate IP Profile
        |
        v
Serving Layer
PostgreSQL + Elasticsearch
        |
        v
Kibana Dashboards + User / Analyst IP Lookup
```

---

## Architecture Diagram


```markdown
(architecture/ip_threat_intelligence_architecture.png)
```

The diagram reflects the following important points:

```text
MinIO stores raw and processed data only.
The enrichment process is performed in the Consumer / PySpark stage.
The final enriched IP profiles are stored in PostgreSQL and Elasticsearch.
```

---

## Architecture Layers

### 1. External Sources

The platform collects data from external cyber intelligence and geolocation sources.

| Source | Purpose |
|---|---|
| AbuseIPDB | Provides reported abusive or suspicious IP addresses |
| OTX | Provides additional threat intelligence indicators |
| GeoIP API | Provides geolocation enrichment for IP addresses |

These sources provide the raw data that is later processed, streamed, enriched, and analyzed by the platform.

---

### 2. Ingestion Layer

The ingestion layer is responsible for collecting raw data from external APIs.

Python scripts are used as collectors.

Example scripts:

```text
ingest_abuseipdb.py
ingest_otx.py
ingest_geoip.py
```

The ingestion process:

1. Calls the external APIs.
2. Retrieves raw threat intelligence and geolocation data.
3. Saves raw responses.
4. Performs initial processing or standardization when needed.
5. Stores raw and processed files in MinIO.
6. Sends relevant records to Kafka for streaming and further processing.

---

### 3. MinIO Storage Layer

MinIO is used as an S3-compatible object storage layer.

In this project, MinIO stores:

- Raw data files
- Processed data files

MinIO is **not** used as the main storage for the final enriched IP profiles.

The final enriched records are generated later by the Consumer / PySpark stage and stored in PostgreSQL and Elasticsearch.

Example logical MinIO structure:

```text
cyber-threat-intelligence/
│
├── raw/
│   ├── abuseipdb/
│   ├── otx/
│   └── geoip/
│
└── processed/
    ├── abuseipdb/
    ├── otx/
    └── geoip/
```

MinIO allows the platform to:

- Preserve raw API responses
- Store processed files
- Support traceability
- Support debugging
- Reprocess historical files when needed
- Separate raw data from processed data

---

### 4. Kafka Streaming Layer

Kafka is used as the streaming layer.

The producer sends IP records into Kafka topics, and the consumer reads those records for processing and enrichment.

Example Kafka topic:

```text
abuseipdb_geoip_topic
```

Kafka helps decouple ingestion from processing.

This means that ingestion scripts can send records to Kafka, while the consumer can process records independently and continuously.

The Kafka layer supports a near-real-time processing architecture after the data is ingested.

---

### 5. Processing Layer

The processing layer is responsible for transforming, enriching, and preparing the final IP profiles.

In this project, the enrichment process is performed in the **Consumer / PySpark** stage.

The consumer reads records from Kafka and performs the following steps:

- Reads IP records from Kafka
- Cleans and standardizes fields
- Parses timestamps
- Adds GeoIP context
- Adds threat intelligence context
- Adds ASN or network-related enrichment when available
- Calculates a risk score
- Generates a final enriched IP profile
- Writes the final output to PostgreSQL
- Indexes the final output into Elasticsearch

Example enriched IP profile fields:

```text
ip_address
source
abuse_country_code
abuse_confidence_score
last_reported_at
geo_country_name
geo_country_code
geo_city
geo_latitude
geo_longitude
risk_score
risk_level
ingestion_time
enrichment_time
```

---

### 6. Serving Layer

The serving layer stores the final enriched data in systems optimized for querying, searching, and visualization.

| Component | Purpose |
|---|---|
| PostgreSQL | Stores structured enriched IP profiles |
| Elasticsearch | Stores searchable enriched IP profiles for fast investigation |
| Kibana | Visualizes dashboards, maps, and investigation views |
| MinIO | Stores raw and processed files for traceability and replay |

Important distinction:

```text
MinIO = Raw and processed file storage
Consumer / PySpark = Enrichment logic
PostgreSQL = Structured enriched data storage
Elasticsearch = Searchable enriched data index
Kibana = Dashboards and investigation interface
```

---

### 7. User / Analyst IP Lookup

The `User / Analyst IP Lookup` component is part of the serving layer.

It allows a user or security analyst to search for a specific IP address and retrieve its enriched threat profile.

The lookup flow works in two modes:

1. **Existing Profile Lookup**  
   The service first searches for the IP address in the existing `ip_profiles_enriched` Elasticsearch index.

   If the IP already exists, the stored enriched profile is returned to the user.  
   If some computed fields are missing, such as `risk_score`, `status`, `attack_categories`, or `attack_keywords_matched`, the service recalculates them and updates the stored profile.

2. **Live External Lookup**  
   If the IP address is not found in the existing index, the service performs a live lookup using external threat intelligence and enrichment APIs:

   - AbuseIPDB
   - GeoIP API
   - OTX

   The live lookup enriches the IP with geolocation, ASN, abuse reports, OTX pulse information, passive DNS information, attack categories, and risk scoring.

After the profile is created or updated, the result is saved back to:

- Elasticsearch
- PostgreSQL

This allows newly searched IP addresses to become part of the platform’s enriched dataset and to be available for future searches and dashboard analysis.

Example lookup result:

```text
IP Address: 192.0.2.10
Country: Netherlands
City: Amsterdam
ASN / Organization: Example ASN Organization
Abuse Confidence Score: 90
OTX Pulse Count: 12
Passive DNS Count: 3
Risk Score: 80.2
Status: High Risk
Attack Categories: Brute Force, Scanning
Matched Keywords: ssh, scan
Profile Source: live_lookup
```
---

### 8. Airflow Orchestration


Airflow is used to orchestrate the scheduled ingestion and streaming preparation workflow.

The main DAG is responsible for running the ingestion and preparation steps before sending the prepared data into Kafka.

The DAG ID is:

cyber_threat_orchestration

ingest_abuseipdb
        |
        v
check_abuse_changes
        |
        |-- no changes detected --> skip downstream tasks
        |
        |-- changes detected / first run -->
        |
        v
+----------------------+----------------------+----------------+
|                      |                      |                |
v                      v                      v                |
transform_abuseipdb    ingest_geoip           ingest_otx        |
                       |                      |                |
                       v                      v                |
                       transform_geoip        transform_otx     |
|                      |                      |                |
+----------------------+----------------------+----------------+
        |
        v
producer_abuseipdb_to_kafka
        |
        v
commit_abuse_state

---

## Technology Stack

| Technology | Role |
|---|---|
| Python | Data ingestion, transformation, and enrichment |
| Docker | Containerized development environment |
| Docker Compose | Multi-container orchestration |
| MinIO | S3-compatible storage for raw and processed files |
| Kafka | Streaming and message broker |
| PySpark | Data processing and enrichment |
| PostgreSQL | Structured storage for enriched IP profiles |
| Elasticsearch | Search index for enriched IP profiles |
| Kibana | Dashboards and visualization |
| Apache Airflow | Workflow orchestration |
| Kafdrop | Kafka topic inspection and debugging |

---

## Project Structure

Example project structure:

```text
Final_Project_Real-Time-Cyber-Threat-Intelligence/
│
├── dags/
│   └── cyber_threat_intelligence_dag.py
│
├── scripts/
│   ├── ingest_abuseipdb.py
│   ├── ingest_otx.py
│   ├── ingest_geoip.py
│   ├── transform_abuseipdb.py
│   ├── transform_geoip.py
│   ├── upload_to_minio.py
│   ├── producer_abuseipdb_geoip.py
│   └── consumer_abuseipdb_geoip.py
│
├── data/
│   ├── raw/
│   └── processed/
│
├── architecture/
│   └── ip_threat_intelligence_architecture.png
│
├── docker-compose.yaml
├── Dockerfile.airflow
├── requirements.txt
├── requirements-airflow.txt
├── .env.example
├── .gitignore
└── README.md
```

The actual structure may vary depending on the development stage.

---

## Environment Variables

The project uses environment variables for API keys and service configuration.

Create a `.env` file in the project root.

Example:

```env
ABUSE_API_KEY=your_abuseipdb_api_key
GEOIP_API_KEY=your_geoip_api_key
OTX_API_KEY=your_otx_api_key

MINIO_ENDPOINT=localhost:9000
MINIO_ACCESS_KEY=minioadmin
MINIO_SECRET_KEY=minioadmin
MINIO_BUCKET=cyber-threat-intelligence

KAFKA_BOOTSTRAP_SERVERS=localhost:29092
KAFKA_TOPIC=abuseipdb_geoip_topic

POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=cyber_threat_intelligence
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres

ELASTICSEARCH_HOST=http://localhost:9200
ELASTICSEARCH_INDEX=ip_profiles_enriched
```


---

## Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/your-username/Final_Project_Real-Time-Cyber-Threat-Intelligence.git
cd Final_Project_Real-Time-Cyber-Threat-Intelligence
```

---

### 2. Create a Virtual Environment

```bash
python -m venv venv
```

Activate the environment.

On Windows:

```bash
venv\Scripts\activate
```

On macOS or Linux:

```bash
source venv/bin/activate
```

---

### 3. Install Python Dependencies

```bash
pip install -r requirements.txt
```

Example dependencies:

```text
requests
python-dotenv
minio
kafka-python
pyspark
psycopg2-binary
elasticsearch
```

---

### 4. Start the Docker Environment

```bash
docker compose up -d
```

Check running containers:

```bash
docker compose ps
```

---

## Main Services

| Service | Default URL / Port |
|---|---|
| MinIO API | http://localhost:9000 |
| MinIO Console | http://localhost:9001 |
| Kafka | localhost:29092 |
| Kafdrop | http://localhost:9003 |
| PostgreSQL | localhost:5432 |
| Elasticsearch | http://localhost:9200 |
| Kibana | http://localhost:5601 |
| Airflow | http://localhost:8080 |

Ports may change depending on the local Docker Compose configuration.

---

## Running the Pipeline Manually

### 1. Ingest AbuseIPDB Data

```bash
python scripts/ingest_abuseipdb.py
```

Expected output:

```text
abuseipdb_raw.json
```

---

### 2. Transform AbuseIPDB Data

```bash
python scripts/transform_abuseipdb.py
```

Expected output:

```text
abuseipdb_processed.json
```

---

### 3. Ingest and Transform GeoIP Data

```bash
python scripts/ingest_geoip.py
python scripts/transform_geoip.py
```

Expected output:

```text
geoip_raw.json
geoip_processed.json
```

---

### 4. Upload Raw and Processed Data to MinIO

```bash
python scripts/upload_to_minio.py
```

The files are uploaded to the configured MinIO bucket.

Example upload paths:

```text
raw/abuseipdb/abuseipdb_raw.json
processed/abuseipdb/abuseipdb_processed.json
raw/geoip/geoip_raw.json
processed/geoip/geoip_processed.json
```

---

### 5. Send Records to Kafka

```bash
python scripts/producer_abuseipdb_geoip.py
```

The producer reads the relevant processed records and sends them to the Kafka topic.

Example topic:

```text
abuseipdb_geoip_topic
```

---

### 6. Run the Consumer

```bash
python scripts/consumer_abuseipdb_geoip.py
```

The consumer reads messages from Kafka, performs enrichment, calculates the risk score, and writes the final enriched IP profiles to:

- PostgreSQL
- Elasticsearch

---

## Running with Airflow

Start the Airflow services using Docker Compose:

```bash
docker compose up -d airflow-init airflow-api-server airflow-scheduler airflow-dag-processor
```

Open Airflow in the browser:

```text
http://localhost:8080
```

Enable the DAG:

```text
cyber_threat_intelligence_dag
```

The DAG orchestrates the pipeline tasks according to the configured schedule.

---

## Airflow Components

The project may include several Airflow-related containers:

| Component | Description |
|---|---|
| airflow-init | Initializes the Airflow metadata database and creates initial configuration |
| airflow-api-server | Runs the Airflow web/API service used to access the Airflow UI |
| airflow-scheduler | Monitors DAG schedules and triggers tasks |
| airflow-dag-processor | Parses DAG files and prepares them for scheduling |

Important:

```text
The Airflow scheduler must be running for scheduled DAG runs to execute.
If Airflow is not running, scheduled jobs will not execute.
```

---

## Kafka Validation

List Kafka topics:

```bash
docker exec -it kafka kafka-topics.sh --bootstrap-server localhost:9092 --list
```

Check topic offsets:

```bash
docker exec -it kafka kafka-run-class.sh kafka.tools.GetOffsetShell --broker-list localhost:9092 --topic abuseipdb_geoip_topic
```

Open Kafdrop:

```text
http://localhost:9003
```

Kafdrop can be used to inspect:

- Topics
- Partitions
- Offsets
- Messages
- Consumer groups

---

## PostgreSQL Validation

Connect to PostgreSQL:

```bash
docker exec -it postgres psql -U postgres -d cyber_threat_intelligence
```

Count records:

```sql
SELECT COUNT(*)
FROM ip_profiles_enriched;
```

Preview records:

```sql
SELECT *
FROM ip_profiles_enriched
LIMIT 10;
```

Search for a specific IP:

```sql
SELECT *
FROM ip_profiles_enriched
WHERE ip_address = '192.0.2.10';
```

---

## Elasticsearch Validation

Check Elasticsearch status:

```bash
curl http://localhost:9200
```

Count indexed records:

```bash
curl http://localhost:9200/ip_profiles_enriched/_count
```

Search for a specific IP:

```bash
curl -X GET "http://localhost:9200/ip_profiles_enriched/_search" \
-H "Content-Type: application/json" \
-d '{
  "query": {
    "match": {
      "ip_address": "192.0.2.10"
    }
  }
}'
```

---

## Kibana Dashboards

Kibana is used to visualize the enriched IP profiles stored in Elasticsearch.

Possible dashboards include:

- Threat overview dashboard
- High-risk IPs dashboard
- Threat map by country
- Risk score distribution
- Abuse confidence score analysis
- Latest reported IPs
- IP investigation dashboard

Example dashboard questions:

- Which countries have the highest number of reported IPs?
- How many IPs are classified as high risk?
- What is the distribution of risk scores?
- Which IPs were reported most recently?
- Are there spikes in reports from specific countries?

---

## Data Flow Summary

The end-to-end data flow is:

```text
External APIs
    |
    v
Python Collectors
    |
    v
Raw JSON Files
    |
    v
Processed Parquet Files
    |
    v
MinIO Raw / Processed Storage
    |
    v
Kafka Producer
    |
    v
Kafka Topic
    |
    v
Consumer / PySpark
    |
    v
Enrichment + Risk Score Calculation
    |
    v
PostgreSQL + Elasticsearch
    |
    v
Kibana + IP Lookup
```

---

## Risk Score Logic

The platform calculates a risk score based on available threat intelligence indicators.

Example risk score factors:

- Abuse confidence score
- Number of reports
- Source reliability
- Last reported timestamp
- Country or geolocation context
- Presence in multiple threat intelligence sources

Example risk levels:

| Risk Score | Risk Level |
|---|---|
| 0 - 39 | Low Risk |
| 40 - 69 | Medium Risk |
| 70 - 100 | High Risk |

The exact scoring logic can be adjusted based on business and security requirements.

---

## Example Final Enriched Record

The final enriched record is generated by the Consumer / PySpark stage and stored in PostgreSQL and Elasticsearch.

```json
{
  "ip_address": "192.0.2.10",
  "source": "AbuseIPDB",
  "abuse_country_code": "NL",
  "abuse_confidence_score": 100,
  "last_reported_at": "2026-03-09T18:17:01+00:00",
  "geo_country_name": "Netherlands",
  "geo_city": "Amsterdam",
  "geo_latitude": 52.3676,
  "geo_longitude": 4.9041,
  "risk_score": 95,
  "risk_level": "High Risk",
  "ingestion_time": "2026-03-09T18:20:00+00:00",
  "enrichment_time": "2026-03-09T18:25:00+00:00"
}
```

---

## Scheduling Strategy

The platform can support different scheduling strategies.

### Daily Batch Ingestion

External API data is collected once per day.

This approach is useful when API rate limits are strict or when daily refresh is enough for the project scope.

### Near-Real-Time Streaming

Once records are ingested, they are sent through Kafka and processed continuously by the consumer.

This means that after data becomes available, the streaming and enrichment parts of the pipeline can behave near-real-time.

---

## API Rate Limit Handling

Some external APIs may enforce request limits.

For example, if AbuseIPDB returns:

```text
429 Too Many Requests
```

it means the request limit was reached.

The platform should handle this case by:

- Logging the error
- Retrying with a delay when appropriate
- Avoiding excessive API calls
- Allowing the pipeline to fail clearly or skip the blocked source depending on the DAG configuration
- Running the ingestion according to a safe schedule

---

## Error Handling

The project includes error handling for common pipeline issues:

- Missing environment variables
- API request failures
- API rate limits
- Invalid JSON responses
- Empty datasets
- Failed MinIO uploads
- Kafka connection issues
- PostgreSQL insertion errors
- Elasticsearch indexing errors

Recommended behavior:

```text
Fail fast for critical infrastructure errors.
Log and skip records for non-critical record-level errors.
Store error outputs when possible for debugging.
```

---

## Monitoring and Debugging

Check containers:

```bash
docker compose ps
```

View logs:

```bash
docker compose logs -f
```

View logs for a specific service:

```bash
docker compose logs -f airflow-scheduler
docker compose logs -f kafka
docker compose logs -f spark-consumer
docker compose logs -f postgres
docker compose logs -f elasticsearch
```

Restart a service:

```bash
docker compose restart service_name
```

Stop all services:

```bash
docker compose down
```

Stop all services and remove volumes:

```bash
docker compose down -v
```

Use this command carefully, because it removes persisted Docker volumes.

---

## Current Project Status

The project currently includes the following main components:

- Python ingestion scripts
- Raw and processed JSON files
- MinIO storage layer for raw and processed files
- Kafka producer and consumer flow
- Kafka topic validation
- Consumer / PySpark enrichment logic
- PostgreSQL structured storage for enriched IP profiles
- Elasticsearch search index for enriched IP profiles
- Kibana serving layer concept
- Airflow orchestration design
- IP lookup architecture design

---

## Future Improvements

Possible future improvements:

- Add more threat intelligence sources
- Add domain reputation analysis
- Add organization authentication logs
- Add brute-force detection logic
- Add bot traffic detection logic
- Add phishing-related indicators
- Improve risk scoring model
- Add anomaly detection
- Add alerting mechanism
- Build a dedicated IP lookup API
- Add automated dashboard deployment
- Add CI/CD pipeline
- Add data quality checks
- Add unit tests and integration tests
- Add historical trend analysis

---

## Security Notes

- API keys must be stored in environment variables.
- The `.env` file should not be committed to GitHub.
- Sensitive credentials should be excluded using `.gitignore`.
- Production deployments should use secret management tools.
- Access to dashboards and lookup tools should be restricted to authorized users.

---

## Project Summary

The **IP Threat Intelligence Monitoring Platform** demonstrates a full data engineering pipeline for cyber threat intelligence.

It collects external IP threat data, stores raw and processed files in MinIO, streams records through Kafka, enriches the data in the Consumer / PySpark layer, stores the final enriched output in PostgreSQL and Elasticsearch, and provides dashboards and IP investigation capabilities through Kibana.

This project combines key Big Data and Cloud Engineering concepts:

- API ingestion
- Data lake storage
- Streaming architecture
- Data enrichment
- Workflow orchestration
- Search indexing
- Structured storage
- Dashboard visualization
- Cyber threat intelligence analytics

---

## Author

Developed as a final project for the Cloud & Big Data Engineering course.