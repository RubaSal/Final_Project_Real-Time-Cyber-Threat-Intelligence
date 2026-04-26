import json
from kafka import KafkaProducer

INPUT_FILE = "abuseipdb_processed.json"
TOPIC_NAME = "abuseipdb_blacklist_topic"
BOOTSTRAP_SERVERS = "localhost:29092"


def load_records(file_path):
    with open(file_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data, dict) and isinstance(data.get("data"), list):
        return data["data"]

    if isinstance(data, list):
        return data

    return []


def main():
    records = load_records(INPUT_FILE)

    if not records:
        print(f"No records found in {INPUT_FILE}")
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


if __name__ == "__main__":
    main()