import json
from kafka import KafkaConsumer

TOPIC_NAME = "abuseipdb_geoip_topic"
BOOTSTRAP_SERVERS = ["localhost:29092"]
OUTPUT_FILE = "consumer_output.jsonl"


def main():
    consumer = KafkaConsumer(
        TOPIC_NAME,
        bootstrap_servers=BOOTSTRAP_SERVERS,
        auto_offset_reset="earliest",
        enable_auto_commit=True,
        group_id="abuseipdb-geoip-consumer-group-minio-v2",
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
        key_deserializer=lambda m: m.decode("utf-8") if m else None,
        consumer_timeout_ms=10000
    )

    print("Consumer started. Reading messages...")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for message in consumer:
            record = {
                "topic": message.topic,
                "partition": message.partition,
                "offset": message.offset,
                "key": message.key,
                "value": message.value
            }

            print(json.dumps(record, ensure_ascii=False, indent=2))
            f.write(json.dumps(record, ensure_ascii=False) + "\n")

    consumer.close()
    print("Consumer finished successfully.")


if __name__ == "__main__":
    main()