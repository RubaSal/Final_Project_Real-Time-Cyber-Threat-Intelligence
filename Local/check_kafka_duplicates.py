import json
from collections import Counter
from kafka import KafkaConsumer

TOPIC = "abuseipdb_blacklist_topic"
BOOTSTRAP_SERVERS = "localhost:29092"

consumer = KafkaConsumer(
    TOPIC,
    bootstrap_servers=BOOTSTRAP_SERVERS,
    auto_offset_reset="earliest",
    enable_auto_commit=False,
    consumer_timeout_ms=10000,
    value_deserializer=lambda v: json.loads(v.decode("utf-8"))
)

ip_list = []

for message in consumer:
    record = message.value
    ip = record.get("ip_address")

    if ip:
        ip_list.append(ip)

consumer.close()

total_messages = len(ip_list)
unique_ips = len(set(ip_list))
duplicate_count = total_messages - unique_ips

print(f"Total messages read: {total_messages}")
print(f"Unique ip_address count: {unique_ips}")
print(f"Duplicate messages by ip_address: {duplicate_count}")

duplicates = Counter(ip_list)
duplicate_ips = {ip: count for ip, count in duplicates.items() if count > 1}

print(f"Number of duplicated IPs: {len(duplicate_ips)}")

print("\nSample duplicated IPs:")
for ip, count in list(duplicate_ips.items())[:20]:
    print(f"{ip}: {count}")