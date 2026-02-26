import json
import time
from kafka import KafkaProducer
from kafka.errors import NoBrokersAvailable

def create_producer(bootstrap_servers="localhost:9092", retries=10):
    for i in range(retries):
        try:
            producer = KafkaProducer(
                bootstrap_servers=bootstrap_servers,
                value_serializer=lambda v: json.dumps(v).encode("utf-8")
            )
            print("✅ Kafka producer connected!")
            return producer
        except NoBrokersAvailable:
            print(f"⏳ Waiting for Kafka... ({i+1}/{retries})")
            time.sleep(5)
    raise Exception("❌ Could not connect to Kafka after retries")

def send_threat(producer, topic, threat_event):
    producer.send(topic, threat_event)
    producer.flush()
