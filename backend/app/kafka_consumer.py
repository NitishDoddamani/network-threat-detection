import json
import asyncio
import threading
from kafka import KafkaConsumer
from kafka.errors import NoBrokersAvailable
from sqlalchemy.orm import Session
from app.database import SessionLocal
from app.models import ThreatAlert
from app.websocket_manager import manager
from app.config import settings
import time

def save_alert(alert_data: dict):
    """Save threat alert to PostgreSQL"""
    db: Session = SessionLocal()
    try:
        # Clean raw_features — convert sets to lists for JSON
        raw = alert_data.get("raw_features", {})
        if raw:
            for k, v in raw.items():
                if isinstance(v, set):
                    raw[k] = list(v)

        alert = ThreatAlert(
            threat_type  = alert_data.get("threat_type", "Unknown"),
            severity     = alert_data.get("severity", "LOW"),
            src_ip       = alert_data.get("src_ip"),
            dst_ip       = alert_data.get("dst_ip"),
            src_port     = alert_data.get("src_port"),
            dst_port     = alert_data.get("dst_port"),
            protocol     = alert_data.get("protocol"),
            packet_count = alert_data.get("packet_count"),
            description  = alert_data.get("description"),
            raw_features = raw,
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        return alert
    except Exception as e:
        print(f"❌ DB save error: {e}")
        db.rollback()
        return None
    finally:
        db.close()

def start_kafka_consumer(loop: asyncio.AbstractEventLoop):
    """Run Kafka consumer in background thread"""
    print("⚡ Starting Kafka consumer...")

    # Retry connection
    for i in range(10):
        try:
            consumer = KafkaConsumer(
                settings.KAFKA_TOPIC,
                bootstrap_servers=settings.KAFKA_BOOTSTRAP_SERVERS,
                value_deserializer=lambda m: json.loads(m.decode("utf-8")),
                auto_offset_reset="latest",
                group_id="threat-detection-group"
            )
            print("✅ Kafka consumer connected!")
            break
        except NoBrokersAvailable:
            print(f"⏳ Waiting for Kafka... ({i+1}/10)")
            time.sleep(5)
    else:
        print("❌ Could not connect to Kafka")
        return

    for message in consumer:
        alert_data = message.value
        print(f"📨 Received from Kafka: {alert_data.get('threat_type')} | {alert_data.get('src_ip')}")

        # Save to PostgreSQL
        saved = save_alert(alert_data)

        if saved:
            # Broadcast to all WebSocket clients
            payload = {
                "id":           saved.id,
                "threat_type":  saved.threat_type,
                "severity":     saved.severity,
                "src_ip":       saved.src_ip,
                "dst_ip":       saved.dst_ip,
                "protocol":     saved.protocol,
                "packet_count": saved.packet_count,
                "description":  saved.description,
                "created_at":   saved.created_at.isoformat(),
            }
            asyncio.run_coroutine_threadsafe(
                manager.broadcast(payload), loop
            )
