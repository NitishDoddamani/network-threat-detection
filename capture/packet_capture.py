#!/usr/bin/env python3
"""
Live packet capture engine using Scapy + ML anomaly detection.
Run with: sudo python3 capture/packet_capture.py
"""
import sys
import time

# Add project root to path for ML imports
sys.path.insert(0, "/home/nitish/network-threat-detection")

from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
from feature_extractor import FlowTracker
from kafka_producer import create_producer, send_threat
from ml.detector import MLDetector

# ── CONFIG ──
KAFKA_SERVERS   = "localhost:9092"
KAFKA_TOPIC     = "network-threats"
INTERFACE       = None   # None = auto-detect
ANALYSIS_WINDOW = 10     # seconds per analysis window

# ── THRESHOLDS ──
PORT_SCAN_THRESHOLD   = 15    # unique ports in window
DDOS_PKT_THRESHOLD    = 1000  # packets/sec
BRUTE_FORCE_THRESHOLD = 20    # syn packets to same port
DNS_PAYLOAD_THRESHOLD = 200   # bytes

tracker  = FlowTracker()
producer = None
detector = None

def detect_threats(features, dst_port=None, protocol=None, dns_payload=0):
    """Rule-based + ML threat detection from flow features"""
    threats = []

    # ── Port Scan ──
    if features["unique_ports"] >= PORT_SCAN_THRESHOLD:
        threats.append({
            "threat_type": "Port Scan",
            "severity": "HIGH" if features["unique_ports"] > 30 else "MEDIUM",
            "src_ip": features["src_ip"],
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "protocol": "TCP",
            "packet_count": features["packet_count"],
            "description": f"Port scan detected: {features['unique_ports']} unique ports contacted",
            "raw_features": features,
        })

    # ── DDoS ──
    if features["packets_per_sec"] >= DDOS_PKT_THRESHOLD:
        threats.append({
            "threat_type": "DDoS",
            "severity": "CRITICAL",
            "src_ip": features["src_ip"],
            "dst_ip": None,
            "src_port": None,
            "dst_port": None,
            "protocol": protocol or "TCP",
            "packet_count": features["packet_count"],
            "description": f"DDoS detected: {features['packets_per_sec']:.0f} pkt/s",
            "raw_features": features,
        })

    # ── Brute Force ──
    if features["syn_count"] >= BRUTE_FORCE_THRESHOLD and features["unique_ports"] <= 3:
        threats.append({
            "threat_type": "Brute Force",
            "severity": "HIGH",
            "src_ip": features["src_ip"],
            "dst_ip": None,
            "src_port": None,
            "dst_port": dst_port,
            "protocol": "TCP",
            "packet_count": features["syn_count"],
            "description": f"Brute force detected: {features['syn_count']} SYN attempts",
            "raw_features": features,
        })

    # ── DNS Tunneling ──
    if dns_payload > DNS_PAYLOAD_THRESHOLD:
        threats.append({
            "threat_type": "DNS Tunneling",
            "severity": "HIGH",
            "src_ip": features["src_ip"],
            "dst_ip": None,
            "src_port": None,
            "dst_port": 53,
            "protocol": "DNS",
            "packet_count": 1,
            "description": f"DNS tunneling suspected: payload {dns_payload} bytes",
            "raw_features": features,
        })

    # ── ML Anomaly (only if no rule triggered) ──
    if not threats and detector and detector.loaded:
        ml_result = detector.predict(features)
        if ml_result["is_anomaly"] and ml_result["confidence"] == "HIGH":
            threats.append({
                "threat_type": "ML Anomaly",
                "severity": "MEDIUM",
                "src_ip": features["src_ip"],
                "dst_ip": None,
                "src_port": None,
                "dst_port": dst_port,
                "protocol": protocol or "OTHER",
                "packet_count": features["packet_count"],
                "description": f"ML anomaly detected | score: {ml_result['anomaly_score']} | confidence: {ml_result['confidence']}",
                "raw_features": features,
            })

    return threats


def process_packet(pkt):
    """Called for every captured packet"""
    if not pkt.haslayer(IP):
        return

    src_ip      = pkt[IP].src
    dst_ip      = pkt[IP].dst
    src_port    = 0
    dst_port    = 0
    flags       = ""
    payload_len = len(pkt)
    dns_payload = 0
    protocol    = "OTHER"

    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        flags    = str(pkt[TCP].flags)
        protocol = "TCP"
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        protocol = "UDP"

    # DNS tunneling check
    if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
        dns_payload = len(pkt[DNSQR].qname)

    # Update flow tracker
    tracker.update(src_ip, dst_ip, src_port, dst_port, payload_len, flags)
    features = tracker.get_features(src_ip)

    # Detect threats (rule-based + ML)
    threats = detect_threats(features, dst_port, protocol, dns_payload)

    for threat in threats:
        print(f"🚨 THREAT: {threat['threat_type']} | {threat['severity']} | {src_ip}")
        if producer:
            send_threat(producer, KAFKA_TOPIC, threat)
        tracker.reset_ip(src_ip)


def main():
    global producer, detector

    print("🚀 Starting Network Threat Detection Engine...")

    # Load ML model
    print("🤖 Loading ML anomaly detection model...")
    detector = MLDetector(model_dir="/home/nitish/network-threat-detection/ml/models")

    # Connect to Kafka
    print("⚡ Connecting to Kafka...")
    producer = create_producer(KAFKA_SERVERS)

    print(f"📡 Starting packet capture on interface: {INTERFACE or 'auto'}")
    print("🛡️  Monitoring for: Port Scan | DDoS | Brute Force | DNS Tunneling | ML Anomaly")
    print("-" * 60)

    sniff(
        iface=INTERFACE,
        prn=process_packet,
        store=False,
        filter="ip"
    )


if __name__ == "__main__":
    main()
