import time
from collections import defaultdict

class FlowTracker:
    """Tracks per-IP flow statistics with time-window analysis"""

    def __init__(self, window_seconds=10):
        self.window_seconds = window_seconds
        self.flows = defaultdict(lambda: {
            "packet_count":  0,
            "byte_count":    0,
            "ports_contacted": set(),
            "dst_ips":       set(),
            "start_time":    time.time(),
            "last_seen":     time.time(),
            "syn_count":     0,
            "failed_conns":  0,
            "alert_count":   0,
            "last_alerted":  0,   # timestamp of last alert
        })

    def update(self, src_ip, dst_ip, src_port, dst_port, payload_len, flags):
        flow = self.flows[src_ip]
        flow["packet_count"]    += 1
        flow["byte_count"]      += payload_len
        flow["ports_contacted"].add(dst_port)
        flow["dst_ips"].add(dst_ip)
        flow["last_seen"]        = time.time()
        if flags and "S" in flags and "A" not in flags:
            flow["syn_count"] += 1

    def get_features(self, src_ip):
        flow     = self.flows[src_ip]
        duration = max(time.time() - flow["start_time"], 0.001)
        return {
            "src_ip":          src_ip,
            "packet_count":    flow["packet_count"],
            "byte_count":      flow["byte_count"],
            "unique_ports":    len(flow["ports_contacted"]),
            "unique_dst_ips":  len(flow["dst_ips"]),
            "packets_per_sec": flow["packet_count"] / duration,
            "bytes_per_sec":   flow["byte_count"] / duration,
            "syn_count":       flow["syn_count"],
            "duration":        duration,
            "alert_count":     flow["alert_count"],
            "last_alerted":    flow["last_alerted"],
        }

    def should_alert(self, src_ip, cooldown_seconds=30) -> bool:
        """
        Prevent alerting same IP repeatedly within cooldown period.
        Returns True if we should alert, False if in cooldown.
        """
        flow = self.flows[src_ip]
        now  = time.time()
        if now - flow["last_alerted"] < cooldown_seconds:
            return False
        return True

    def mark_alerted(self, src_ip):
        """Mark that we just alerted on this IP."""
        self.flows[src_ip]["last_alerted"]  = time.time()
        self.flows[src_ip]["alert_count"]  += 1

    def reset_ip(self, src_ip):
        self.flows[src_ip] = {
            "packet_count":    0,
            "byte_count":      0,
            "ports_contacted": set(),
            "dst_ips":         set(),
            "start_time":      time.time(),
            "last_seen":       time.time(),
            "syn_count":       0,
            "failed_conns":    0,
            "alert_count":     0,
            "last_alerted":    self.flows[src_ip]["last_alerted"],  # keep cooldown
        }
