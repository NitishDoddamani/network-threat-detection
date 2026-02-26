import time
from collections import defaultdict

class FlowTracker:
    """Tracks per-IP flow statistics for feature extraction"""

    def __init__(self):
        self.flows = defaultdict(lambda: {
            "packet_count": 0,
            "byte_count": 0,
            "ports_contacted": set(),
            "dst_ips": set(),
            "start_time": time.time(),
            "last_seen": time.time(),
            "syn_count": 0,
            "failed_conns": 0,
        })

    def update(self, src_ip, dst_ip, src_port, dst_port, payload_len, flags):
        flow = self.flows[src_ip]
        flow["packet_count"] += 1
        flow["byte_count"] += payload_len
        flow["ports_contacted"].add(dst_port)
        flow["dst_ips"].add(dst_ip)
        flow["last_seen"] = time.time()
        if flags and "S" in flags and "A" not in flags:
            flow["syn_count"] += 1

    def get_features(self, src_ip):
        flow = self.flows[src_ip]
        duration = max(time.time() - flow["start_time"], 0.001)
        return {
            "src_ip": src_ip,
            "packet_count": flow["packet_count"],
            "byte_count": flow["byte_count"],
            "unique_ports": len(flow["ports_contacted"]),
            "unique_dst_ips": len(flow["dst_ips"]),
            "packets_per_sec": flow["packet_count"] / duration,
            "bytes_per_sec": flow["byte_count"] / duration,
            "syn_count": flow["syn_count"],
            "duration": duration,
        }

    def reset_ip(self, src_ip):
        self.flows[src_ip] = {
            "packet_count": 0,
            "byte_count": 0,
            "ports_contacted": set(),
            "dst_ips": set(),
            "start_time": time.time(),
            "last_seen": time.time(),
            "syn_count": 0,
            "failed_conns": 0,
        }
