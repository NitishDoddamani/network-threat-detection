"""
MITRE ATT&CK Framework mapping for detected threats.
https://attack.mitre.org/
"""

MITRE_MAPPINGS = {
    "DDoS": {
        "technique_id":   "T1498",
        "technique_name": "Network Denial of Service",
        "tactic":         "Impact",
        "tactic_id":      "TA0040",
        "description":    "Adversary attempts to degrade or block availability of resources",
        "url":            "https://attack.mitre.org/techniques/T1498/",
        "subtechnique":   "T1498.001 - Direct Network Flood",
    },
    "Port Scan": {
        "technique_id":   "T1046",
        "technique_name": "Network Service Discovery",
        "tactic":         "Discovery",
        "tactic_id":      "TA0007",
        "description":    "Adversary enumerates services running on remote hosts",
        "url":            "https://attack.mitre.org/techniques/T1046/",
        "subtechnique":   "T1046 - Port Scanning",
    },
    "Brute Force": {
        "technique_id":   "T1110",
        "technique_name": "Brute Force",
        "tactic":         "Credential Access",
        "tactic_id":      "TA0006",
        "description":    "Adversary attempts to gain access by guessing credentials",
        "url":            "https://attack.mitre.org/techniques/T1110/",
        "subtechnique":   "T1110.001 - Password Guessing",
    },
    "DNS Tunneling": {
        "technique_id":   "T1071",
        "technique_name": "Application Layer Protocol",
        "tactic":         "Command and Control",
        "tactic_id":      "TA0011",
        "description":    "Adversary uses DNS to communicate and exfiltrate data",
        "url":            "https://attack.mitre.org/techniques/T1071/",
        "subtechnique":   "T1071.004 - DNS",
    },
    "ML Anomaly": {
        "technique_id":   "T0000",
        "technique_name": "Unknown / Zero-Day Threat",
        "tactic":         "Unknown",
        "tactic_id":      "TA0000",
        "description":    "ML model detected anomalous traffic not matching known patterns",
        "url":            "https://attack.mitre.org/",
        "subtechnique":   "Detected via Isolation Forest anomaly detection",
    },
}

def get_mitre_info(threat_type: str) -> dict:
    """Get MITRE ATT&CK info for a given threat type."""
    return MITRE_MAPPINGS.get(threat_type, {
        "technique_id":   "T0000",
        "technique_name": "Unknown",
        "tactic":         "Unknown",
        "tactic_id":      "TA0000",
        "description":    "Unclassified threat",
        "url":            "https://attack.mitre.org/",
        "subtechnique":   "N/A",
    })

def enrich_threat(threat: dict) -> dict:
    """Add MITRE ATT&CK fields to a threat dict."""
    mitre = get_mitre_info(threat.get("threat_type", ""))
    threat["mitre_technique_id"]   = mitre["technique_id"]
    threat["mitre_technique_name"] = mitre["technique_name"]
    threat["mitre_tactic"]         = mitre["tactic"]
    threat["mitre_tactic_id"]      = mitre["tactic_id"]
    threat["mitre_url"]            = mitre["url"]
    return threat
