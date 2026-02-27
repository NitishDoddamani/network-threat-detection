"""
Automated threat response engine.
Blocks malicious IPs via iptables and tracks all response actions.
"""
import subprocess
import threading
import time
import json
import os
from datetime import datetime, timedelta
from collections import defaultdict
from response.whitelist import is_whitelisted

# ── CONFIG ──
AUTO_BLOCK_SEVERITIES  = {"CRITICAL", "HIGH"}   # which severities trigger block
BLOCK_DURATION_MINUTES = 15                       # auto-unblock after X mins
MAX_BLOCKED_IPS        = 100                      # safety limit
RESPONSE_LOG_FILE      = "response/response_log.json"

# ── State ──
blocked_ips: dict  = {}   # ip → {"blocked_at", "unblock_at", "reason", "threat_type"}
response_lock       = threading.Lock()
_unblock_thread     = None

def _run_iptables(args: list) -> bool:
    """Execute an iptables command. Returns True on success."""
    try:
        result = subprocess.run(
            ["iptables"] + args,
            capture_output=True, text=True
        )
        return result.returncode == 0
    except FileNotFoundError:
        print("⚠️  iptables not found — running in simulation mode")
        return True   # simulate success
    except Exception as e:
        print(f"❌ iptables error: {e}")
        return False

def block_ip(ip: str, threat_type: str, severity: str, description: str = "") -> dict:
    """
    Block an IP using iptables.
    Returns response action dict.
    """
    with response_lock:
        # Safety checks
        if is_whitelisted(ip):
            return {"status": "skipped", "reason": "whitelisted", "ip": ip}

        if ip in blocked_ips:
            return {"status": "already_blocked", "ip": ip}

        if len(blocked_ips) >= MAX_BLOCKED_IPS:
            return {"status": "skipped", "reason": "max_limit_reached", "ip": ip}

        # Block inbound traffic from this IP
        success = _run_iptables(["-A", "INPUT", "-s", ip, "-j", "DROP"])

        if success:
            now        = datetime.utcnow()
            unblock_at = now + timedelta(minutes=BLOCK_DURATION_MINUTES)

            blocked_ips[ip] = {
                "ip":          ip,
                "blocked_at":  now.isoformat(),
                "unblock_at":  unblock_at.isoformat(),
                "threat_type": threat_type,
                "severity":    severity,
                "description": description,
                "status":      "blocked"
            }

            _log_response("BLOCK", ip, threat_type, severity, description)
            print(f"🚫 AUTO-BLOCKED: {ip} | {threat_type} | {severity} | unblocks in {BLOCK_DURATION_MINUTES}m")

            # Schedule auto-unblock
            _schedule_unblock(ip, BLOCK_DURATION_MINUTES * 60)

            return {"status": "blocked", "ip": ip, "unblock_at": unblock_at.isoformat()}
        else:
            return {"status": "failed", "ip": ip}

def unblock_ip(ip: str) -> dict:
    """Manually or automatically unblock an IP."""
    with response_lock:
        if ip not in blocked_ips:
            return {"status": "not_blocked", "ip": ip}

        success = _run_iptables(["-D", "INPUT", "-s", ip, "-j", "DROP"])

        if success:
            info = blocked_ips.pop(ip)
            _log_response("UNBLOCK", ip, info.get("threat_type"), info.get("severity"), "auto/manual unblock")
            print(f"✅ UNBLOCKED: {ip}")
            return {"status": "unblocked", "ip": ip}
        else:
            return {"status": "failed", "ip": ip}

def _schedule_unblock(ip: str, delay_seconds: int):
    """Schedule automatic unblock after delay."""
    def _do_unblock():
        time.sleep(delay_seconds)
        unblock_ip(ip)

    t = threading.Thread(target=_do_unblock, daemon=True)
    t.start()

def get_blocked_ips() -> list:
    """Return all currently blocked IPs."""
    with response_lock:
        return list(blocked_ips.values())

def should_block(severity: str) -> bool:
    return severity in AUTO_BLOCK_SEVERITIES

def handle_threat(threat: dict) -> dict | None:
    """
    Called for every detected threat.
    Decides whether to block and executes response.
    """
    ip       = threat.get("src_ip")
    severity = threat.get("severity", "LOW")
    ttype    = threat.get("threat_type", "Unknown")
    desc     = threat.get("description", "")

    if not ip or not should_block(severity):
        return None

    return block_ip(ip, ttype, severity, desc)

def _log_response(action: str, ip: str, threat_type: str, severity: str, description: str):
    """Append response action to log file."""
    log_entry = {
        "action":      action,
        "ip":          ip,
        "threat_type": threat_type,
        "severity":    severity,
        "description": description,
        "timestamp":   datetime.utcnow().isoformat()
    }
    try:
        logs = []
        if os.path.exists(RESPONSE_LOG_FILE):
            with open(RESPONSE_LOG_FILE, "r") as f:
                logs = json.load(f)
        logs.append(log_entry)
        # Keep last 1000 entries
        logs = logs[-1000:]
        with open(RESPONSE_LOG_FILE, "w") as f:
            json.dump(logs, f, indent=2)
    except Exception as e:
        print(f"⚠️  Log write error: {e}")

def get_response_logs(limit: int = 50) -> list:
    """Get recent response actions from log."""
    try:
        if not os.path.exists(RESPONSE_LOG_FILE):
            return []
        with open(RESPONSE_LOG_FILE, "r") as f:
            logs = json.load(f)
        return logs[-limit:][::-1]  # newest first
    except Exception:
        return []
