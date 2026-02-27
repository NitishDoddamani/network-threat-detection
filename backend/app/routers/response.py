from fastapi import APIRouter
import sys
sys.path.insert(0, "/home/nitish/network-threat-detection")
from response.auto_response import (
    get_blocked_ips, unblock_ip, block_ip, get_response_logs
)

router = APIRouter(prefix="/response", tags=["response"])

@router.get("/blocked")
def get_blocked():
    return get_blocked_ips()

@router.delete("/unblock/{ip}")
def manual_unblock(ip: str):
    # Replace dots encoded in URL
    ip = ip.replace("-", ".")
    return unblock_ip(ip)

@router.post("/block/{ip}")
def manual_block(ip: str, threat_type: str = "Manual", severity: str = "HIGH"):
    ip = ip.replace("-", ".")
    return block_ip(ip, threat_type, severity, "Manually blocked via API")

@router.get("/logs")
def get_logs(limit: int = 50):
    return get_response_logs(limit)
