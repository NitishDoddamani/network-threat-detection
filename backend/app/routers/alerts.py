from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from app.database import get_db
from app.models import ThreatAlert
from typing import List, Optional

router = APIRouter(prefix="/alerts", tags=["alerts"])

@router.get("/")
def get_alerts(
    limit: int = Query(50, le=200),
    threat_type: Optional[str] = None,
    severity: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(ThreatAlert).order_by(desc(ThreatAlert.created_at))
    if threat_type:
        query = query.filter(ThreatAlert.threat_type == threat_type)
    if severity:
        query = query.filter(ThreatAlert.severity == severity)
    alerts = query.limit(limit).all()
    return [
        {
            "id":           a.id,
            "threat_type":  a.threat_type,
            "severity":     a.severity,
            "src_ip":       a.src_ip,
            "dst_ip":       a.dst_ip,
            "protocol":     a.protocol,
            "packet_count": a.packet_count,
            "description":  a.description,
            "created_at":   a.created_at.isoformat() if a.created_at else None,
        }
        for a in alerts
    ]

@router.get("/stats/summary")
def get_summary(db: Session = Depends(get_db)):
    total     = db.query(ThreatAlert).count()
    critical  = db.query(ThreatAlert).filter(ThreatAlert.severity == "CRITICAL").count()
    high      = db.query(ThreatAlert).filter(ThreatAlert.severity == "HIGH").count()
    medium    = db.query(ThreatAlert).filter(ThreatAlert.severity == "MEDIUM").count()

    # Threat type breakdown
    from sqlalchemy import func
    breakdown = db.query(
        ThreatAlert.threat_type,
        func.count(ThreatAlert.id).label("count")
    ).group_by(ThreatAlert.threat_type).all()

    return {
        "total_alerts": total,
        "critical":     critical,
        "high":         high,
        "medium":       medium,
        "breakdown":    [{"type": b[0], "count": b[1]} for b in breakdown]
    }
