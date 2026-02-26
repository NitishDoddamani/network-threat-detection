from sqlalchemy import Column, Integer, String, Float, DateTime, JSON
from sqlalchemy.sql import func
from app.database import Base

class ThreatAlert(Base):
    __tablename__ = "threat_alerts"

    id           = Column(Integer, primary_key=True, index=True)
    threat_type  = Column(String, nullable=False)
    severity     = Column(String, nullable=False)
    src_ip       = Column(String)
    dst_ip       = Column(String)
    src_port     = Column(Integer)
    dst_port     = Column(Integer)
    protocol     = Column(String)
    packet_count = Column(Integer)
    description  = Column(String)
    raw_features = Column(JSON)
    created_at   = Column(DateTime(timezone=True), server_default=func.now())

class TrafficStat(Base):
    __tablename__ = "traffic_stats"

    id              = Column(Integer, primary_key=True, index=True)
    packets_per_sec = Column(Float)
    bytes_per_sec   = Column(Float)
    active_ips      = Column(Integer)
    threat_count    = Column(Integer)
    recorded_at     = Column(DateTime(timezone=True), server_default=func.now())
