from fastapi import APIRouter
import sys
sys.path.insert(0, "/home/nitish/network-threat-detection")
from ml.adaptive_trainer import adaptive_trainer

router = APIRouter(prefix="/stats", tags=["stats"])

@router.get("/ml-metrics")
def get_ml_metrics():
    return adaptive_trainer.get_metrics()
