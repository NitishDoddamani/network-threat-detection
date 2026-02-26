import joblib
import numpy as np
import pandas as pd

class MLDetector:
    def __init__(self, model_dir="ml/models"):
        self.model = None
        self.scaler = None
        self.feature_names = None
        self.loaded = False
        self._load(model_dir)

    def _load(self, model_dir):
        try:
            self.model         = joblib.load(f"{model_dir}/isolation_forest.pkl")
            self.scaler        = joblib.load(f"{model_dir}/scaler.pkl")
            self.feature_names = joblib.load(f"{model_dir}/feature_names.pkl")
            self.loaded        = True
            print("✅ ML model loaded successfully!")
        except FileNotFoundError:
            print("⚠️  ML model not found — run ml/train_model.py first")

    def predict(self, features: dict) -> dict:
        if not self.loaded:
            return {"is_anomaly": False, "anomaly_score": 0, "confidence": "UNKNOWN"}

        # ✅ Use DataFrame with feature names to suppress warning
        feature_df = pd.DataFrame([{
            "packet_count":    features.get("packet_count", 0),
            "byte_count":      features.get("byte_count", 0),
            "unique_ports":    features.get("unique_ports", 0),
            "unique_dst_ips":  features.get("unique_dst_ips", 0),
            "packets_per_sec": features.get("packets_per_sec", 0),
            "bytes_per_sec":   features.get("bytes_per_sec", 0),
            "syn_count":       features.get("syn_count", 0),
            "duration":        features.get("duration", 1),
        }])

        X          = self.scaler.transform(feature_df)
        prediction = self.model.predict(X)[0]
        score      = self.model.score_samples(X)[0]
        is_anomaly = prediction == -1

        if score < -0.15:
            confidence = "HIGH"
        elif score < -0.10:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"

        return {
            "is_anomaly":    is_anomaly,
            "anomaly_score": round(float(score), 4),
            "confidence":    confidence if is_anomaly else "NORMAL"
        }
