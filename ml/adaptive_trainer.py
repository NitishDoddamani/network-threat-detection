"""
Adaptive Learning Engine.
Collects confirmed threat features, retrains model periodically,
and tracks accuracy improvement over time.
"""
import os
import json
import time
import joblib
import threading
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ── CONFIG ──
BASE_DIR           = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TRAINING_DATA_DIR  = os.path.join(BASE_DIR, "ml", "training_data")
MODEL_DIR          = os.path.join(BASE_DIR, "ml", "models")
THREAT_DATA_FILE   = os.path.join(TRAINING_DATA_DIR, "confirmed_threats.json")
NORMAL_DATA_FILE   = os.path.join(TRAINING_DATA_DIR, "normal_traffic.json")
METRICS_FILE       = os.path.join(TRAINING_DATA_DIR, "model_metrics.json")
RETRAIN_INTERVAL   = 300        # retrain every 5 minutes
MIN_NEW_SAMPLES    = 10         # minimum new samples before retraining

os.makedirs(TRAINING_DATA_DIR, exist_ok=True)
os.makedirs(MODEL_DIR, exist_ok=True)

FEATURE_COLUMNS = [
    "packet_count", "byte_count", "unique_ports",
    "unique_dst_ips", "packets_per_sec", "bytes_per_sec",
    "syn_count", "duration"
]

class AdaptiveTrainer:
    def __init__(self):
        self.threat_samples  = self._load_json(THREAT_DATA_FILE, [])
        self.normal_samples  = self._load_json(NORMAL_DATA_FILE, [])
        self.metrics_history = self._load_json(METRICS_FILE, [])
        self.new_since_last  = 0
        self.lock            = threading.Lock()
        self.version         = len(self.metrics_history) + 1
        print(f"🤖 Adaptive trainer initialized | version: {self.version} | threat samples: {len(self.threat_samples)}")

    def _load_json(self, path, default):
        try:
            if os.path.exists(path):
                with open(path) as f:
                    return json.load(f)
        except Exception:
            pass
        return default

    def _save_json(self, path, data):
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def _extract_features(self, raw_features: dict) -> dict | None:
        """Extract only ML feature columns from raw features."""
        try:
            return {col: float(raw_features.get(col, 0)) for col in FEATURE_COLUMNS}
        except Exception:
            return None

    def add_threat_sample(self, threat: dict):
        """Add a confirmed threat to training data."""
        raw = threat.get("raw_features", {})
        if not raw:
            return

        features = self._extract_features(raw)
        if not features:
            return

        features["threat_type"] = threat.get("threat_type", "Unknown")
        features["severity"]    = threat.get("severity", "LOW")
        features["timestamp"]   = datetime.utcnow().isoformat()

        with self.lock:
            self.threat_samples.append(features)
            self.new_since_last += 1
            # Keep last 5000 samples
            self.threat_samples = self.threat_samples[-5000:]
            self._save_json(THREAT_DATA_FILE, self.threat_samples)

        print(f"📝 Threat sample saved | total: {len(self.threat_samples)} | type: {features['threat_type']}")

    def add_normal_sample(self, features: dict):
        """Add a normal traffic sample to training data."""
        extracted = self._extract_features(features)
        if not extracted:
            return

        extracted["timestamp"] = datetime.utcnow().isoformat()

        with self.lock:
            self.normal_samples.append(extracted)
            self.normal_samples = self.normal_samples[-10000:]
            self._save_json(NORMAL_DATA_FILE, self.normal_samples)

    def retrain(self) -> bool:
        """Retrain the Isolation Forest with accumulated data."""
        with self.lock:
            if self.new_since_last < MIN_NEW_SAMPLES:
                print(f"⏳ Not enough new samples ({self.new_since_last}/{MIN_NEW_SAMPLES}) — skipping retrain")
                return False

            print(f"\n🔄 Starting adaptive retraining...")
            print(f"   Threat samples: {len(self.threat_samples)}")
            print(f"   Normal samples: {len(self.normal_samples)}")

            # Build training data
            # Load base normal traffic
            base_normal = self._generate_base_normal(5000)

            # Add collected normal samples
            if self.normal_samples:
                collected_df = pd.DataFrame(self.normal_samples)[FEATURE_COLUMNS]
                train_df = pd.concat([base_normal, collected_df], ignore_index=True)
            else:
                train_df = base_normal

            print(f"   Total training samples: {len(train_df)}")

            # Scale and train
            scaler   = StandardScaler()
            X_scaled = scaler.fit_transform(train_df)

            model = IsolationForest(
                n_estimators=200,
                contamination=0.02,
                random_state=int(time.time()) % 1000,
                n_jobs=-1
            )
            model.fit(X_scaled)

            # Evaluate on threat samples
            accuracy = self._evaluate(model, scaler)

            # Save new model
            self.version += 1
            joblib.dump(model,  os.path.join(MODEL_DIR, "isolation_forest.pkl"))
            joblib.dump(scaler, os.path.join(MODEL_DIR, "scaler.pkl"))

            # Save backup with version
            joblib.dump(model,  os.path.join(MODEL_DIR, f"isolation_forest_v{self.version}.pkl"))

            # Log metrics
            metric = {
                "version":        self.version,
                "timestamp":      datetime.utcnow().isoformat(),
                "threat_samples": len(self.threat_samples),
                "normal_samples": len(train_df),
                "threat_detection_rate": accuracy,
                "new_samples_added": self.new_since_last,
            }
            self.metrics_history.append(metric)
            self._save_json(METRICS_FILE, self.metrics_history)

            self.new_since_last = 0
            print(f"✅ Retrained! Version: {self.version} | Detection rate: {accuracy:.1%}")
            return True

    def _evaluate(self, model, scaler) -> float:
        """Evaluate model on known threat samples."""
        if not self.threat_samples:
            return 0.0
        try:
            df      = pd.DataFrame(self.threat_samples)[FEATURE_COLUMNS]
            X       = scaler.transform(df)
            preds   = model.predict(X)
            # Count how many threat samples are correctly flagged as anomalies
            detected = sum(1 for p in preds if p == -1)
            return detected / len(preds)
        except Exception as e:
            print(f"⚠️  Evaluation error: {e}")
            return 0.0

    def _generate_base_normal(self, n: int) -> pd.DataFrame:
        """Generate synthetic normal traffic baseline."""
        np.random.seed(42)
        return pd.DataFrame({
            "packet_count":    np.random.poisson(50, n),
            "byte_count":      np.random.normal(8000, 4000, n).clip(100),
            "unique_ports":    np.random.randint(1, 8, n),
            "unique_dst_ips":  np.random.randint(1, 6, n),
            "packets_per_sec": np.random.normal(25, 15, n).clip(0.5),
            "bytes_per_sec":   np.random.normal(4000, 2000, n).clip(50),
            "syn_count":       np.random.randint(0, 5, n),
            "duration":        np.random.uniform(1, 60, n),
        })

    def get_metrics(self) -> dict:
        """Return current model metrics."""
        return {
            "current_version":   self.version,
            "threat_samples":    len(self.threat_samples),
            "normal_samples":    len(self.normal_samples),
            "retraining_history": self.metrics_history[-10:],
            "new_since_retrain": self.new_since_last,
            "next_retrain_in":   max(0, MIN_NEW_SAMPLES - self.new_since_last),
        }

    def start_auto_retrain(self):
        """Start background thread that retrains periodically."""
        def _loop():
            while True:
                time.sleep(RETRAIN_INTERVAL)
                try:
                    self.retrain()
                except Exception as e:
                    print(f"❌ Retrain error: {e}")

        t = threading.Thread(target=_loop, daemon=True)
        t.start()
        print(f"🔄 Auto-retrain scheduled every {RETRAIN_INTERVAL//60} minutes")

# Global instance
adaptive_trainer = AdaptiveTrainer()
