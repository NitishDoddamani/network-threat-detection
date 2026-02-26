"""
Train Isolation Forest anomaly detection model on simulated normal traffic.
Run once: python3 ml/train_model.py
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os

os.makedirs("ml/models", exist_ok=True)

print("📊 Generating normal traffic training data...")

np.random.seed(42)
n_samples = 5000

# Simulate normal traffic features
normal_data = pd.DataFrame({
    "packet_count":    np.random.poisson(50, n_samples),
    "byte_count":      np.random.normal(5000, 2000, n_samples).clip(100),
    "unique_ports":    np.random.randint(1, 8, n_samples),
    "unique_dst_ips":  np.random.randint(1, 5, n_samples),
    "packets_per_sec": np.random.normal(20, 10, n_samples).clip(1),
    "bytes_per_sec":   np.random.normal(2000, 800, n_samples).clip(100),
    "syn_count":       np.random.randint(0, 5, n_samples),
    "duration":        np.random.uniform(1, 30, n_samples),
})

print(f"✅ Generated {len(normal_data)} normal traffic samples")
print(normal_data.describe())

# Scale features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(normal_data)

# Train Isolation Forest
print("\n🤖 Training Isolation Forest model...")
model = IsolationForest(
    n_estimators=100,
    contamination=0.05,   # expect 5% anomalies
    random_state=42,
    n_jobs=-1
)
model.fit(X_scaled)

# Save model and scaler
joblib.dump(model, "ml/models/isolation_forest.pkl")
joblib.dump(scaler, "ml/models/scaler.pkl")
joblib.dump(list(normal_data.columns), "ml/models/feature_names.pkl")

print("✅ Model saved to ml/models/isolation_forest.pkl")
print("✅ Scaler saved to ml/models/scaler.pkl")

# Test with anomalous samples
print("\n🧪 Testing model with anomalous traffic...")
anomalous = pd.DataFrame({
    "packet_count":    [5000, 1, 200],
    "byte_count":      [500000, 10, 50000],
    "unique_ports":    [100, 1, 50],
    "unique_dst_ips":  [50, 1, 20],
    "packets_per_sec": [2000, 0.1, 500],
    "bytes_per_sec":   [100000, 5, 25000],
    "syn_count":       [500, 0, 100],
    "duration":        [1, 60, 2],
})

X_anom = scaler.transform(anomalous)
preds = model.predict(X_anom)
scores = model.score_samples(X_anom)

labels = ["DDoS simulation", "Idle host", "Port Scan simulation"]
for label, pred, score in zip(labels, preds, scores):
    status = "🚨 ANOMALY" if pred == -1 else "✅ NORMAL"
    print(f"  {status} | {label} | score: {score:.3f}")

print("\n🎉 Training complete!")
