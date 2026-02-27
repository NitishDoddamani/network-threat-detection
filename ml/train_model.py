"""
Improved training — uses more realistic normal traffic patterns
to reduce false positives on actual network traffic.
"""
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os

os.makedirs("ml/models", exist_ok=True)

print("📊 Generating realistic normal traffic training data...")
np.random.seed(42)
n_samples = 10000   # more samples = better model

# ── Normal web browsing traffic ──
web_traffic = pd.DataFrame({
    "packet_count":    np.random.poisson(30, n_samples // 4),
    "byte_count":      np.random.normal(8000, 3000, n_samples // 4).clip(500),
    "unique_ports":    np.random.randint(1, 5, n_samples // 4),
    "unique_dst_ips":  np.random.randint(1, 8, n_samples // 4),
    "packets_per_sec": np.random.normal(15, 8, n_samples // 4).clip(1),
    "bytes_per_sec":   np.random.normal(3000, 1500, n_samples // 4).clip(100),
    "syn_count":       np.random.randint(0, 4, n_samples // 4),
    "duration":        np.random.uniform(2, 60, n_samples // 4),
})

# ── Streaming/download traffic ──
stream_traffic = pd.DataFrame({
    "packet_count":    np.random.poisson(200, n_samples // 4),
    "byte_count":      np.random.normal(50000, 20000, n_samples // 4).clip(1000),
    "unique_ports":    np.random.randint(1, 3, n_samples // 4),
    "unique_dst_ips":  np.random.randint(1, 3, n_samples // 4),
    "packets_per_sec": np.random.normal(80, 30, n_samples // 4).clip(5),
    "bytes_per_sec":   np.random.normal(20000, 8000, n_samples // 4).clip(1000),
    "syn_count":       np.random.randint(0, 2, n_samples // 4),
    "duration":        np.random.uniform(10, 120, n_samples // 4),
})

# ── Background system traffic ──
system_traffic = pd.DataFrame({
    "packet_count":    np.random.poisson(10, n_samples // 4),
    "byte_count":      np.random.normal(1000, 500, n_samples // 4).clip(100),
    "unique_ports":    np.random.randint(1, 3, n_samples // 4),
    "unique_dst_ips":  np.random.randint(1, 4, n_samples // 4),
    "packets_per_sec": np.random.normal(5, 3, n_samples // 4).clip(0.1),
    "bytes_per_sec":   np.random.normal(500, 200, n_samples // 4).clip(10),
    "syn_count":       np.random.randint(0, 2, n_samples // 4),
    "duration":        np.random.uniform(1, 30, n_samples // 4),
})

# ── P2P / high volume traffic ──
p2p_traffic = pd.DataFrame({
    "packet_count":    np.random.poisson(100, n_samples // 4),
    "byte_count":      np.random.normal(20000, 10000, n_samples // 4).clip(500),
    "unique_ports":    np.random.randint(1, 10, n_samples // 4),
    "unique_dst_ips":  np.random.randint(1, 10, n_samples // 4),
    "packets_per_sec": np.random.normal(40, 20, n_samples // 4).clip(2),
    "bytes_per_sec":   np.random.normal(8000, 4000, n_samples // 4).clip(100),
    "syn_count":       np.random.randint(0, 8, n_samples // 4),
    "duration":        np.random.uniform(5, 90, n_samples // 4),
})

# Combine all normal traffic types
normal_data = pd.concat([
    web_traffic, stream_traffic, system_traffic, p2p_traffic
], ignore_index=True)

print(f"✅ Generated {len(normal_data)} normal traffic samples")
print(f"   Web:    {len(web_traffic)} samples")
print(f"   Stream: {len(stream_traffic)} samples")
print(f"   System: {len(system_traffic)} samples")
print(f"   P2P:    {len(p2p_traffic)} samples")

# Scale features
scaler  = StandardScaler()
X_scaled = scaler.fit_transform(normal_data)

# Train with lower contamination (expect fewer anomalies)
print("\n🤖 Training improved Isolation Forest...")
model = IsolationForest(
    n_estimators=200,      # more trees = more accurate
    contamination=0.02,    # reduced from 0.05 → fewer false positives
    max_samples="auto",
    random_state=42,
    n_jobs=-1
)
model.fit(X_scaled)

# Save
joblib.dump(model,          "ml/models/isolation_forest.pkl")
joblib.dump(scaler,         "ml/models/scaler.pkl")
joblib.dump(list(normal_data.columns), "ml/models/feature_names.pkl")

print("✅ Improved model saved!")

# Test
print("\n🧪 Testing with various traffic types...")

test_cases = [
    # Normal cases — should NOT be anomalies
    ("Normal web browse",   [25,  5000,  2, 3,  12,  2000, 1, 10]),
    ("Normal streaming",    [200, 50000, 1, 1,  80,  20000,1, 30]),
    ("Normal system",       [8,   800,   1, 2,  4,   400,  0, 15]),
    # Attack cases — SHOULD be anomalies
    ("DDoS attack",         [5000,500000,2, 1,  2000,100000,0,1]),
    ("Port scan",           [100, 3000,  50,50, 200, 6000, 80,2]),
    ("Brute force SSH",     [50,  2000,  1, 1,  100, 4000, 45,1]),
]

test_df = pd.DataFrame(
    [t[1] for t in test_cases],
    columns=normal_data.columns
)
X_test  = scaler.transform(test_df)
preds   = model.predict(X_test)
scores  = model.score_samples(X_test)

for (label, _), pred, score in zip(test_cases, preds, scores):
    status = "🚨 ANOMALY" if pred == -1 else "✅ NORMAL "
    print(f"  {status} | {label:25} | score: {score:.3f}")

print("\n🎉 Improved model training complete!")
