#!/usr/bin/env python
import os
import sys
import json
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler, LabelEncoder

# Inject the backend directory into Python path to resolve imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

FEATURE_COLS = [
    "login_hour", "day_of_week", "is_weekend", "is_night", "is_business",
    "failed_attempt_count", "login_failed",
    "vpn_detected", "tor_detected",
    "new_device", "new_location", "impossible_travel",
    "country_enc", "city_enc", "device_type_enc", "browser_enc",
    "login_frequency_7d", "avg_failed_7d"
]

def main():
    print("=" * 80)
    print("      THREATWATCH-AI - HEADLESS ML TRAINING PIPELINE")
    print("=" * 80)
    
    # 1. Load exported dataset
    csv_path = "login_data.csv"
    if not os.path.exists(csv_path):
        print(f"[!] Error: {csv_path} does not exist. Run export_db_to_csv.py first.")
        sys.exit(1)
        
    df = pd.read_csv(csv_path)
    print(f"[+] Loaded {len(df)} rows from {csv_path}.")
    
    # 2. Extract engineered timestamp features
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df["login_hour"] = df["timestamp"].dt.hour
    df["day_of_week"] = df["timestamp"].dt.dayofweek
    df["is_weekend"] = (df["day_of_week"] >= 5).astype(int)
    df["is_night"] = df["login_hour"].apply(lambda h: 1 if (h < 6 or h >= 22) else 0)
    df["is_business"] = df["login_hour"].apply(lambda h: 1 if 9 <= h <= 17 else 0)
    
    # 2b. Map login status to binary flag
    df["login_failed"] = (df["login_status"].str.lower() == "failed").astype(int)
    
    # 3. Label encode categorical features and save encoders
    le_dict = {}
    for col in ["country", "city", "device_type", "browser"]:
        le = LabelEncoder()
        df[col + "_enc"] = le.fit_transform(df[col].astype(str))
        le_dict[col] = le
    print("[+] Label encoding completed successfully.")
    
    # 4. Prepare feature matrix X
    X = df[FEATURE_COLS].copy()
    X = X.fillna(X.median(numeric_only=True))
    
    # 5. Scale features using StandardScaler
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    print("[+] Feature scaling completed successfully.")
    
    # 6. Fit IsolationForest model
    # contamination = 0.10 (Standard 10% contamination rate for threat datasets)
    print("[*] Training Isolation Forest model (n_estimators=150)...")
    iso_forest = IsolationForest(
        n_estimators=150,
        contamination=0.10,
        random_state=42,
        n_jobs=-1
    )
    iso_forest.fit(X_scaled)
    print("[+] Isolation Forest fit completed successfully.")
    
    # 7. Normalize decision scores to [0.0, 1.0] and compute bounds
    raw_scores = iso_forest.decision_function(X_scaled)
    score_min = float(raw_scores.min())
    score_max = float(raw_scores.max())
    
    # 8. Save artifacts directly to app/ml/models/
    base_dir = os.path.dirname(os.path.abspath(__file__))
    models_dir = os.path.join(os.path.dirname(base_dir), "app", "ml", "models")
    os.makedirs(models_dir, exist_ok=True)
    
    joblib.dump(iso_forest, os.path.join(models_dir, "isolation_forest.pkl"))
    joblib.dump(scaler, os.path.join(models_dir, "scaler.pkl"))
    joblib.dump(le_dict, os.path.join(models_dir, "label_encoders.pkl"))
    
    # Save features list
    with open(os.path.join(models_dir, "feature_cols.json"), "w") as f:
        json.dump(FEATURE_COLS, f, indent=2)
        
    # Save score bounds
    bounds = {"score_min": score_min, "score_max": score_max}
    with open(os.path.join(models_dir, "score_bounds.json"), "w") as f:
        json.dump(bounds, f, indent=2)
        
    print("\n[SUCCESS] Model artifacts successfully trained and saved to:")
    print(f"    - {models_dir}/")
    print(f"    - Normalization Bounds: Min={score_min:.4f}, Max={score_max:.4f}")
    print("=" * 80)

if __name__ == "__main__":
    main()
