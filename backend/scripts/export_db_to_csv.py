#!/usr/bin/env python
import os
import sys
import pandas as pd

# Inject the backend directory into Python path to resolve imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.core.database import SessionLocal
from app.models.login_event import LoginEvent
from app.services.anomaly_service import AnomalyService

def main():
    print("=" * 80)
    print("      THREATWATCH-AI - DB TO CSV FEATURE EXPORTER")
    print("=" * 80)
    print("[*] Connecting to SQLite database to query events...")
    
    db = SessionLocal()
    try:
        events = db.query(LoginEvent).order_by(LoginEvent.timestamp.asc()).all()
        print(f"[+] Retrieved {len(events)} login events from database.")
        
        anomaly_service = AnomalyService(db)
        data_rows = []
        
        for idx, event in enumerate(events):
            if (idx + 1) % 500 == 0 or idx == 0:
                print(f"    - Processing event {idx + 1} of {len(events)}...")
            
            # Standardize OS to match label encoder classes
            os_str = (event.os or "Windows").lower()
            if "windows" in os_str:
                device_type = "Windows"
            elif "android" in os_str:
                device_type = "Android"
            elif "mac" in os_str:
                device_type = "macOS"
            elif "iphone" in os_str or "ios" in os_str:
                device_type = "iOS"
            else:
                device_type = "Linux"
                
            # Extract features using our official production extractor
            features = anomaly_service.extract_features(event)
            
            # Map index features to match the exact schema of train_model.py:
            # 5: failed_attempt_count, 7: vpn_detected, 8: tor_detected, 
            # 9: new_device, 10: new_location, 11: impossible_travel,
            # 16: login_frequency_7d, 17: avg_failed_7d
            data_rows.append({
                "user_id": str(event.user_id),
                "timestamp": str(event.timestamp),
                "ip_address": event.ip_address,
                "login_status": event.status,
                "country": event.country or "India",
                "city": event.city or "Pune",
                "device_type": device_type,
                "browser": event.browser or "Chrome",
                "failed_attempt_count": int(features[5]),
                "vpn_detected": int(features[7]),
                "tor_detected": int(features[8]),
                "new_device": int(features[9]),
                "new_location": int(features[10]),
                "impossible_travel": int(features[11]),
                "login_frequency_7d": float(features[16]),
                "avg_failed_7d": float(features[17])
            })
            
        print("[*] Reassembling feature rows into pandas DataFrame...")
        df = pd.DataFrame(data_rows)
        
        # Save to login_data.csv
        csv_path = "login_data.csv"
        df.to_csv(csv_path, index=False)
        print(f"[SUCCESS] Exported {len(df)} feature rows to '{csv_path}'!")
        print("=" * 80)
        
    except Exception as e:
        print(f"[!] Error exporting database to CSV: {e}")
        raise e
    finally:
        db.close()

if __name__ == "__main__":
    main()
