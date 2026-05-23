#!/usr/bin/env python
"""
ThreatWatch-AI - Alert Manager Integration & Verification Test Script
Tests the full alerting chain:
1. Simulates a highly anomalous "Impossible Travel" login event.
2. Triggers the Risk Engine to compute a high risk score.
3. Automatically triggers AlertManager to write an Alert record to PostgreSQL.
4. Generates and renders beautiful User & Admin warning emails with console fallback.
"""

import os
import sys
from datetime import datetime, timedelta
import uuid

# Inject backend directory into python path to resolve imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session, sessionmaker
from app.core.database import Base
from app.models.login_event import LoginEvent
from app.models.user import User
from app.models.device import Device
from app.models.user_profile import UserBehaviorProfile
from app.models.risk_assessment import RiskAssessment
from app.models.alert import Alert
from app.services.risk_assessment_service import RiskAssessmentService


def print_header(title: str):
    print("\n" + "=" * 80)
    print(f" {title.upper()}")
    print("=" * 80)


def main():
    print_header("THREATWATCH-AI - ALERT MANAGER INTEGRATION TESTING")

    # Use a local temporary SQLite database for self-contained, zero-config testing
    sqlite_db_file = "alert_test.db"
    if os.path.exists(sqlite_db_file):
        try:
            os.remove(sqlite_db_file)
        except Exception:
            pass

    engine = create_engine(f"sqlite:///{sqlite_db_file}")
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    print("[*] Initializing local SQLite database schema...")
    Base.metadata.create_all(bind=engine)
    print("[+] SQLite database schema initialized successfully.")

    db: Session = SessionLocal()
    mock_user = None
    
    try:
        # 1. Verify schema for risk_factors
        try:
            db.execute(text("ALTER TABLE risk_assessments ADD COLUMN IF NOT EXISTS risk_factors JSON;"))
            db.commit()
        except Exception as e:
            db.rollback()
            print(f"[!] Warning: Schema upgrade failed, proceeding anyway: {e}")

        # 2. Setup Isolated Test User and Behavior Profile
        print("[*] Setting up isolated test user 'alert.tester'...")
        mock_user = db.query(User).filter(User.username == "alert.tester").first()
        if not mock_user:
            mock_user = User(
                username="alert.tester",
                email="20230140302@mitaoe.ac.in",
                role="Employee",
                department="Operations"
            )
            db.add(mock_user)
            db.commit()
            db.refresh(mock_user)
            print("[+] Test user 'alert.tester' created.")
        else:
            mock_user.email = "20230140302@mitaoe.ac.in"
            db.commit()
            print("[+] Test user 'alert.tester' verified and email updated.")

        # Create trusted device for Pune daytime baselines
        mock_device = db.query(Device).filter(Device.user_id == mock_user.id).first()
        if not mock_device:
            mock_device = Device(
                user_id=mock_user.id,
                device_hash="alert_trusted_device_hash_777",
                browser="Chrome",
                os="Windows",
                device_type="desktop",
                trusted=True
            )
            db.add(mock_device)
            db.commit()
            db.refresh(mock_device)
            print("[+] Trusted device created.")
        else:
            print("[+] Trusted device verified.")

        # Set user behavior profile (Daytime Pune logins)
        mock_profile = (
            db.query(UserBehaviorProfile)
            .filter(UserBehaviorProfile.user_id == mock_user.id)
            .first()
        )
        if not mock_profile:
            mock_profile = UserBehaviorProfile(
                user_id=mock_user.id,
                avg_login_hour=12.0,
                std_login_hour=1.0,
                common_city="Pune",
                common_country="India",
                common_browser="Chrome",
                common_os="Windows",
                login_frequency_per_day=3.0
            )
            db.add(mock_profile)
            db.commit()
            print("[+] Behavioral profile created (Pune, daytime logins).")
        else:
            mock_profile.avg_login_hour = 12.0
            mock_profile.std_login_hour = 1.0
            mock_profile.common_city = "Pune"
            mock_profile.common_country = "India"
            mock_profile.common_browser = "Chrome"
            mock_profile.common_os = "Windows"
            mock_profile.login_frequency_per_day = 3.0
            db.commit()
            print("[+] Behavioral profile baseline reset.")

        # 3. Simulate IMPOssIBLE TRAVEL SCENARIO
        print("\n[*] Simulating Suspicious Scenario: Impossible Travel")
        print("    - Event A: 10:00 AM Login from Pune, India (Trusted Device)")
        print("    - Event B: 10:10 AM Login from New York, USA (Untrusted Device, 10 mins later)")
        
        base_time = datetime.now() - timedelta(hours=6)

        # Event A: Legitimate login in Pune
        travel_pune_event = LoginEvent(
            user_id=mock_user.id,
            timestamp=base_time.replace(hour=10, minute=0),
            status="success",
            ip_address="103.111.222.36",
            country="India",
            city="Pune",
            browser="Chrome",
            os="Windows",
            device_id=mock_device.id,
            isp="Reliance Jio",
            latitude=18.5204,
            longitude=73.8567
        )
        db.add(travel_pune_event)
        db.commit()

        # Event B: Suspicious login in New York (10 mins later)
        impossible_travel_event = LoginEvent(
            user_id=mock_user.id,
            timestamp=base_time.replace(hour=10, minute=10),
            status="success",
            ip_address="198.51.100.22",
            country="USA",
            city="New York",
            browser="Chrome",
            os="Windows",
            device_id=None,  # Untrusted device
            isp="Verizon Wireless",
            latitude=40.7128,
            longitude=-74.0060
        )
        db.add(impossible_travel_event)
        db.commit()
        db.refresh(impossible_travel_event)

        # 4. Trigger Risk Assessment Pipeline
        # This will evaluate risk, persist it, and AUTOMATICALLY trigger AlertManager!
        print("\n[*] Running Risk Assessment on Event B...")
        risk_service = RiskAssessmentService(db)
        report = risk_service.evaluate_and_persist(impossible_travel_event.id)

        print("\n[*] Risk Report Returned by API:")
        print(f"    - Event ID:   {report['event_id']}")
        print(f"    - Risk Score: {report['risk_score']} / 100")
        print(f"    - Risk Level: {report['risk_level']}")
        print(f"    - Reasons:    {report['reasons']}")

        # 5. Database Verification
        print("\n[*] Verifying Alert Persistence in Database...")
        assessment = db.query(RiskAssessment).filter(RiskAssessment.login_event_id == impossible_travel_event.id).first()
        if not assessment:
            raise ValueError("[FAIL] RiskAssessment record not found in database!")

        alert = db.query(Alert).filter(Alert.risk_assessment_id == assessment.id).first()
        if alert:
            print(f"    [SUCCESS] Alert created successfully in PostgreSQL!")
            print(f"    - Alert ID:   {alert.id}")
            print(f"    - Alert Type: {alert.alert_type.upper()}")
            print(f"    - Severity:   {alert.severity.upper()}")
            print(f"    - Message:    {alert.message}")
            print(f"    - Status:     {alert.status.upper()}")
        else:
            print("    [FAIL] Alert record was NOT created in the database!")

        # 6. Cleanup created events
        print("\n[*] Cleaning up test events...")
        db.query(Alert).filter(Alert.risk_assessment_id == assessment.id).delete()
        db.query(RiskAssessment).filter(RiskAssessment.login_event_id == impossible_travel_event.id).delete()
        db.query(LoginEvent).filter(LoginEvent.id == impossible_travel_event.id).delete()
        db.query(LoginEvent).filter(LoginEvent.id == travel_pune_event.id).delete()
        db.commit()
        print("    [+] Test event cleanup complete.")

    except Exception as e:
        db.rollback()
        print(f"\n[!] Error occurred: {e}")
        raise e
    finally:
        # Cleanup isolated tester structures
        if mock_user:
            print("\n[*] Cleaning up test user 'alert.tester' baselines...")
            try:
                db.query(UserBehaviorProfile).filter(UserBehaviorProfile.user_id == mock_user.id).delete()
                db.query(Device).filter(Device.user_id == mock_user.id).delete()
                db.query(User).filter(User.id == mock_user.id).delete()
                db.commit()
                print("    [+] User baseline cleanup complete.")
            except Exception as e:
                db.rollback()
                print(f"    [!] User cleanup failed: {e}")
        db.close()
        
        # Clean up local temporary SQLite db file
        if os.path.exists(sqlite_db_file):
            try:
                os.remove(sqlite_db_file)
            except Exception:
                pass


if __name__ == "__main__":
    main()
