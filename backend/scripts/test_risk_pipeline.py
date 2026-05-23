#!/usr/bin/env python
import os
import sys
from datetime import datetime, timedelta
import uuid

# Inject parent directory to Python path to resolve imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sqlalchemy.orm import Session
from sqlalchemy import text
from app.core.database import SessionLocal
from app.models.login_event import LoginEvent
from app.models.user import User
from app.models.device import Device
from app.models.user_profile import UserBehaviorProfile
from app.models.risk_assessment import RiskAssessment
from app.services.risk_assessment_service import RiskAssessmentService


def print_separator(char="=", length=75):
    print(char * length)


def format_event_details(event: LoginEvent) -> str:
    device_status = (
        "Trusted Device"
        if event.device_id and event.device and event.device.trusted
        else "New/Untrusted Device"
    )
    return (
        f"Event ID:  {event.id}\n"
        f"Timestamp: {event.timestamp} | Hour: {event.timestamp.hour:02d}:{event.timestamp.minute:02d}\n"
        f"Location:  {event.city}, {event.country} (IP: {event.ip_address} | ISP: {event.isp or 'Unknown'})\n"
        f"Device:    {event.os} / {event.browser} ({device_status})\n"
        f"Status:    {event.status.upper()}"
    )


def print_results(report: dict, persisted: RiskAssessment) -> None:
    print("\n--- RESULTS ---")
    print(f"Anomaly Score:   {report['anomaly_score']} / 1.0")
    print(f"Risk Score:      {report['risk_score']} / 100")
    print(f"Risk Level:      {report['risk_level']}")
    print(f"Explainable Reasons:")
    if not report['reasons']:
        print("  - None (Normal behavior baseline matches)")
    else:
        for reason in report['reasons']:
            print(f"  - {reason}")
    
    print(f"Database Verification:")
    if persisted:
        print(f"  [OK] Persisted successfully.")
        print(f"  [OK] Failed Login Score:    {persisted.failed_login_score}")
        print(f"  [OK] Unusual Time Score:    {persisted.unusual_time_score}")
        print(f"  [OK] New Device Score:      {persisted.new_device_score}")
        print(f"  [OK] New Location Score:    {persisted.new_location_score}")
        print(f"  [OK] AI Anomaly Score:      {persisted.anomaly_score}")
        print(f"  [OK] Risk Level In DB:      {persisted.risk_level}")
        print(f"  [OK] Reasons in DB:         {persisted.risk_factors}")
    else:
        print(f"  [FAIL] FAILED to persist in database!")


def main():
    print_separator()
    print("      THREATWATCH-AI - REAL-TIME ML RISK PIPELINE VALIDATION")
    print_separator()

    db: Session = SessionLocal()
    try:
        # 1. Self-Healing Schema Alteration
        print("[*] Step 1: Running schema verification...")
        try:
            db.execute(text("ALTER TABLE risk_assessments ADD COLUMN IF NOT EXISTS risk_factors JSON;"))
            db.commit()
            print("[+] Database schema is up to date.")
        except Exception as e:
            db.rollback()
            print(f"[!] Warning: Schema upgrade failed, proceeding anyway: {e}")

        # 2. Setup Isolated Test User and Behavior Profile
        print("[*] Step 2: Ensuring isolated test user 'risk.tester' exists...")
        mock_user = db.query(User).filter(User.username == "risk.tester").first()
        if not mock_user:
            mock_user = User(
                username="risk.tester",
                email="risk.tester@threatwatch.ai",
                role="Employee",
                department="Engineering"
            )
            db.add(mock_user)
            db.commit()
            db.refresh(mock_user)
            print("[+] Test user 'risk.tester' created.")
        else:
            print("[+] Test user 'risk.tester' verified.")

        # Create trusted device
        mock_device = db.query(Device).filter(Device.user_id == mock_user.id).first()
        if not mock_device:
            mock_device = Device(
                user_id=mock_user.id,
                device_hash="risk_trusted_device_hash_999",
                browser="Chrome",
                os="Windows",
                device_type="desktop",
                trusted=True
            )
            db.add(mock_device)
            db.commit()
            db.refresh(mock_device)
            print("[+] Trusted device created for test user.")
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
            # Reset profile values to ensure consistent heuristic rules behavior
            mock_profile.avg_login_hour = 12.0
            mock_profile.std_login_hour = 1.0
            mock_profile.common_city = "Pune"
            mock_profile.common_country = "India"
            mock_profile.common_browser = "Chrome"
            mock_profile.common_os = "Windows"
            mock_profile.login_frequency_per_day = 3.0
            db.commit()
            print("[+] Behavioral profile baseline reset.")

        print_separator("-")

        # 3. Commencing isolated threat scenarios evaluations
        print("[*] Step 3: Commencing isolated threat scenarios evaluations...")
        print_separator("-")
        
        base_time = datetime.now() - timedelta(hours=12)
        risk_service = RiskAssessmentService(db)

        # ==========================================
        # SCENARIO 1: Normal Login
        # ==========================================
        print("Executing Risk Scoring for: Scenario 1: Normal Login")
        normal_event = LoginEvent(
            user_id=mock_user.id,
            timestamp=base_time.replace(hour=12, minute=15),
            status="success",
            ip_address="103.111.222.33",
            country="India",
            city="Pune",
            browser="Chrome",
            os="Windows",
            device_id=mock_device.id,
            isp="Reliance Jio",
            latitude=18.5204,
            longitude=73.8567
        )
        db.add(normal_event)
        db.commit()
        db.refresh(normal_event)

        print(format_event_details(normal_event))
        report = risk_service.evaluate_and_persist(normal_event.id)
        persisted = db.query(RiskAssessment).filter(RiskAssessment.login_event_id == normal_event.id).first()
        print_results(report, persisted)

        # Cleanup Scenario 1
        db.query(RiskAssessment).filter(RiskAssessment.login_event_id == normal_event.id).delete()
        db.query(LoginEvent).filter(LoginEvent.id == normal_event.id).delete()
        db.commit()
        print_separator("-")

        # ==========================================
        # SCENARIO 2: Night Login
        # ==========================================
        print("Executing Risk Scoring for: Scenario 2: Night Login")
        night_event = LoginEvent(
            user_id=mock_user.id,
            timestamp=base_time.replace(hour=3, minute=10),
            status="success",
            ip_address="103.111.222.34",
            country="India",
            city="Pune",
            browser="Chrome",
            os="Windows",
            device_id=mock_device.id,
            isp="Reliance Jio",
            latitude=18.5204,
            longitude=73.8567
        )
        db.add(night_event)
        db.commit()
        db.refresh(night_event)

        print(format_event_details(night_event))
        report = risk_service.evaluate_and_persist(night_event.id)
        persisted = db.query(RiskAssessment).filter(RiskAssessment.login_event_id == night_event.id).first()
        print_results(report, persisted)

        # Cleanup Scenario 2
        db.query(RiskAssessment).filter(RiskAssessment.login_event_id == night_event.id).delete()
        db.query(LoginEvent).filter(LoginEvent.id == night_event.id).delete()
        db.commit()
        print_separator("-")

        # ==========================================
        # SCENARIO 3: Brute Force Attack
        # ==========================================
        print("Executing Risk Scoring for: Scenario 3: Brute Force Attack")
        brute_force_base_time = base_time.replace(hour=14, minute=0)
        # Seed 5 failed login attempts
        failed_events_ids = []
        for i in range(5):
            failed_ev = LoginEvent(
                user_id=mock_user.id,
                timestamp=brute_force_base_time + timedelta(minutes=i),
                status="failed",
                ip_address="45.11.22.33",
                country="India",
                city="Pune",
                browser="Chrome",
                os="Windows",
                device_id=mock_device.id,
                isp="Reliance Jio",
                latitude=18.5204,
                longitude=73.8567
            )
            db.add(failed_ev)
            db.commit()
            failed_events_ids.append(failed_ev.id)

        # Trigger event (the 6th failed attempt)
        brute_trigger = LoginEvent(
            user_id=mock_user.id,
            timestamp=brute_force_base_time + timedelta(minutes=5),
            status="failed",
            ip_address="45.11.22.33",
            country="India",
            city="Pune",
            browser="Chrome",
            os="Windows",
            device_id=mock_device.id,
            isp="Reliance Jio",
            latitude=18.5204,
            longitude=73.8567
        )
        db.add(brute_trigger)
        db.commit()
        db.refresh(brute_trigger)

        print(format_event_details(brute_trigger))
        report = risk_service.evaluate_and_persist(brute_trigger.id)
        persisted = db.query(RiskAssessment).filter(RiskAssessment.login_event_id == brute_trigger.id).first()
        print_results(report, persisted)

        # Cleanup Scenario 3
        db.query(RiskAssessment).filter(RiskAssessment.login_event_id == brute_trigger.id).delete()
        db.query(LoginEvent).filter(LoginEvent.id == brute_trigger.id).delete()
        db.query(LoginEvent).filter(LoginEvent.id.in_(failed_events_ids)).delete(synchronize_session=False)
        db.commit()
        print_separator("-")

        # ==========================================
        # SCENARIO 4: Unknown Device
        # ==========================================
        print("Executing Risk Scoring for: Scenario 4: Unknown Device")
        unknown_device_event = LoginEvent(
            user_id=mock_user.id,
            timestamp=base_time.replace(hour=13, minute=30),
            status="success",
            ip_address="103.111.222.35",
            country="India",
            city="Pune",
            browser="Safari",
            os="iOS",
            device_id=None,  # Untrusted
            isp="Reliance Jio",
            latitude=18.5204,
            longitude=73.8567
        )
        db.add(unknown_device_event)
        db.commit()
        db.refresh(unknown_device_event)

        print(format_event_details(unknown_device_event))
        report = risk_service.evaluate_and_persist(unknown_device_event.id)
        persisted = db.query(RiskAssessment).filter(RiskAssessment.login_event_id == unknown_device_event.id).first()
        print_results(report, persisted)

        # Cleanup Scenario 4
        db.query(RiskAssessment).filter(RiskAssessment.login_event_id == unknown_device_event.id).delete()
        db.query(LoginEvent).filter(LoginEvent.id == unknown_device_event.id).delete()
        db.commit()
        print_separator("-")

        # ==========================================
        # SCENARIO 5: Impossible Travel
        # ==========================================
        print("Executing Risk Scoring for: Scenario 5: Impossible Travel")
        # 1. Daytime login from Pune
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

        # 2. Login from New York 10 minutes later (untrusted device, US country)
        impossible_travel_event = LoginEvent(
            user_id=mock_user.id,
            timestamp=base_time.replace(hour=10, minute=10),
            status="success",
            ip_address="198.51.100.22",
            country="USA",
            city="New York",
            browser="Chrome",
            os="Windows",
            device_id=None,
            isp="Verizon Wireless",
            latitude=40.7128,
            longitude=-74.0060
        )
        db.add(impossible_travel_event)
        db.commit()
        db.refresh(impossible_travel_event)

        print(format_event_details(impossible_travel_event))
        report = risk_service.evaluate_and_persist(impossible_travel_event.id)
        persisted = db.query(RiskAssessment).filter(RiskAssessment.login_event_id == impossible_travel_event.id).first()
        print_results(report, persisted)

        # Cleanup Scenario 5
        db.query(RiskAssessment).filter(RiskAssessment.login_event_id == impossible_travel_event.id).delete()
        db.query(LoginEvent).filter(LoginEvent.id == impossible_travel_event.id).delete()
        db.query(LoginEvent).filter(LoginEvent.id == travel_pune_event.id).delete()
        db.commit()
        print_separator("-")

    finally:
        # Cleanup isolated tester structures to keep the database tidy
        print("[*] Cleaning up isolated test user baseline and structures...")
        try:
            if 'mock_user' in locals() and mock_user:
                db.query(UserBehaviorProfile).filter(UserBehaviorProfile.user_id == mock_user.id).delete()
                db.query(Device).filter(Device.user_id == mock_user.id).delete()
                db.query(User).filter(User.id == mock_user.id).delete()
                db.commit()
                print("[+] Cleanup complete.")
        except Exception as e:
            db.rollback()
            print(f"[!] Cleanup failed: {e}")
        db.close()


if __name__ == "__main__":
    main()
