#!/usr/bin/env python
import os
import sys
from datetime import datetime, timedelta

# Inject parent directory to Python path to resolve imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sqlalchemy.orm import Session
from app.core.database import SessionLocal
from app.models.login_event import LoginEvent
from app.models.user import User
from app.models.device import Device
from app.models.user_profile import UserBehaviorProfile
from app.services.profile_builder import UserProfileBuilder
from app.services.anomaly_service import AnomalyService

def print_separator(char="=", length=75):
    print(char * length)

def format_event_details(event: LoginEvent) -> str:
    device_status = "Trusted Device" if event.device_id and event.device and event.device.trusted else "New/Untrusted Device"
    return (
        f"Event ID:  {event.id}\n"
        f"Timestamp: {event.timestamp} | Hour: {event.timestamp.hour:02d}:{event.timestamp.minute:02d}\n"
        f"Location:  {event.city}, {event.country} (IP: {event.ip_address})\n"
        f"Device:    {event.os} / {event.browser} ({device_status})\n"
        f"Status:    {event.status.upper()}"
    )

def main():
    print_separator()
    print("      THREATWATCH-AI - AI ANOMALY DETECTION LAYER VALIDATION SUITE")
    print_separator()

    db: Session = SessionLocal()
    try:
        # 1. Initialize Profiles
        print("[*] Step 1: Ensuring User Behavior Profiles are initialized...")
        profile_builder = UserProfileBuilder(db)
        profile_count = profile_builder.build_all_profiles()
        print(f"[+] Successfully built/updated {profile_count} user behavior profiles.")
        print_separator("-")

        # 2. Initialize and Train Isolation Forest Model
        print("[*] Step 2: Ensuring AI Isolation Forest Model is trained and active...")
        anomaly_service = AnomalyService(db)
        # ensure_trained will load all successful logins, compile features and fit the forest
        anomaly_service.ensure_trained()
        print("[+] Isolation Forest Model is fully loaded and ready.")
        print_separator("-")

        # 3. Locate Scenario Events
        print("[*] Step 3: Scanning database for representative scenario events...")

        scenarios = {}

        # Scenario 1: Normal Login (Daytime, Pune, Trusted Device)
        normal_event = (
            db.query(LoginEvent)
            .filter(
                LoginEvent.status == "success",
                LoginEvent.city == "Pune",
                LoginEvent.device_id.isnot(None)
            )
            .order_by(LoginEvent.timestamp.desc())
            .first()
        )
        if normal_event:
            scenarios["1. Normal Login (Pune, Trusted Device)"] = normal_event

        # Scenario 2: Night Login (Unusual hour: 2:00 AM - 4:59 AM)
        all_success_events = db.query(LoginEvent).filter(LoginEvent.status == "success").all()
        night_event = None
        for event in all_success_events:
            if 2 <= event.timestamp.hour <= 4:
                night_event = event
                break
        if night_event:
            scenarios["2. Night Login (02:00 AM - 04:59 AM)"] = night_event

        # Scenario 3: New Device Login (Success from Untrusted Device)
        new_device_event = (
            db.query(LoginEvent)
            .filter(
                LoginEvent.status == "success",
                LoginEvent.device_id.is_(None),
                LoginEvent.city == "Pune"
            )
            .order_by(LoginEvent.timestamp.desc())
            .first()
        )
        if new_device_event:
            scenarios["3. New Device Login (Untrusted Device)"] = new_device_event

        # Scenario 4: New Location Login (Daytime success from London/New York)
        new_loc_event = (
            db.query(LoginEvent)
            .filter(
                LoginEvent.status == "success",
                LoginEvent.city.in_(["London", "New York"])
            )
            .order_by(LoginEvent.timestamp.desc())
            .first()
        )
        # Check if the location is indeed new/atypical for the user
        if new_loc_event:
            scenarios["4. New Location Login (Atypical Geography)"] = new_loc_event

        # Scenario 5: Impossible Travel Login
        # Search for a user who had a login in Pune/Mumbai followed rapidly by one in London/NY
        impossible_travel_event = None
        for event in all_success_events:
            if event.city in ["London", "New York"] and event.device_id is None:
                # Find if this same user had a login within 30 minutes in Pune or Mumbai
                time_limit_start = event.timestamp - timedelta(minutes=30)
                preceding_event = (
                    db.query(LoginEvent)
                    .filter(
                        LoginEvent.user_id == event.user_id,
                        LoginEvent.status == "success",
                        LoginEvent.city.in_(["Pune", "Mumbai"]),
                        LoginEvent.timestamp >= time_limit_start,
                        LoginEvent.timestamp < event.timestamp
                    )
                    .first()
                )
                if preceding_event:
                    impossible_travel_event = event
                    break
        if impossible_travel_event:
            scenarios["5. Impossible Travel Login (Velocity Anomaly)"] = impossible_travel_event

        # Report search findings
        for name, event in scenarios.items():
            print(f"    [+] Found representative event for {name}")

        missing_scenarios = [s for s in [
            "1. Normal Login (Pune, Trusted Device)",
            "2. Night Login (02:00 AM - 04:59 AM)",
            "3. New Device Login (Untrusted Device)",
            "4. New Location Login (Atypical Geography)",
            "5. Impossible Travel Login (Velocity Anomaly)"
        ] if s not in scenarios]

        if missing_scenarios:
            print(f"[!] Warning: Could not find pre-existing events in DB for: {missing_scenarios}")
            print("[*] Creating programmatic mock scenarios to complete test validation...")
            # If any specific events are missing, we inject a test user and seed the exact scenario
            # to guarantee the test script is completely self-contained!
            mock_user = db.query(User).filter(User.username == "anomaly.tester").first()
            if not mock_user:
                mock_user = User(
                    username="anomaly.tester",
                    email="anomaly.tester@threatwatch.ai",
                    role="Employee",
                    department="Security"
                )
                db.add(mock_user)
                db.commit()
                db.refresh(mock_user)
            
            # Create a trusted device for the mock user
            mock_device = db.query(Device).filter(Device.user_id == mock_user.id).first()
            if not mock_device:
                mock_device = Device(
                    user_id=mock_user.id,
                    device_hash="mock_trusted_device_hash_123",
                    browser="Chrome",
                    os="Windows",
                    device_type="desktop",
                    trusted=True
                )
                db.add(mock_device)
                db.commit()
                db.refresh(mock_device)

            # Establish behavior profile baseline (Pune daytime logins)
            mock_profile = db.query(UserBehaviorProfile).filter(UserBehaviorProfile.user_id == mock_user.id).first()
            if not mock_profile:
                mock_profile = UserBehaviorProfile(
                    user_id=mock_user.id,
                    avg_login_hour=12.0,
                    std_login_hour=1.0,
                    common_city="Pune",
                    common_country="India",
                    common_browser="Chrome",
                    common_os="Windows",
                    login_frequency_per_day=2.0
                )
                db.add(mock_profile)
                db.commit()

            # Programmatically inject missing scenario events
            base_time = datetime.now() - timedelta(days=1)
            
            if "1. Normal Login (Pune, Trusted Device)" not in scenarios:
                ev = LoginEvent(
                    user_id=mock_user.id,
                    timestamp=base_time.replace(hour=12, minute=0),
                    status="success",
                    ip_address="115.112.50.1",
                    country="India",
                    city="Pune",
                    browser="Chrome",
                    os="Windows",
                    device_id=mock_device.id,
                    latitude=18.5204,
                    longitude=73.8567
                )
                db.add(ev)
                db.commit()
                scenarios["1. Normal Login (Pune, Trusted Device)"] = ev
                
            if "2. Night Login (02:00 AM - 04:59 AM)" not in scenarios:
                ev = LoginEvent(
                    user_id=mock_user.id,
                    timestamp=base_time.replace(hour=3, minute=15),
                    status="success",
                    ip_address="115.112.50.2",
                    country="India",
                    city="Pune",
                    browser="Chrome",
                    os="Windows",
                    device_id=mock_device.id,
                    latitude=18.5204,
                    longitude=73.8567
                )
                db.add(ev)
                db.commit()
                scenarios["2. Night Login (02:00 AM - 04:59 AM)"] = ev
                
            if "3. New Device Login (Untrusted Device)" not in scenarios:
                ev = LoginEvent(
                    user_id=mock_user.id,
                    timestamp=base_time.replace(hour=13, minute=30),
                    status="success",
                    ip_address="115.112.50.3",
                    country="India",
                    city="Pune",
                    browser="Firefox",  # Different browser
                    os="Linux",         # Different OS
                    device_id=None,     # Untrusted
                    latitude=18.5204,
                    longitude=73.8567
                )
                db.add(ev)
                db.commit()
                scenarios["3. New Device Login (Untrusted Device)"] = ev

            if "4. New Location Login (Atypical Geography)" not in scenarios:
                ev = LoginEvent(
                    user_id=mock_user.id,
                    timestamp=base_time.replace(hour=14, minute=0),
                    status="success",
                    ip_address="8.8.8.8",
                    country="United States",
                    city="New York",
                    browser="Chrome",
                    os="Windows",
                    device_id=mock_device.id,
                    latitude=40.7128,
                    longitude=-74.0060
                )
                db.add(ev)
                db.commit()
                scenarios["4. New Location Login (Atypical Geography)"] = ev

            if "5. Impossible Travel Login (Velocity Anomaly)" not in scenarios:
                # Event A in Pune
                ev_a = LoginEvent(
                    user_id=mock_user.id,
                    timestamp=base_time.replace(hour=15, minute=0),
                    status="success",
                    ip_address="115.112.50.4",
                    country="India",
                    city="Pune",
                    browser="Chrome",
                    os="Windows",
                    device_id=mock_device.id,
                    latitude=18.5204,
                    longitude=73.8567
                )
                db.add(ev_a)
                db.commit()
                
                # Event B in New York 10 mins later
                ev_b = LoginEvent(
                    user_id=mock_user.id,
                    timestamp=base_time.replace(hour=15, minute=10),
                    status="success",
                    ip_address="8.8.8.9",
                    country="United States",
                    city="New York",
                    browser="Chrome",
                    os="Windows",
                    device_id=None,
                    latitude=40.7128,
                    longitude=-74.0060
                )
                db.add(ev_b)
                db.commit()
                scenarios["5. Impossible Travel Login (Velocity Anomaly)"] = ev_b

            print("[+] Programmatic mock scenarios injected successfully.")
            print_separator("-")

        # 4. Run Anomaly Service on each scenario and display scores
        print("[*] Step 4: Initiating ML Anomaly Detection on scenarios...")
        print_separator("-")

        for scenario_name, event in sorted(scenarios.items()):
            print(f"SCENARIO: {scenario_name}")
            print_separator(".", 40)
            print(format_event_details(event))
            
            # Perform detection
            result = anomaly_service.detect_anomaly(event.id)
            
            print_separator(".", 40)
            score = result["anomaly_score"]
            is_anomalous = result["is_anomalous"]
            
            # Design visual indicators for anomaly status
            status_indicator = "!!! [ANOMALOUS]" if is_anomalous else "+++ [NORMAL]"
            print(f"RESULT: Anomaly Score = {score:.4f} | Status = {status_indicator}")
            print_separator("-")

        print("\n[+] AI Anomaly Detection Validation Suite execution completed successfully.")
        print_separator()

    except Exception as e:
        print(f"[!] Error during test execution: {e}")
        import traceback
        traceback.print_exc()
    finally:
        db.close()

if __name__ == "__main__":
    main()
