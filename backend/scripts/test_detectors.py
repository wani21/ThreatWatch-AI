#!/usr/bin/env python
"""
ThreatWatch-AI - Detection Engine Test Suite
Validates all five rule-based and behavioral detectors against synthetic threat scenarios.
"""

import sys
import os
import json
from datetime import datetime, timedelta
import uuid

# Inject the backend directory into the Python Path to resolve imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.core.database import SessionLocal
from app.models import User, Device, LoginEvent, UserBehaviorProfile
from app.services.detection_service import DetectionService

# Formatting Helpers
def print_section(title: str):
    print("\n" + "=" * 80)
    print(f" SCENARIO: {title}")
    print("=" * 80)

def print_json(data: dict):
    print(json.dumps(data, indent=2))

def print_detector_results(results: dict):
    print(f"\n[+] Total Composite Risk Score: {results['total_score']}")
    print(f"[+] Triggered Detectors: {results['triggered_detectors']}")
    print("\nIndividual Detector Breakdown:")
    for res in results["results"]:
        status = "[TRIGGERED]" if res["triggered"] else "[SAFE]"
        print(f"  - {res['detector_name'].upper():<15} | {status:<12} | Score: {res['score']:<3} | Reason: {res['reason']}")

def main():
    print("=" * 80)
    print(" ThreatWatch-AI Detection Engine Test Suite Initializing...")
    print("=" * 80)

    # Initialize DB Session
    db = SessionLocal()
    
    try:
        # Wrap everything in a transaction so we can roll back and keep the database clean
        # Start a transaction block
        db.begin_nested() # Create a savepoint

        # ---------------------------------------------------------------------
        # SETUP SHARED TEST ENTITIES
        # ---------------------------------------------------------------------
        print("[*] Creating temporary test user and default trusted environment...")
        
        # Test User
        test_user = User(
            id=uuid.uuid4(),
            username="test.security_99",
            email="test.security_99@threatwatch.ai",
            department="Security",
            role="Admin",
            created_at=datetime.now() - timedelta(days=60)
        )
        db.add(test_user)

        # Trusted Device
        trusted_device = Device(
            id=uuid.uuid4(),
            user_id=test_user.id,
            device_hash="trusted-fingerprint-sha256-hash",
            browser="Chrome",
            os="Windows",
            device_type="desktop",
            first_seen=datetime.now() - timedelta(days=30),
            trusted=True
        )
        db.add(trusted_device)

        # Baseline Behavioral Profile (Centered on Pune, India during standard daytime hours)
        user_profile = UserBehaviorProfile(
            id=uuid.uuid4(),
            user_id=test_user.id,
            avg_login_hour=12.0,  # 12:00 PM
            std_login_hour=1.0,   # Normal range is 10:00 AM - 2:00 PM (12.0 +/- 2.0*1.0)
            common_country="India",
            common_city="Pune",
            common_browser="Chrome",
            common_os="Windows",
            login_frequency_per_day=3.0
        )
        db.add(user_profile)
        db.flush()

        # ---------------------------------------------------------------------
        # 1. FAILED LOGIN SCENARIO
        # ---------------------------------------------------------------------
        print_section("1. Failed Login / Brute Force (>= 5 failures within 5 mins)")
        
        # Create 4 failed logins by the same user within the last 3 minutes
        base_time = datetime.now()
        for i in range(4):
            failed_attempt = LoginEvent(
                id=uuid.uuid4(),
                user_id=test_user.id,
                timestamp=base_time - timedelta(minutes=4 - i),
                status="failed",
                ip_address="192.168.1.100",
                country="India",
                country_code="IN",
                city="Pune",
                browser="Chrome",
                os="Windows",
                device_id=trusted_device.id,
                session_id=None,
                latitude=18.5204,
                longitude=73.8567
            )
            db.add(failed_attempt)
        db.flush()

        # Current 5th login attempt is also a failure, occurring now
        current_failed_event = LoginEvent(
            id=uuid.uuid4(),
            user_id=test_user.id,
            timestamp=base_time,
            status="failed",
            ip_address="192.168.1.100",
            country="India",
            country_code="IN",
            city="Pune",
            browser="Chrome",
            os="Windows",
            device_id=trusted_device.id,
            session_id=None,
            latitude=18.5204,
            longitude=73.8567
        )
        # Flush to DB so the queries inside the detector can see it
        db.add(current_failed_event)
        db.flush()

        # Run analysis
        failed_results = DetectionService.analyze_event(current_failed_event, db)
        print_detector_results(failed_results)

        # Assertions to verify correct logic
        failed_login_res = next(r for r in failed_results["results"] if r["detector_name"] == "failed_login")
        assert failed_login_res["triggered"] == True, "Failed login detector should have triggered!"
        assert failed_login_res["score"] == 40.0, "Failed login detector score should be 40!"

        # ---------------------------------------------------------------------
        # 2. NIGHT LOGIN SCENARIO (Unusual Timing)
        # ---------------------------------------------------------------------
        print_section("2. Night Login / Unusual Timing (3:00 AM Login vs 12:00 PM Avg)")
        
        # User avg login is 12:00 PM, std is 1.0. A login at 3:00 AM (hour = 3.0) is far outside normal window.
        night_time = base_time.replace(hour=3, minute=0, second=0)
        night_login_event = LoginEvent(
            id=uuid.uuid4(),
            user_id=test_user.id,
            timestamp=night_time,
            status="success",
            ip_address="192.168.1.100",
            country="India",
            country_code="IN",
            city="Pune",
            browser="Chrome",
            os="Windows",
            device_id=trusted_device.id,
            session_id=str(uuid.uuid4()),
            latitude=18.5204,
            longitude=73.8567
        )
        db.add(night_login_event)
        db.flush()

        night_results = DetectionService.analyze_event(night_login_event, db)
        print_detector_results(night_results)

        timing_res = next(r for r in night_results["results"] if r["detector_name"] == "timing")
        assert timing_res["triggered"] == True, "Timing detector should have triggered!"
        assert timing_res["score"] == 20.0, "Timing detector score should be 20!"

        # ---------------------------------------------------------------------
        # 3. NEW DEVICE SCENARIO
        # ---------------------------------------------------------------------
        print_section("3. New / Untrusted Device")
        
        # Login event with device_id = None (or a non-matching, untrusted device hash)
        new_device_event = LoginEvent(
            id=uuid.uuid4(),
            user_id=test_user.id,
            timestamp=base_time,
            status="success",
            ip_address="192.168.1.100",
            country="India",
            country_code="IN",
            city="Pune",
            browser="Safari",  # Changed browser
            os="macOS",        # Changed OS
            device_id=None,    # Untrusted/unrecognized
            session_id=str(uuid.uuid4()),
            latitude=18.5204,
            longitude=73.8567
        )
        db.add(new_device_event)
        db.flush()

        device_results = DetectionService.analyze_event(new_device_event, db)
        print_detector_results(device_results)

        device_res = next(r for r in device_results["results"] if r["detector_name"] == "device")
        assert device_res["triggered"] == True, "Device detector should have triggered!"
        assert device_res["score"] == 20.0, "Device detector score should be 20!"

        # ---------------------------------------------------------------------
        # 4. NEW LOCATION SCENARIO
        # ---------------------------------------------------------------------
        print_section("4. New / Unusual Location (Login from London vs India Baseline)")
        
        # Common city is Pune, India. Let's create a login from London, UK.
        new_location_event = LoginEvent(
            id=uuid.uuid4(),
            user_id=test_user.id,
            timestamp=base_time,
            status="success",
            ip_address="81.2.199.255",  # London IP simulation
            country="United Kingdom",
            country_code="GB",
            city="London",
            browser="Chrome",
            os="Windows",
            device_id=trusted_device.id,
            session_id=str(uuid.uuid4()),
            latitude=51.5074,
            longitude=-0.1278
        )
        db.add(new_location_event)
        db.flush()

        location_results = DetectionService.analyze_event(new_location_event, db)
        print_detector_results(location_results)

        location_res = next(r for r in location_results["results"] if r["detector_name"] == "location")
        assert location_res["triggered"] == True, "Location detector should have triggered!"
        assert location_res["score"] == 20.0, "Location detector score should be 20!"

        # ---------------------------------------------------------------------
        # 5. IMPOSSIBLE TRAVEL SCENARIO
        # ---------------------------------------------------------------------
        print_section("5. Impossible Travel (Pune to London in 1 Hour)")
        
        # Successful login A: Pune, India at 9:00 AM
        pune_time = base_time.replace(hour=9, minute=0, second=0)
        login_pune = LoginEvent(
            id=uuid.uuid4(),
            user_id=test_user.id,
            timestamp=pune_time,
            status="success",
            ip_address="115.112.0.1",
            country="India",
            country_code="IN",
            city="Pune",
            browser="Chrome",
            os="Windows",
            device_id=trusted_device.id,
            session_id=str(uuid.uuid4()),
            latitude=18.5204,
            longitude=73.8567
        )
        db.add(login_pune)
        db.flush()

        # Successful login B: London, United Kingdom at 10:00 AM (1 hour later)
        # Distance Pune to London is ~7,200 km. Required speed: 7,200 km/h, which is impossible (> 900 km/h).
        london_time = pune_time + timedelta(hours=1)
        login_london = LoginEvent(
            id=uuid.uuid4(),
            user_id=test_user.id,
            timestamp=london_time,
            status="success",
            ip_address="81.2.199.255",
            country="United Kingdom",
            country_code="GB",
            city="London",
            browser="Chrome",
            os="Windows",
            device_id=trusted_device.id,
            session_id=str(uuid.uuid4()),
            latitude=51.5074,
            longitude=-0.1278
        )
        db.add(login_london)
        db.flush()

        travel_results = DetectionService.analyze_event(login_london, db)
        print_detector_results(travel_results)

        travel_res = next(r for r in travel_results["results"] if r["detector_name"] == "travel")
        assert travel_res["triggered"] == True, "Travel detector should have triggered!"
        assert travel_res["score"] == 30.0, "Travel detector score should be 30!"

        print("\n" + "=" * 80)
        print(" [SUCCESS] ALL DETECTOR SCENARIOS PASSED SUCCESSFULLY!")
        print("=" * 80)

    except Exception as e:
        print(f"\n[!] Test Suite Failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        # Roll back the nested transaction (savepoint) to keep the DB perfectly clean
        print("\n[*] Rolling back transaction to ensure database stays clean...")
        db.rollback()
        db.close()
        print("[+] Test database changes successfully rolled back.")

if __name__ == "__main__":
    main()
