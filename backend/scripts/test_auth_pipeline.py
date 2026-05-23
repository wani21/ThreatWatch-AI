#!/usr/bin/env python
import os
import sys
from datetime import datetime, timedelta
import uuid

# Inject parent directory to Python path to resolve imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session
from app.main import app
from app.core.database import SessionLocal
from app.models.login_event import LoginEvent
from app.models.risk_assessment import RiskAssessment
from app.models.user import User


def print_separator(char="=", length=75):
    print(char * length)


def print_verdict(scenario_name: str, response_json: dict) -> None:
    print(f"\nScenario: {scenario_name}")
    print(f"  Authenticated:     {response_json.get('authenticated')}")
    print(f"  Login Event ID:    {response_json.get('event_id')}")
    print(f"  AI Anomaly Score:  {response_json.get('anomaly_score')} / 1.0")
    print(f"  Risk Score:        {response_json.get('risk_score')} / 100")
    print(f"  Risk Level:        {response_json.get('risk_level')}")
    print(f"  Triggered Factors:")
    factors = response_json.get("triggered_factors", [])
    if not factors:
        print("    - None (Normal baseline matches)")
    else:
        for factor in factors:
            print(f"    - {factor}")


def clean_test_events(db: Session, email: str) -> None:
    """
    Cleans up all injected login events and risk assessments for a given email
    to avoid cluttering the PostgreSQL database after validation runs.
    """
    user = db.query(User).filter(User.email == email).first()
    if user:
        db.query(RiskAssessment).filter(
            RiskAssessment.login_event_id.in_(
                db.query(LoginEvent.id).filter(LoginEvent.user_id == user.id)
            )
        ).delete(synchronize_session=False)
        db.query(LoginEvent).filter(LoginEvent.user_id == user.id).delete()
        db.commit()


def main():
    print_separator()
    print("      THREATWATCH-AI - END-TO-END AUTH SIMULATION PIPELINE")
    print_separator()

    db: Session = SessionLocal()
    client = TestClient(app)

    try:
        # ==========================================
        # SCENARIO 1: Normal Login
        # ==========================================
        print("[*] Simulating Scenario 1: Normal Login...")
        payload_normal = {
            "email": "admin@sentinel.ai",
            "password": "password123",
            "city": "Pune",
            "country": "India",
            "device_type": "Windows",
            "browser": "Chrome",
            "ip_address": "103.111.222.33"
        }
        res = client.post("/api/v1/auth/login", json=payload_normal)
        if res.status_code == 200:
            print_verdict("1. Successful Login (Normal)", res.json())
        else:
            print(f"[FAIL] Scenario 1 error (status code {res.status_code}): {res.text}")
        
        # Clean up S1 immediately
        clean_test_events(db, "admin@sentinel.ai")
        print_separator("-")

        # ==========================================
        # SCENARIO 2: Wrong Password
        # ==========================================
        print("[*] Simulating Scenario 2: Wrong Password...")
        payload_wrong_pwd = {
            "email": "employee1@sentinel.ai",
            "password": "wrong_password_999",
            "city": "Pune",
            "country": "India",
            "device_type": "Windows",
            "browser": "Chrome",
            "ip_address": "103.111.222.33"
        }
        res = client.post("/api/v1/auth/login", json=payload_wrong_pwd)
        if res.status_code == 200:
            print_verdict("2. Failed Login (Wrong Password)", res.json())
        else:
            print(f"[FAIL] Scenario 2 error (status code {res.status_code}): {res.text}")

        # Clean up S2 immediately
        clean_test_events(db, "employee1@sentinel.ai")
        print_separator("-")

        # ==========================================
        # SCENARIO 3: Five Consecutive Failures (Brute Force)
        # ==========================================
        print("[*] Simulating Scenario 3: Five Consecutive Failures (Brute Force)...")
        # Trigger 5 rapid password failures consecutively
        payload_failure = {
            "email": "employee1@sentinel.ai",
            "password": "wrong_password_999",
            "city": "Pune",
            "country": "India",
            "device_type": "Windows",
            "browser": "Chrome",
            "ip_address": "45.11.22.33"
        }
        
        for i in range(5):
            client.post("/api/v1/auth/login", json=payload_failure)
            
        # The 6th attempt (brute force triggers failed login detector checks)
        res = client.post("/api/v1/auth/login", json=payload_failure)
        if res.status_code == 200:
            print_verdict("3. Brute Force Threat (consecutive failures)", res.json())
        else:
            print(f"[FAIL] Scenario 3 error (status code {res.status_code}): {res.text}")

        # Clean up S3 immediately
        clean_test_events(db, "employee1@sentinel.ai")
        print_separator("-")

        # ==========================================
        # SCENARIO 4: Unknown Device
        # ==========================================
        print("[*] Simulating Scenario 4: Unknown Device...")
        payload_device = {
            "email": "employee2@sentinel.ai",
            "password": "password123",
            "city": "Pune",
            "country": "India",
            "device_type": "iPhone",  # Device mismatch (baseline os: Windows)
            "browser": "Safari",      # Browser mismatch (baseline browser: Chrome)
            "ip_address": "103.111.222.35"
        }
        res = client.post("/api/v1/auth/login", json=payload_device)
        if res.status_code == 200:
            print_verdict("4. Unknown Device Login", res.json())
        else:
            print(f"[FAIL] Scenario 4 error (status code {res.status_code}): {res.text}")

        # Clean up S4 immediately
        clean_test_events(db, "employee2@sentinel.ai")
        print_separator("-")

        # ==========================================
        # SCENARIO 5: Impossible Travel
        # ==========================================
        print("[*] Simulating Scenario 5: Impossible Travel...")
        # 1. First event in Pune, India
        payload_pune = {
            "email": "admin@sentinel.ai",
            "password": "password123",
            "city": "Pune",
            "country": "India",
            "device_type": "Windows",
            "browser": "Chrome",
            "ip_address": "103.111.222.36"
        }
        client.post("/api/v1/auth/login", json=payload_pune)

        # 2. Consecutive event in New York, USA instantly (impossible travel velocity!)
        payload_ny = {
            "email": "admin@sentinel.ai",
            "password": "password123",
            "city": "New York",
            "country": "USA",
            "device_type": "Windows",
            "browser": "Chrome",
            "ip_address": "198.51.100.22"
        }
        res = client.post("/api/v1/auth/login", json=payload_ny)
        if res.status_code == 200:
            print_verdict("5. Impossible Travel (Pune -> New York)", res.json())
        else:
            print(f"[FAIL] Scenario 5 error (status code {res.status_code}): {res.text}")

        # Clean up S5 immediately
        clean_test_events(db, "admin@sentinel.ai")
        print_separator("-")

    finally:
        db.close()


if __name__ == "__main__":
    main()
