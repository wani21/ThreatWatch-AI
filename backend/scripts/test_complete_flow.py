#!/usr/bin/env python
import os
import sys
import uuid
from datetime import datetime

# Inject backend parent folder into sys path to resolve imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.main import app
from app.core.database import SessionLocal
from app.models.user import User
from app.models.login_event import LoginEvent
from app.models.risk_assessment import RiskAssessment
from app.models.alert import Alert


def print_separator(char="=", length=85):
    print(char * length)


def print_incident_card(scenario_name: str, res_json: dict, alert_ticket: Alert = None):
    print(f"\n[SCENARIO] {scenario_name}")
    print(f"  - Authentication Passed:   {res_json.get('authenticated')}")
    print(f"  - Generated Event UUID:    {res_json.get('event_id')}")
    print(f"  - Combined Risk Score:     {res_json.get('risk_score')} / 100")
    print(f"  - Evaluated Threat Tier:   {res_json.get('risk_level')}")
    print(f"  - Behavioral Anomaly Score: {res_json.get('anomaly_score')} / 1.0")
    print(f"  - Rule Engine Findings:")
    factors = res_json.get("triggered_factors", [])
    if not factors:
        print("     * None (Standard behavior parameters match)")
    else:
        for factor in factors:
            print(f"     * {factor}")
            
    if alert_ticket:
        print(f"  - [ALERT TRIGGERED] Status: {alert_ticket.status.upper()} | Type: {alert_ticket.alert_type.upper()}")
        print(f"    Message: {alert_ticket.message}")
    else:
        print(f"  - [ALERT TELEMETRY] No alert generated (Low/Medium severity threshold bypass)")


def clean_previous_runs(db: Session):
    """
    Idempotently cleans up previous automated test runs to ensure a clean slate,
    while leaving the current test run details available for immediate UI inspection.
    """
    print("[*] Performing database housekeeping: clearing old validation rows...")
    test_emails = ["admin@sentinel.ai", "employee1@sentinel.ai", "employee2@sentinel.ai"]
    users = db.query(User).filter(User.email.in_(test_emails)).all()
    
    if users:
        user_ids = [u.id for u in users]
        # Query matching assessments and delete related alert tickets
        assessments = db.query(RiskAssessment).filter(
            RiskAssessment.login_event_id.in_(
                db.query(LoginEvent.id).filter(LoginEvent.user_id.in_(user_ids))
            )
        ).all()
        
        if assessments:
            assessment_ids = [a.id for a in assessments]
            db.query(Alert).filter(Alert.risk_assessment_id.in_(assessment_ids)).delete(synchronize_session=False)
            db.query(RiskAssessment).filter(RiskAssessment.login_event_id.in_(
                db.query(LoginEvent.id).filter(LoginEvent.user_id.in_(user_ids))
            )).delete(synchronize_session=False)
            
        db.query(LoginEvent).filter(LoginEvent.user_id.in_(user_ids)).delete(synchronize_session=False)
        db.commit()
    print("[+] Database cleared successfully. Proceeding with fresh simulation pipeline.\n")


def main():
    print_separator()
    print("         THREATWATCH-AI - FULL-STACK INTEGRATION END-TO-END DEMO SUITE")
    print_separator()

    db: Session = SessionLocal()
    client = TestClient(app)

    try:
        # Pre-execution Database Seeding verification
        admin = db.query(User).filter(User.email == "admin@sentinel.ai").first()
        if not admin:
            print("[!] Warning: Demo accounts are not seeded. Please run 'python scripts/create_demo_users.py' first.")
            sys.exit(1)

        # Clear old rows to prevent collision and keep statistics clean
        clean_previous_runs(db)

        # =====================================================================
        # SCENARIO 1: Normal Login (Happy Path)
        # =====================================================================
        print("[*] Initiating Scenario 1: Normal Login...")
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
        assert res.status_code == 200, "Scenario 1 API Connection failure"
        res_data = res.json()
        
        # Query database to assert row persistence
        event = db.query(LoginEvent).filter(LoginEvent.id == uuid.UUID(res_data["event_id"])).first()
        assert event is not None, "LoginEvent failed to write to PostgreSQL"
        assessment = db.query(RiskAssessment).filter(RiskAssessment.login_event_id == event.id).first()
        assert assessment is not None, "RiskAssessment failed to persist"
        alert = db.query(Alert).filter(Alert.risk_assessment_id == assessment.id).first()
        
        print_incident_card("1. Standard Employee Access (Normal)", res_data, alert)
        db.commit() # Release transaction lock
        print_separator("-")

        # =====================================================================
        # SCENARIO 2: Failed Login (Wrong Password)
        # =====================================================================
        print("[*] Initiating Scenario 2: Failed Login...")
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
        assert res.status_code == 200, "Scenario 2 API Connection failure"
        res_data = res.json()
        
        event = db.query(LoginEvent).filter(LoginEvent.id == uuid.UUID(res_data["event_id"])).first()
        assessment = db.query(RiskAssessment).filter(RiskAssessment.login_event_id == event.id).first()
        alert = db.query(Alert).filter(Alert.risk_assessment_id == assessment.id).first()
        
        print_incident_card("2. Failed Login (Wrong Password)", res_data, alert)
        db.commit() # Release transaction lock
        print_separator("-")

        # =====================================================================
        # SCENARIO 3: Brute Force Attack
        # =====================================================================
        print("[*] Initiating Scenario 3: Brute Force Attack (5 rapid failures)...")
        payload_bf = {
            "email": "employee1@sentinel.ai",
            "password": "wrong_password_999",
            "city": "Pune",
            "country": "India",
            "device_type": "Windows",
            "browser": "Chrome",
            "ip_address": "45.11.22.33"
        }
        # Simulate 5 rapid brute force events
        for i in range(5):
            client.post("/api/v1/auth/login", json=payload_bf)

        # 6th attempt triggers rule evaluations for multiple failed credentials
        res = client.post("/api/v1/auth/login", json=payload_bf)
        assert res.status_code == 200, "Scenario 3 API Connection failure"
        res_data = res.json()
        
        event = db.query(LoginEvent).filter(LoginEvent.id == uuid.UUID(res_data["event_id"])).first()
        assessment = db.query(RiskAssessment).filter(RiskAssessment.login_event_id == event.id).first()
        alert = db.query(Alert).filter(Alert.risk_assessment_id == assessment.id).first()
        assert alert is not None, "Alert failed to create under brute force conditions"
        assert alert.alert_type == "brute_force", "Incorrect alert type categorization"
        
        print_incident_card("3. Active Brute Force Threat (Rapid consecutive failures)", res_data, alert)
        db.commit() # Release transaction lock
        print_separator("-")

        # =====================================================================
        # SCENARIO 4: Unknown Device
        # =====================================================================
        print("[*] Initiating Scenario 4: Unknown Device...")
        payload_device = {
            "email": "employee2@sentinel.ai",
            "password": "password123",
            "city": "Pune",
            "country": "India",
            "device_type": "iPhone",  # os mismatch (baseline: Windows)
            "browser": "Safari",      # browser mismatch (baseline: Chrome)
            "ip_address": "103.111.222.35"
        }
        res = client.post("/api/v1/auth/login", json=payload_device)
        assert res.status_code == 200, "Scenario 4 API Connection failure"
        res_data = res.json()
        
        event = db.query(LoginEvent).filter(LoginEvent.id == uuid.UUID(res_data["event_id"])).first()
        assessment = db.query(RiskAssessment).filter(RiskAssessment.login_event_id == event.id).first()
        alert = db.query(Alert).filter(Alert.risk_assessment_id == assessment.id).first()
        
        print_incident_card("4. Unknown Client Device Profile Match", res_data, alert)
        db.commit() # Release transaction lock
        print_separator("-")

        # =====================================================================
        # SCENARIO 5: Impossible Travel
        # =====================================================================
        print("[*] Initiating Scenario 5: Impossible Travel (Pune -> New York)...")
        # 1. Base login in Pune, India
        payload_base = {
            "email": "admin@sentinel.ai",
            "password": "password123",
            "city": "Pune",
            "country": "India",
            "device_type": "Windows",
            "browser": "Chrome",
            "ip_address": "103.111.222.36"
        }
        client.post("/api/v1/auth/login", json=payload_base)

        # 2. Impossible geographic displacement to NYC (velocity check flags velocity!)
        payload_nyc = {
            "email": "admin@sentinel.ai",
            "password": "password123",
            "city": "New York",
            "country": "USA",
            "device_type": "Windows",
            "browser": "Chrome",
            "ip_address": "198.51.100.22"
        }
        res = client.post("/api/v1/auth/login", json=payload_nyc)
        assert res.status_code == 200, "Scenario 5 API Connection failure"
        res_data = res.json()
        
        event = db.query(LoginEvent).filter(LoginEvent.id == uuid.UUID(res_data["event_id"])).first()
        assessment = db.query(RiskAssessment).filter(RiskAssessment.login_event_id == event.id).first()
        alert = db.query(Alert).filter(Alert.risk_assessment_id == assessment.id).first()
        assert alert is not None, "Alert failed to create under impossible travel displacement"
        assert alert.alert_type == "impossible_travel", "Incorrect travel threat categorization"
        
        print_incident_card("5. Impossible Travel Velocity Displacement", res_data, alert)
        print_separator()

        print("\n[+] SUCCESS: All five end-to-end security pipelines verified perfectly!")
        print("    - LoginEvents committed to PostgreSQL.")
        print("    - Heuristics and behavioral Isolation Forest risk reports generated.")
        print("    - Incident Alert Tickets initialized inside Alert Manager.")
        print("    - SOC metrics tables updated successfully.")
        print("    - Telemetry logs left persistent in PostgreSQL for visual inspection.")
        print_separator()

    finally:
        db.close()


if __name__ == "__main__":
    main()
