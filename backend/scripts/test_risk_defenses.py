#!/usr/bin/env python
import os
import sys
import time
import json
import urllib.request
import urllib.error
from datetime import datetime

# Inject parent directory to Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sqlalchemy.orm import Session
from app.core.database import SessionLocal
from app.models.login_event import LoginEvent
from app.models.risk_assessment import RiskAssessment
from app.models.user import User

BASE_URL = "http://127.0.0.1:8001/api/v1"

def api_post(endpoint, data):
    url = f"{BASE_URL}{endpoint}"
    req = urllib.request.Request(
        url,
        data=json.dumps(data).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req) as res:
            status = res.status
            body_bytes = res.read()
            body_str = body_bytes.decode("utf-8")
            try:
                return status, json.loads(body_str)
            except json.JSONDecodeError:
                print(f"[-] JSON decode error for successful request. Status: {status}, Body: {body_str}")
                return status, {"raw_body": body_str}
    except urllib.error.HTTPError as e:
        body_bytes = e.read()
        body_str = body_bytes.decode("utf-8")
        try:
            return e.code, json.loads(body_str)
        except json.JSONDecodeError:
            print(f"[-] JSON decode error for HTTPError. Code: {e.code}, Body: {body_str}")
            return e.code, {"raw_body": body_str}
    except Exception as e:
        return 500, {"detail": str(e)}

def clean_locks_and_mfa():
    """Helper to clear recent events/locks so tests run cleanly"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == "20230140302@mitaoe.ac.in").first()
        if user:
            # Delete recent assessments and login events for this user to start fresh
            events = db.query(LoginEvent).filter(LoginEvent.user_id == user.id).all()
            for e in events:
                if e.risk_assessment:
                    db.delete(e.risk_assessment)
                db.delete(e)
            db.commit()
            print("[*] Cleanup complete. Database cleared for test account.")
    finally:
        db.close()

def get_latest_otp():
    """Retrieve the generated OTP from the database for verification testing"""
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == "20230140302@mitaoe.ac.in").first()
        if user:
            latest_event = db.query(LoginEvent).filter(
                LoginEvent.user_id == user.id,
                LoginEvent.status == "mfa_pending"
            ).order_by(LoginEvent.timestamp.desc()).first()
            if latest_event:
                return latest_event.id, latest_event.otp_code
        return None, None
    finally:
        db.close()

def run_tests():
    print("=" * 80)
    print("      THREATWATCH-AI - END-TO-END SECURITY DEFENSE VERIFICATION")
    print("=" * 80)

    # 0. Clean recent logins
    clean_locks_and_mfa()

    # Test Credentials
    user_email = "20230140302@mitaoe.ac.in"
    user_pass = "password123"

    # Scenario 1: Low Risk Login (Pune, Chrome, Windows)
    print("\n[+] SCENARIO 1: Legitimate daytime login (Low Risk)...")
    payload1 = {
        "email": user_email,
        "password": user_pass,
        "city": "Pune",
        "country": "India",
        "device_type": "Windows",
        "browser": "Chrome",
        "ip_address": "103.111.222.36"
    }
    code, resp = api_post("/auth/login", payload1)
    print(f"    - Response Status: {code}")
    print(f"    - Authenticated:   {resp.get('authenticated')}")
    print(f"    - Risk Score:      {resp.get('risk_score')}")
    print(f"    - Risk Level:      {resp.get('risk_level')}")
    print(f"    - MFA Required:    {resp.get('mfa_required')}")
    assert code == 200, "Scenario 1 failed"
    assert resp.get("authenticated") is True, "User should be authenticated"
    assert resp.get("risk_score") < 45, "Risk score should be low"

    # Scenario 2: Medium Risk Login (Mumbai, Firefox) -> Should trigger lockout on subsequent attempts
    print("\n[+] SCENARIO 2: Ingress from Mumbai, Firefox (Medium Risk)...")
    payload2 = {
        "email": user_email,
        "password": user_pass,
        "city": "Mumbai",
        "country": "India",
        "device_type": "Windows",
        "browser": "Firefox",
        "ip_address": "103.120.200.44"
    }
    code, resp = api_post("/auth/login", payload2)
    print(f"    - Response Status: {code}")
    print(f"    - Authenticated:   {resp.get('authenticated')}")
    print(f"    - Risk Score:      {resp.get('risk_score')}")
    print(f"    - Risk Level:      {resp.get('risk_level')}")
    print(f"    - Factors:         {resp.get('triggered_factors')}")
    assert code == 200, "Scenario 2 failed"
    assert resp.get("authenticated") is True, "User should be authenticated"
    assert 45 <= resp.get("risk_score") <= 75, "Risk score should be medium"

    # Scenario 3: Enforcing 5-Minute Lockout
    print("\n[+] SCENARIO 3: Verify 5-minute lockout enforcement on subsequent login...")
    payload3 = {
        "email": user_email,
        "password": user_pass,
        "city": "Pune",
        "country": "India",
        "device_type": "Windows",
        "browser": "Chrome",
        "ip_address": "103.111.222.36"
    }
    # Wait a second to allow timestamp order
    time.sleep(1)
    code, resp = api_post("/auth/login", payload3)
    print(f"    - Response Status: {code}")
    print(f"    - Error Detail:    {resp.get('detail')}")
    assert code == 403, "Lockout check failed to block login attempt"
    assert "locked" in resp.get("detail").lower(), "Error message should mention account lockout"
    print("    [SUCCESS] Account successfully blocked by lockout sentinel!")

    # Scenario 4: Severe Risk Login (New York, Safari, macOS) -> Should trigger 2FA OTP
    # First, let's bypass the lockout rule in the database so we can test the 2FA flow.
    # To bypass it, we delete the medium risk assessment record.
    print("\n[*] Resetting lockout record to initiate MFA test...")
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == user_email).first()
        if user:
            # Delete only the medium risk assessment event to clear lockout
            medium_events = db.query(LoginEvent).join(RiskAssessment).filter(
                LoginEvent.user_id == user.id,
                RiskAssessment.total_score >= 45.0,
                RiskAssessment.total_score <= 75.0
            ).all()
            for me in medium_events:
                db.delete(me.risk_assessment)
                db.delete(me)
            db.commit()
    finally:
        db.close()

    print("\n[+] SCENARIO 4: Ingress from New York, macOS, Safari (Severe Risk/Impossible Travel)...")
    payload4 = {
        "email": user_email,
        "password": user_pass,
        "city": "New York",
        "country": "USA",
        "device_type": "MacOS",
        "browser": "Safari",
        "ip_address": "198.51.100.22"
    }
    code, resp = api_post("/auth/login", payload4)
    print(f"    - Response Status: {code}")
    print(f"    - Authenticated:   {resp.get('authenticated')}")
    print(f"    - MFA Required:    {resp.get('mfa_required')}")
    print(f"    - Risk Score:      {resp.get('risk_score')}")
    print(f"    - Risk Level:      {resp.get('risk_level')}")
    print(f"    - Factors:         {resp.get('triggered_factors')}")
    assert code == 200, "Scenario 4 failed"
    assert resp.get("authenticated") is False, "User authentication should be intercepted"
    assert resp.get("mfa_required") is True, "2FA must be required"
    assert resp.get("risk_score") > 75, "Risk score must cross the severe threshold"
    print("    [SUCCESS] Ingress successfully intercepted! 2FA OTP triggered.")

    # Scenario 5: MFA Verification
    print("\n[+] SCENARIO 5: Submit correct 6-digit OTP code to verify-2fa route...")
    event_id, otp_code = get_latest_otp()
    print(f"    - Extracted OTP Code: {otp_code} for Event ID: {event_id}")
    assert otp_code is not None, "Failed to retrieve OTP from test database"

    payload5 = {
        "event_id": str(event_id),
        "otp_code": otp_code
    }
    code, resp = api_post("/auth/verify-2fa", payload5)
    print(f"    - Response Status: {code}")
    print(f"    - Authenticated:   {resp.get('authenticated')}")
    print(f"    - Message:         {resp.get('message')}")
    assert code == 200, "MFA verification request failed"
    assert resp.get("authenticated") is True, "MFA verification should succeed and authorize user"
    print("    [SUCCESS] 2FA session authorized!")

    # Scenario 6: Admin Bypass Check
    print("\n[+] SCENARIO 6: Verify Admin account bypasses lockout and MFA checks...")
    # Admin login from London (unusual) at 3 AM (unusual timing)
    admin_payload = {
        "email": "admin@abc.com",
        "password": "pass@123",
        "city": "London",
        "country": "United Kingdom",
        "device_type": "MacOS",
        "browser": "Safari",
        "ip_address": "82.165.12.33"
    }
    code, resp = api_post("/auth/login", admin_payload)
    print(f"    - Response Status: {code}")
    print(f"    - Authenticated:   {resp.get('authenticated')}")
    print(f"    - Risk Score:      {resp.get('risk_score')}")
    print(f"    - Risk Level:      {resp.get('risk_level')}")
    print(f"    - Role:            {resp.get('role')}")
    assert code == 200, "Admin authentication failed"
    assert resp.get("authenticated") is True, "Admin credentials must authenticate successfully"
    assert resp.get("role") == "Administrator", "Role must be Administrator"
    print("    [SUCCESS] Administrator successfully authenticated without defense triggers!")

    print("\n" + "=" * 80)
    print("      ALL END-TO-END SECURITY DEFENSE VERIFICATION TESTS PASSED SUCCESSFULLY!")
    print("=" * 80)

if __name__ == "__main__":
    run_tests()
