#!/usr/bin/env python
import os
import sys
import uuid
from datetime import datetime, timedelta

# Inject parent directory to Python path to resolve imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sqlalchemy.orm import Session
from sqlalchemy import text
from app.core.database import SessionLocal, Base, engine
from app.models.user import User
from app.models.device import Device
from app.models.user_profile import UserBehaviorProfile
from app.models.login_event import LoginEvent
from app.models.risk_assessment import RiskAssessment
from app.models.alert import Alert


def main():
    print("=" * 75)
    print("      THREATWATCH-AI - HACKATHON DEMO DATABASE SEEDER")
    print("=" * 75)

    print("[*] Initializing database schema...")
    Base.metadata.create_all(bind=engine)
    print("[+] Database schema verified / initialized.")

    db: Session = SessionLocal()
    try:
        # 1. Idempotently Upgrade User Schema
        print("[*] Checking / executing database schema self-healing upgrade...")
        try:
            result = db.execute(text("PRAGMA table_info(users);")).fetchall()
            cols = [r[1] for r in result]
            if "password" not in cols:
                db.execute(text("ALTER TABLE users ADD COLUMN password VARCHAR(100) DEFAULT 'password123';"))
                db.commit()
                print("[+] Users table upgraded with password field.")
        except Exception as e:
            db.rollback()
            print(f"[!] Schema alteration warning: {e}")

        # 2. Define Demo Accounts
        # Standard Timing: 8 AM to 5 PM (avg_login_hour = 12.5, std_login_hour = 2.25 -> range: 12.5 ± 2*2.25 = 8.0 to 17.0)
        accounts = [
            {"email": "admin@abc.com", "username": "admin_abc", "password": "pass@123", "role": "Administrator", "dept": "Security"},
            {"email": "20230140302@mitaoe.ac.in", "username": "sentinel_user1", "password": "password123", "role": "Employee", "dept": "Operations"},
            {"email": "202301040161@mitaoe.ac.in", "username": "sentinel_user2", "password": "pass@123", "role": "Employee", "dept": "Engineering"}
        ]

        print("\n[*] Commencing seeding of hackathon demo accounts...")
        seeded_users = {}
        for acc in accounts:
            user = db.query(User).filter(User.email == acc["email"]).first()
            if not user:
                user = User(
                    username=acc["username"],
                    email=acc["email"],
                    password=acc["password"],
                    role=acc["role"],
                    department=acc["dept"]
                )
                db.add(user)
                db.commit()
                db.refresh(user)
                print(f"  [+] Seeded user account: {acc['email']}")
            else:
                user.username = acc["username"]
                user.password = acc["password"]
                user.role = acc["role"]
                user.department = acc["dept"]
                db.commit()
                print(f"  [+] Reset / verified user account: {acc['email']}")
            
            seeded_users[acc["email"]] = user

            # Seed Trusted Device (For regular users and admins)
            device = db.query(Device).filter(Device.user_id == user.id).first()
            if not device:
                device = Device(
                    user_id=user.id,
                    device_hash=f"trusted_device_hash_{acc['username']}",
                    browser="Chrome",
                    os="Windows",
                    device_type="desktop",
                    trusted=True
                )
                db.add(device)
                db.commit()
                print(f"    - Seeded trusted Windows Chrome device for {acc['email']}")
            else:
                device.browser = "Chrome"
                device.os = "Windows"
                device.trusted = True
                db.commit()
                print(f"    - Verified trusted Windows Chrome device for {acc['email']}")

            # Seed Behavioral Profile Baseline
            # Regular working window: 8:00 AM to 5:00 PM (Circular 24h)
            profile = db.query(UserBehaviorProfile).filter(UserBehaviorProfile.user_id == user.id).first()
            if not profile:
                profile = UserBehaviorProfile(
                    user_id=user.id,
                    avg_login_hour=12.5,
                    std_login_hour=2.25,
                    common_city="Pune",
                    common_country="India",
                    common_browser="Chrome",
                    common_os="Windows",
                    login_frequency_per_day=3.0
                )
                db.add(profile)
                db.commit()
                print(f"    - Seeded Pune baseline timing (8 AM - 5 PM) for {acc['email']}")
            else:
                profile.avg_login_hour = 12.5
                profile.std_login_hour = 2.25
                profile.common_city = "Pune"
                profile.common_country = "India"
                profile.common_browser = "Chrome"
                profile.common_os = "Windows"
                profile.login_frequency_per_day = 3.0
                db.commit()
                print(f"    - Reset Pune baseline timing (8 AM - 5 PM) for {acc['email']}")

        # 3. Pre-populate chronological synthetic past events
        print("\n[*] Clearing old synthetic history for demo accounts...")
        for user in seeded_users.values():
            events = db.query(LoginEvent).filter(LoginEvent.user_id == user.id).all()
            for e in events:
                if e.risk_assessment:
                    db.query(Alert).filter(Alert.risk_assessment_id == e.risk_assessment.id).delete()
                    db.delete(e.risk_assessment)
                db.delete(e)
        db.commit()
        print("[+] History cleared.")

        print("\n[*] Commencing seeding of chronological threat events...")
        base_time = datetime.now() - timedelta(days=2)

        # ─── USER 1 HISTORY: 20230140302@mitaoe.ac.in ───
        u1 = seeded_users["20230140302@mitaoe.ac.in"]
        u1_dev = db.query(Device).filter(Device.user_id == u1.id).first()

        # Event 1: Safe daytime login (Pune, 11:30 AM)
        e1 = LoginEvent(
            user_id=u1.id, timestamp=base_time.replace(hour=11, minute=30), status="success",
            ip_address="103.111.222.36", country="India", city="Pune", browser="Chrome", os="Windows",
            device_id=u1_dev.id, auth_method="password", source="web", isp="Reliance Jio", latitude=18.5204, longitude=73.8567
        )
        db.add(e1); db.commit(); db.refresh(e1)
        r1 = RiskAssessment(
            login_event_id=e1.id, failed_login_score=0, unusual_time_score=0, new_device_score=0,
            new_location_score=0, anomaly_score=0.05, total_score=1.25, risk_level="LOW", risk_factors=[]
        )
        db.add(r1)

        # Event 2: Timing Violation (Pune, 2:15 AM) -> MEDIUM Risk (lockout check fails, warning displayed)
        e2 = LoginEvent(
            user_id=u1.id, timestamp=base_time.replace(hour=2, minute=15) + timedelta(hours=6), status="success",
            ip_address="103.111.222.45", country="India", city="Pune", browser="Chrome", os="Windows",
            device_id=u1_dev.id, auth_method="password", source="web", isp="Reliance Jio", latitude=18.5204, longitude=73.8567
        )
        db.add(e2); db.commit(); db.refresh(e2)
        r2 = RiskAssessment(
            login_event_id=e2.id, failed_login_score=0, unusual_time_score=20, new_device_score=0,
            new_location_score=0, anomaly_score=0.25, total_score=26.25, risk_level="LOW", risk_factors=["Unusual login timing detected"]
        )
        db.add(r2)

        # Event 3: Critical Threat - Impossible Travel (New York, 10 minutes later) -> HIGH Risk (triggers 2FA email + lockout alert)
        e3 = LoginEvent(
            user_id=u1.id, timestamp=base_time.replace(hour=2, minute=25) + timedelta(hours=6), status="success",
            ip_address="198.51.100.22", country="USA", city="New York", browser="Safari", os="macOS",
            device_id=None, auth_method="password", source="web", isp="Verizon Wireless", latitude=40.7128, longitude=-74.0060
        )
        db.add(e3); db.commit(); db.refresh(e3)
        r3 = RiskAssessment(
            login_event_id=e3.id, failed_login_score=0, unusual_time_score=20, new_device_score=20,
            new_location_score=50, anomaly_score=0.65, total_score=71.25, risk_level="HIGH",
            risk_factors=["Unknown device detected", "Login from unusual location", "Impossible travel behavior", "Unusual login timing detected"]
        )
        db.add(r3); db.commit(); db.refresh(r3)
        a3 = Alert(
            risk_assessment_id=r3.id, alert_type="impossible_travel", severity="high",
            message="Suspicious login activity flagged: Unknown device detected, Login from unusual location, Impossible travel behavior.",
            status="resolved"
        )
        db.add(a3)

        # ─── USER 2 HISTORY: 202301040161@mitaoe.ac.in ───
        u2 = seeded_users["202301040161@mitaoe.ac.in"]
        u2_dev = db.query(Device).filter(Device.user_id == u2.id).first()

        # Event 1: Safe daytime login (Pune, 10:00 AM)
        e4 = LoginEvent(
            user_id=u2.id, timestamp=base_time.replace(hour=10, minute=0), status="success",
            ip_address="103.111.222.90", country="India", city="Pune", browser="Chrome", os="Windows",
            device_id=u2_dev.id, auth_method="password", source="web", isp="Airtel", latitude=18.5204, longitude=73.8567
        )
        db.add(e4); db.commit(); db.refresh(e4)
        r4 = RiskAssessment(
            login_event_id=e4.id, failed_login_score=0, unusual_time_score=0, new_device_score=0,
            new_location_score=0, anomaly_score=0.05, total_score=1.25, risk_level="LOW", risk_factors=[]
        )
        db.add(r4)

        # Event 2: Unknown Device daytime (Pune, 2:30 PM) -> MEDIUM Risk (Score 21)
        e5 = LoginEvent(
            user_id=u2.id, timestamp=base_time.replace(hour=14, minute=30), status="success",
            ip_address="103.111.222.90", country="India", city="Pune", browser="Firefox", os="Windows",
            device_id=None, auth_method="password", source="web", isp="Airtel", latitude=18.5204, longitude=73.8567
        )
        db.add(e5); db.commit(); db.refresh(e5)
        r5 = RiskAssessment(
            login_event_id=e5.id, failed_login_score=0, unusual_time_score=0, new_device_score=20,
            new_location_score=0, anomaly_score=0.15, total_score=23.75, risk_level="LOW", risk_factors=["Unknown device detected"]
        )
        db.add(r5)

        # Event 3: Location Warning - London, UK daytime -> MEDIUM Risk (Score 41 -> triggers 5-min Lockout on subsequent attempts!)
        e6 = LoginEvent(
            user_id=u2.id, timestamp=base_time.replace(hour=16, minute=15) + timedelta(days=1), status="success",
            ip_address="82.165.12.33", country="United Kingdom", city="London", browser="Chrome", os="Windows",
            device_id=u2_dev.id, auth_method="password", source="web", isp="BT Group", latitude=51.5074, longitude=-0.1278
        )
        db.add(e6); db.commit(); db.refresh(e6)
        r6 = RiskAssessment(
            login_event_id=e6.id, failed_login_score=0, unusual_time_score=0, new_device_score=0,
            new_location_score=20, anomaly_score=0.45, total_score=51.25, risk_level="MEDIUM",
            risk_factors=["Login from unusual location"]
        )
        db.add(r6); db.commit(); db.refresh(r6)
        a6 = Alert(
            risk_assessment_id=r6.id, alert_type="unusual_location", severity="medium",
            message="Suspicious login activity flagged: Login from unusual location.",
            status="open"
        )
        db.add(a6)

        db.commit()
        print("[+] Chronological threat events seeded successfully!")
        print("\n[+] Demo user database seeding complete successfully!")
        print("=" * 75)

    finally:
        db.close()


if __name__ == "__main__":
    main()
