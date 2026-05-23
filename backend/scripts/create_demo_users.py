#!/usr/bin/env python
import os
import sys

# Inject parent directory to Python path to resolve imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from sqlalchemy.orm import Session
from sqlalchemy import text
from app.core.database import SessionLocal, Base, engine
from app.models.user import User
from app.models.device import Device
from app.models.user_profile import UserBehaviorProfile


def main():
    print("=" * 75)
    print("      THREATWATCH-AI - HACKATHON DEMO USER SEEDER")
    print("=" * 75)

    print("[*] Initializing database schema...")
    Base.metadata.create_all(bind=engine)
    print("[+] Database schema verified / initialized.")

    db: Session = SessionLocal()
    try:
        # 1. Idempotently Upgrade User Schema
        print("[*] Checking / executing database schema self-healing upgrade...")
        try:
            db.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS password VARCHAR(100) DEFAULT 'password123';"))
            db.commit()
            print("[+] Users table upgraded with password field.")
        except Exception as e:
            db.rollback()
            print(f"[!] Schema alteration warning: {e}")

        # 2. Seed Demo Accounts
        accounts = [
            {"email": "admin@sentinel.ai", "username": "admin", "role": "Administrator", "dept": "Security"},
            {"email": "employee1@sentinel.ai", "username": "employee1", "role": "Employee", "dept": "Engineering"},
            {"email": "employee2@sentinel.ai", "username": "employee2", "role": "Employee", "dept": "Marketing"},
            {"email": "20230140302@mitaoe.ac.in", "username": "sentinel_user", "role": "Employee", "dept": "Operations"}
        ]

        print("\n[*] Commencing seeding of hackathon demo accounts...")
        for acc in accounts:
            user = db.query(User).filter(User.email == acc["email"]).first()
            if not user:
                user = User(
                    username=acc["username"],
                    email=acc["email"],
                    password="password123",  # Plain text demo password
                    role=acc["role"],
                    department=acc["dept"]
                )
                db.add(user)
                db.commit()
                db.refresh(user)
                print(f"  [+] Seeded user account: {acc['email']}")
            else:
                user.username = acc["username"]
                user.password = "password123"
                user.role = acc["role"]
                user.department = acc["dept"]
                db.commit()
                print(f"  [+] Reset / verified user account: {acc['email']}")

            # Seed Trusted Device
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
            # (Pune, Daytime logins baseline)
            profile = db.query(UserBehaviorProfile).filter(UserBehaviorProfile.user_id == user.id).first()
            if not profile:
                profile = UserBehaviorProfile(
                    user_id=user.id,
                    avg_login_hour=12.0,
                    std_login_hour=1.0,
                    common_city="Pune",
                    common_country="India",
                    common_browser="Chrome",
                    common_os="Windows",
                    login_frequency_per_day=3.0
                )
                db.add(profile)
                db.commit()
                print(f"    - Seeded Pune baseline behavior profile for {acc['email']}")
            else:
                profile.avg_login_hour = 12.0
                profile.std_login_hour = 1.0
                profile.common_city = "Pune"
                profile.common_country = "India"
                profile.common_browser = "Chrome"
                profile.common_os = "Windows"
                profile.login_frequency_per_day = 3.0
                db.commit()
                print(f"    - Reset Pune baseline behavior profile for {acc['email']}")

        print("\n[+] Demo user database seeding complete successfully!")
        print("=" * 75)

    finally:
        db.close()


if __name__ == "__main__":
    main()
