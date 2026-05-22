#!/usr/bin/env python
"""
ThreatWatch-AI - Database Seeder & Synthetic Data Generator
Generates realistic login telemetry datasets for cyber threat detection, behavioral profiling,
risk scoring, and Splunk ingestion.

Features:
- 100 users across 5 departments with varied roles.
- 1-3 trusted devices per user with specific fingerprints.
- ~20,000 login events spanning the previous 30 days.
- 80% Normal user logins (9:00 AM - 7:00 PM, trusted device, primary location Pune).
- 10% Simple failed login events.
- Brute Force Scenarios (5 consecutive FAILED attempts followed by a SUCCESS from the same IP).
- Unusual Timing Logins (Success/Failure events between 2:00 AM and 4:59 AM).
- New Device Events (Successful authentication from unrecognized untrusted devices).
- New Location Events (Daytime logins originating from Mumbai, Delhi, Bangalore, London, New York).
- Impossible Travel Events (Logins from Pune/Mumbai and London/New York within an physically impossible time window).
"""

import sys
import os
import argparse
import random
import uuid
import hashlib
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple

# Inject the backend directory into the Python Path to resolve imports
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from faker import Faker
from sqlalchemy import select, delete
from app.core.database import SessionLocal, engine, Base
from app.models import User, Device, LoginEvent, UserBehaviorProfile, RiskAssessment, Alert

# Geographic coordinates and metadata for standard locations
LOCATIONS = {
    "Pune": {"country": "India", "country_code": "IN", "city": "Pune", "lat": 18.5204, "lon": 73.8567},
    "Mumbai": {"country": "India", "country_code": "IN", "city": "Mumbai", "lat": 19.0760, "lon": 72.8777},
    "Delhi": {"country": "India", "country_code": "IN", "city": "Delhi", "lat": 28.6139, "lon": 77.2090},
    "Bangalore": {"country": "India", "country_code": "IN", "city": "Bangalore", "lat": 12.9716, "lon": 77.5946},
    "London": {"country": "United Kingdom", "country_code": "GB", "city": "London", "lat": 51.5074, "lon": -0.1278},
    "New York": {"country": "United States", "country_code": "US", "city": "New York", "lat": 40.7128, "lon": -74.0060}
}

DEPARTMENTS = ["Engineering", "Finance", "HR", "Operations", "Security"]
ROLES = ["Employee", "Manager", "Admin"]
AUTH_METHODS = ["password", "mfa_sms", "mfa_authenticator", "sso"]
SOURCES = ["web", "mobile", "api"]
ISPS = ["Reliance Jio", "Airtel", "Vodafone", "Comcast", "BT Group", "Tata Communications", "Verizon"]

DEVICE_CONFIGS = [
    {"os": "Windows", "browser": "Chrome", "device_type": "desktop"},
    {"os": "Windows", "browser": "Edge", "device_type": "desktop"},
    {"os": "macOS", "browser": "Safari", "device_type": "desktop"},
    {"os": "macOS", "browser": "Chrome", "device_type": "desktop"},
    {"os": "Android", "browser": "Chrome", "device_type": "mobile"},
    {"os": "iOS", "browser": "Safari", "device_type": "mobile"}
]


def clear_database(db) -> None:
    """Deletes existing data in cascading dependency order."""
    print("[-] Clearing existing database tables...")
    db.query(Alert).delete()
    db.query(RiskAssessment).delete()
    db.query(LoginEvent).delete()
    db.query(Device).delete()
    db.query(UserBehaviorProfile).delete()
    db.query(User).delete()
    db.commit()
    print("[+] Database tables cleared successfully.")


def generate_users(db, fake: Faker, count: int = 100) -> List[User]:
    """Generates synthetic users and commits them to the database."""
    print(f"[*] Generating {count} unique users...")
    users = []
    
    # Use weighted choices for roles (Employees: 80%, Managers: 15%, Admins: 5%)
    role_weights = [0.80, 0.15, 0.05]
    
    for _ in range(count):
        first_name = fake.first_name()
        last_name = fake.last_name()
        username = f"{first_name.lower()}.{last_name.lower()}_{random.randint(10, 99)}"
        email = f"{username}@threatwatch.ai"
        
        user = User(
            id=uuid.uuid4(),
            username=username,
            email=email,
            department=random.choice(DEPARTMENTS),
            role=random.choices(ROLES, weights=role_weights, k=1)[0],
            created_at=fake.date_time_between(start_date="-90d", end_date="-31d")
        )
        users.append(user)
        db.add(user)
        
    db.commit()
    print(f"[+] Successfully inserted {count} users.")
    return users


def generate_devices(db, users: List[User]) -> List[Device]:
    """Generates 1 to 3 trusted devices for each user."""
    print("[*] Generating trusted devices for each user...")
    devices = []
    
    for user in users:
        device_count = random.randint(1, 3)
        user_configs = random.sample(DEVICE_CONFIGS, device_count)
        
        for config in user_configs:
            # Generate SHA-256 fingerprint from user_id and specs
            fingerprint_raw = f"{user.id}-{config['os']}-{config['browser']}-{random.random()}"
            device_hash = hashlib.sha256(fingerprint_raw.encode()).hexdigest()
            
            device = Device(
                id=uuid.uuid4(),
                user_id=user.id,
                device_hash=device_hash,
                browser=config["browser"],
                os=config["os"],
                device_type=config["device_type"],
                first_seen=user.created_at + timedelta(days=random.randint(1, 5)),
                trusted=True
            )
            device.last_seen = device.first_seen + timedelta(days=random.randint(5, 20))
            devices.append(device)
            db.add(device)
            
    db.commit()
    print(f"[+] Successfully inserted {len(devices)} devices.")
    return devices


def generate_login_events(db, users: List[User], devices: List[Device], fake: Faker, total_events: int = 20000) -> int:
    """Generates and inserts realistic login telemetry, including normal use and threat scenarios."""
    print(f"[*] Generating approximately {total_events} login telemetry events...")
    
    # Map devices to users for easy lookup
    user_devices = {}
    for device in devices:
        if device.user_id not in user_devices:
            user_devices[device.user_id] = []
        user_devices[device.user_id].append(device)

    # Establish time bounds (past 30 days)
    end_time = datetime.now()
    start_time = end_time - timedelta(days=30)
    total_seconds = int((end_time - start_time).total_seconds())

    events: List[LoginEvent] = []

    # Distribution counts:
    # 80% Normal success
    # 10% Simple failure
    # 10% Anomalies/Attacks (Brute force, Unusual timings, New devices, New locations, Impossible travel)
    normal_count = int(total_events * 0.80)
    failed_count = int(total_events * 0.10)
    anomalous_target = total_events - normal_count - failed_count

    print(f"    - Target normal events: {normal_count}")
    print(f"    - Target failed events: {failed_count}")
    print(f"    - Target anomalous events: {anomalous_target}")

    # Generate Primary normal events (Pune successes)
    pune_loc = LOCATIONS["Pune"]
    
    print("[*] Simulating normal user logins...")
    for _ in range(normal_count):
        user = random.choice(users)
        user_devs = user_devices.get(user.id, [])
        device = random.choice(user_devs) if user_devs else None
        
        # Pick random timestamp inside working hours (09:00 - 19:00)
        random_day_offset = random.randint(0, 29)
        hour = random.randint(9, 18)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        
        event_time = start_time + timedelta(days=random_day_offset)
        event_time = event_time.replace(hour=hour, minute=minute, second=second)

        events.append(LoginEvent(
            id=uuid.uuid4(),
            user_id=user.id,
            timestamp=event_time,
            status="success",
            ip_address=f"115.112.{random.randint(0, 255)}.{random.randint(1, 254)}",  # Pune IP block simulation
            country=pune_loc["country"],
            country_code=pune_loc["country_code"],
            city=pune_loc["city"],
            browser=device.browser if device else "Chrome",
            os=device.os if device else "Windows",
            device_id=device.id if device else None,
            session_id=fake.uuid4(),
            latitude=pune_loc["lat"],
            longitude=pune_loc["lon"],
            auth_method=random.choice(AUTH_METHODS),
            source="web" if (device and device.device_type == "desktop") else random.choice(SOURCES),
            isp=random.choice(["Reliance Jio", "Airtel", "Tata Communications"])
        ))

    # Generate Simple failed logins (Pune failures)
    print("[*] Simulating simple authentication failures...")
    for _ in range(failed_count):
        user = random.choice(users)
        user_devs = user_devices.get(user.id, [])
        device = random.choice(user_devs) if user_devs else None
        
        random_day_offset = random.randint(0, 29)
        hour = random.randint(8, 22)
        event_time = start_time + timedelta(days=random_day_offset)
        event_time = event_time.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))

        events.append(LoginEvent(
            id=uuid.uuid4(),
            user_id=user.id,
            timestamp=event_time,
            status="failed",
            ip_address=f"115.112.{random.randint(0, 255)}.{random.randint(1, 254)}",
            country=pune_loc["country"],
            country_code=pune_loc["country_code"],
            city=pune_loc["city"],
            browser=device.browser if device else "Chrome",
            os=device.os if device else "Windows",
            device_id=device.id if device else None,
            session_id=None,  # No active session for failed logins
            latitude=pune_loc["lat"],
            longitude=pune_loc["lon"],
            auth_method="password",
            source="web" if (device and device.device_type == "desktop") else random.choice(SOURCES),
            isp=random.choice(["Reliance Jio", "Airtel", "Tata Communications"])
        ))

    # Generate Special Threat & Anomaly Scenarios
    print("[*] Generating security threat patterns & anomalies...")
    anomalous_count = 0

    # 1. Brute Force Scenarios (~100 scenarios, yielding ~600 events)
    # 5 failed attempts followed by 1 successful login in rapid succession
    print("    -> Simulating Brute Force attacks (5 Fails + 1 Success)...")
    brute_force_user_count = min(30, len(users))
    brute_users = random.sample(users, brute_force_user_count)
    for user in brute_users:
        user_devs = user_devices.get(user.id, [])
        device = random.choice(user_devs) if user_devs else None
        
        # Choose a random day for the attack
        random_day_offset = random.randint(1, 28)
        hour = random.randint(1, 23)
        base_time = start_time + timedelta(days=random_day_offset)
        base_time = base_time.replace(hour=hour, minute=random.randint(10, 45), second=0)

        # Attacker details (Unrecognized IP and ISP)
        attacker_ip = fake.ipv4_public()
        attacker_isp = random.choice(ISPS)
        
        # 5 consecutive FAILED attempts (spaced 5-15 seconds apart)
        for i in range(5):
            attempt_time = base_time + timedelta(seconds=i * random.randint(5, 15))
            events.append(LoginEvent(
                id=uuid.uuid4(),
                user_id=user.id,
                timestamp=attempt_time,
                status="failed",
                ip_address=attacker_ip,
                country=pune_loc["country"],
                country_code=pune_loc["country_code"],
                city=pune_loc["city"],
                browser=device.browser if device else "Chrome",
                os=device.os if device else "Windows",
                device_id=None,  # Attacker device unrecognized initially
                session_id=None,
                latitude=pune_loc["lat"],
                longitude=pune_loc["lon"],
                auth_method="password",
                source="web",
                isp=attacker_isp
            ))
            anomalous_count += 1
            
        # 1 SUCCESSFUL login (attacker cracked password / bypassed via stolen credentials)
        success_time = base_time + timedelta(seconds=5 * 15 + random.randint(5, 10))
        events.append(LoginEvent(
            id=uuid.uuid4(),
            user_id=user.id,
            timestamp=success_time,
            status="success",
            ip_address=attacker_ip,
            country=pune_loc["country"],
            country_code=pune_loc["country_code"],
            city=pune_loc["city"],
            browser=device.browser if device else "Chrome",
            os=device.os if device else "Windows",
            device_id=None,
            session_id=fake.uuid4(),
            latitude=pune_loc["lat"],
            longitude=pune_loc["lon"],
            auth_method="password",
            source="web",
            isp=attacker_isp
        ))
        anomalous_count += 1

    # 2. Unusual Timing Events (~300 events)
    # Logins occurring between 2:00 AM and 4:59 AM
    print("    -> Simulating Unusual Timing logins (02:00 - 04:00 AM)...")
    for _ in range(300):
        user = random.choice(users)
        user_devs = user_devices.get(user.id, [])
        device = random.choice(user_devs) if user_devs else None
        
        random_day_offset = random.randint(0, 29)
        hour = random.choice([2, 3, 4])
        event_time = start_time + timedelta(days=random_day_offset)
        event_time = event_time.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))

        events.append(LoginEvent(
            id=uuid.uuid4(),
            user_id=user.id,
            timestamp=event_time,
            status="success",
            ip_address=f"115.112.{random.randint(0, 255)}.{random.randint(1, 254)}",
            country=pune_loc["country"],
            country_code=pune_loc["country_code"],
            city=pune_loc["city"],
            browser=device.browser if device else "Chrome",
            os=device.os if device else "Windows",
            device_id=device.id if device else None,
            session_id=fake.uuid4(),
            latitude=pune_loc["lat"],
            longitude=pune_loc["lon"],
            auth_method=random.choice(AUTH_METHODS),
            source="web",
            isp=random.choice(["Reliance Jio", "Airtel"])
        ))
        anomalous_count += 1

    # 3. New Device Events (~300 events)
    # Successes from devices outside the user's trusted device list
    print("    -> Simulating New (Untrusted) Device logins...")
    for _ in range(300):
        user = random.choice(users)
        # Select device config completely different from trusted ones
        config = random.choice(DEVICE_CONFIGS)
        
        random_day_offset = random.randint(0, 29)
        hour = random.randint(9, 18)
        event_time = start_time + timedelta(days=random_day_offset)
        event_time = event_time.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))

        events.append(LoginEvent(
            id=uuid.uuid4(),
            user_id=user.id,
            timestamp=event_time,
            status="success",
            ip_address=f"115.112.{random.randint(0, 255)}.{random.randint(1, 254)}",
            country=pune_loc["country"],
            country_code=pune_loc["country_code"],
            city=pune_loc["city"],
            browser=config["browser"],
            os=config["os"],
            device_id=None,  # Unrecognized device ID
            session_id=fake.uuid4(),
            latitude=pune_loc["lat"],
            longitude=pune_loc["lon"],
            auth_method="password",
            source="web" if config["device_type"] == "desktop" else "mobile",
            isp=random.choice(["Reliance Jio", "Airtel"])
        ))
        anomalous_count += 1

    # 4. New Location Events (~400 events)
    # Daytime logins originating from Delhi, Mumbai, Bangalore, London, New York
    print("    -> Simulating anomalous New Location logins (Mumbai, London, NY)...")
    anomalous_loc_keys = ["Mumbai", "Delhi", "Bangalore", "London", "New York"]
    for _ in range(400):
        user = random.choice(users)
        user_devs = user_devices.get(user.id, [])
        device = random.choice(user_devs) if user_devs else None
        
        loc_name = random.choice(anomalous_loc_keys)
        loc = LOCATIONS[loc_name]
        
        random_day_offset = random.randint(0, 29)
        hour = random.randint(9, 18)
        event_time = start_time + timedelta(days=random_day_offset)
        event_time = event_time.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59))

        events.append(LoginEvent(
            id=uuid.uuid4(),
            user_id=user.id,
            timestamp=event_time,
            status="success",
            ip_address=fake.ipv4_public(),
            country=loc["country"],
            country_code=loc["country_code"],
            city=loc["city"],
            browser=device.browser if device else "Chrome",
            os=device.os if device else "Windows",
            device_id=device.id if device else None,
            session_id=fake.uuid4(),
            latitude=loc["lat"],
            longitude=loc["lon"],
            auth_method=random.choice(AUTH_METHODS),
            source="web",
            isp=random.choice(ISPS)
        ))
        anomalous_count += 1

    # 5. Impossible Travel Events (~50 scenarios, yielding 100 events)
    # Login in Location A followed within short duration by Location B where travel is physically impossible
    print("    -> Simulating Impossible Travel scenarios (e.g. Pune -> New York in 10 minutes)...")
    for _ in range(50):
        user = random.choice(users)
        user_devs = user_devices.get(user.id, [])
        device = random.choice(user_devs) if user_devs else None
        
        # Choose a random timestamp
        random_day_offset = random.randint(0, 29)
        hour = random.randint(9, 16)
        base_time = start_time + timedelta(days=random_day_offset)
        base_time = base_time.replace(hour=hour, minute=random.randint(0, 40), second=0)

        # Event A: Legitimate login in Pune/Mumbai
        loc_a_name = random.choice(["Pune", "Mumbai"])
        loc_a = LOCATIONS[loc_a_name]
        
        event_a = LoginEvent(
            id=uuid.uuid4(),
            user_id=user.id,
            timestamp=base_time,
            status="success",
            ip_address=f"115.112.{random.randint(0, 255)}.{random.randint(1, 254)}",
            country=loc_a["country"],
            country_code=loc_a["country_code"],
            city=loc_a["city"],
            browser=device.browser if device else "Chrome",
            os=device.os if device else "Windows",
            device_id=device.id if device else None,
            session_id=fake.uuid4(),
            latitude=loc_a["lat"],
            longitude=loc_a["lon"],
            auth_method=random.choice(AUTH_METHODS),
            source="web",
            isp="Reliance Jio"
        )
        events.append(event_a)
        anomalous_count += 1

        # Event B: Intruder logins from London/New York 10 minutes later
        loc_b_name = random.choice(["London", "New York"])
        loc_b = LOCATIONS[loc_b_name]
        
        event_b = LoginEvent(
            id=uuid.uuid4(),
            user_id=user.id,
            timestamp=base_time + timedelta(minutes=10),  # Only 10 minutes later!
            status="success",
            ip_address=fake.ipv4_public(),
            country=loc_b["country"],
            country_code=loc_b["country_code"],
            city=loc_b["city"],
            browser=device.browser if device else "Chrome",
            os=device.os if device else "Windows",
            device_id=None,  # Intruder device
            session_id=fake.uuid4(),
            latitude=loc_b["lat"],
            longitude=loc_b["lon"],
            auth_method="password",
            source="web",
            isp=random.choice(ISPS)
        )
        events.append(event_b)
        anomalous_count += 1

    # Sort all events chronologically by timestamp before bulk saving
    # This keeps sequential data (e.g. brute force, impossible travel) realistic and ordered.
    print("[*] Sorting all generated login events chronologically...")
    events.sort(key=lambda e: e.timestamp)

    print("[*] Committing login events to database in chunks...")
    # Bulk insert using SQLAlchemy add_all in chunks of 5000 for efficiency
    chunk_size = 5000
    for i in range(0, len(events), chunk_size):
        chunk = events[i:i + chunk_size]
        db.add_all(chunk)
        db.commit()
        print(f"    - Inserted events {i} to {min(i + chunk_size, len(events))}...")

    print(f"[+] Successfully inserted {len(events)} login events.")
    return len(events)


def generate_user_profiles(db, users: List[User], devices: List[Device]) -> None:
    """Generates baseline UserBehaviorProfiles by aggregating user parameters."""
    print("[*] Generating baseline UserBehaviorProfiles...")
    
    for user in users:
        # Create a behavioral profile with baseline values centered around Pune
        pune_loc = LOCATIONS["Pune"]
        
        # Windows/Chrome are default common browser/OS
        profile = UserBehaviorProfile(
            id=uuid.uuid4(),
            user_id=user.id,
            avg_login_hour=random.uniform(10.0, 16.0),
            std_login_hour=random.uniform(1.0, 3.5),
            common_country=pune_loc["country"],
            common_city=pune_loc["city"],
            common_browser="Chrome",
            common_os="Windows",
            login_frequency_per_day=random.uniform(1.5, 4.0)
        )
        db.add(profile)
        
    db.commit()
    print("[+] User Behavior Profiles baseline generated.")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ThreatWatch-AI Synthetic Login Activity Generator"
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Deletes existing data in users, devices, login_events, and security tables before generation."
    )
    parser.add_argument(
        "--seed",
        type=int,
        help="Seed for reproducible random generation."
    )
    args = parser.parse_args()

    # Seed the generators for repeatability
    if args.seed is not None:
        print(f"[!] Seeding generators with seed={args.seed}...")
        random.seed(args.seed)
        Faker.seed(args.seed)
        
    fake = Faker()

    # Establish database session
    db = SessionLocal()
    
    try:
        # Ensure database tables exist
        print("[*] Ensuring database schema is initialized...")
        Base.metadata.create_all(bind=engine)

        if args.reset:
            clear_database(db)

        # Generate all entities
        users = generate_users(db, fake, count=100)
        devices = generate_devices(db, users)
        generate_user_profiles(db, users, devices)
        events_inserted = generate_login_events(db, users, devices, fake, total_events=20000)

        # Print final report
        print("\n" + "=" * 50)
        print("ThreatWatch-AI Synthetic Data Generation Complete")
        print("=" * 50)
        print(f"Users inserted: {len(users)}")
        print(f"Devices inserted: {len(devices)}")
        print(f"Events inserted: {events_inserted}")
        print("=" * 50)

    except Exception as e:
        print(f"[!] Error occurred during generation: {e}")
        db.rollback()
        raise e
    finally:
        db.close()


if __name__ == "__main__":
    main()
