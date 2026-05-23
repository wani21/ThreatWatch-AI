import uuid
from datetime import datetime
from typing import Dict, Any, Tuple
from fastapi import HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.login_event import LoginEvent
from app.models.device import Device
from app.models.user_profile import UserBehaviorProfile
from app.schemas.auth import LoginRequest, SignUpRequest
from app.services.risk_assessment_service import RiskAssessmentService


def lookup_coordinates(city: str) -> Tuple[float, float]:
    """
    Simulates a high-precision IP-to-Geo geolocation lookup.
    Maps standard testing cities to their corresponding geographic coordinates.
    """
    if not city:
        return None, None
    city_lower = city.lower()
    if "pune" in city_lower:
        return 18.5204, 73.8567
    if "new york" in city_lower:
        return 40.7128, -74.0060
    if "london" in city_lower:
        return 51.5074, -0.1278
    if "berlin" in city_lower:
        return 52.5200, 13.4050
    if "singapore" in city_lower:
        return 1.3521, 103.8198
    if "sydney" in city_lower:
        return -33.8688, 151.2093
    if "toronto" in city_lower:
        return 43.6532, -79.3832
    return None, None


class AuthService:
    """
    Simulated Authentication Orchestrator for hackathon demonstration.
    Performs plain credential checks, inserts contextual LoginEvents, 
    and automatically triggers the downstream rules and ML threat decision pipeline.
    """

    def __init__(self, db: Session):
        self.db = db
        self._ensure_schema_upgraded()

    def _ensure_schema_upgraded(self) -> None:
        """
        Dynamically executes an ALTER TABLE script on PostgreSQL engine.
        Ensures the 'users' table is safely updated with the 'password' column.
        """
        try:
            self.db.execute(text("ALTER TABLE users ADD COLUMN IF NOT EXISTS password VARCHAR(100) DEFAULT 'password123';"))
            self.db.commit()
        except Exception as e:
            self.db.rollback()
            print(f"[!] Warning: Failed to execute users password schema self-healing upgrade: {e}")

    def authenticate_and_analyze(self, credentials: LoginRequest) -> Dict[str, Any]:
        """
        Processes simulated login request, generates security event logs,
        triggers downstream threat detectors, and returns a unified security verdict.

        Args:
            credentials (LoginRequest): Input body containing credentials and environment context.

        Returns:
            Dict[str, Any]: Complete security pipeline response.
        """
        # 1. Look up user by email in the database
        user = self.db.query(User).filter(User.email == credentials.email).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Authentication failed: User with email '{credentials.email}' does not exist."
            )

        # 2. Check password credentials
        # (Hackathon simplification: plain-text password comparison)
        is_authenticated = (credentials.password == user.password)
        login_status = "success" if is_authenticated else "failed"

        # 3. Resolve client device registration matching
        device = self.db.query(Device).filter(
            Device.user_id == user.id,
            Device.os.ilike(credentials.device_type),
            Device.browser.ilike(credentials.browser)
        ).first()
        device_id = device.id if device else None

        # 4. Resolve geographic coordinates from city
        lat, lon = lookup_coordinates(credentials.city)

        # 5. Create LoginEvent record in the database
        event = LoginEvent(
            user_id=user.id,
            timestamp=datetime.now(),
            status=login_status,
            ip_address=credentials.ip_address,
            country=credentials.country,
            city=credentials.city,
            browser=credentials.browser,
            os=credentials.device_type,  # Map Pydantic device_type to OS column
            device_id=device_id,         # Associated matching device
            latitude=lat,
            longitude=lon,
            session_id=str(uuid.uuid4()),
            auth_method="password",
            source="web"
        )
        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)

        # 6. Trigger downstream rule-based and behavioral ML threat analysis pipeline
        risk_service = RiskAssessmentService(self.db)
        risk_report = risk_service.evaluate_and_persist(event.id)

        # 7. Build and return unified security verdict
        return {
            "authenticated": is_authenticated,
            "event_id": str(event.id),
            "risk_score": risk_report["risk_score"],
            "risk_level": risk_report["risk_level"],
            "anomaly_score": risk_report["anomaly_score"],
            "triggered_factors": risk_report["reasons"]
        }

    def register_user(self, payload: SignUpRequest) -> Dict[str, Any]:
        """
        Idempotently inserts a new user into PostgreSQL database in real time.
        Creates baseline profiles to support rule checks and Isolation Forest calculations.
        """
        # 1. Verify user email uniqueness
        existing_user = self.db.query(User).filter(User.email == payload.email).first()
        if existing_user:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"User with email '{payload.email}' already exists."
            )

        # 2. Save User
        new_user = User(
            username=payload.username,
            email=payload.email,
            password=payload.password,  # Plain text password simplification
            role=payload.role,          # Administrator or Employee
            department=payload.department
        )
        self.db.add(new_user)
        self.db.commit()
        self.db.refresh(new_user)

        # 3. Build and register default trusted device baseline (Windows Chrome)
        device = Device(
            user_id=new_user.id,
            device_hash=f"trusted_device_hash_{new_user.username}",
            browser="Chrome",
            os="Windows",
            device_type="desktop",
            trusted=True
        )
        self.db.add(device)

        # 4. Build and save default behavioral profile baseline (Pune, India daytime)
        profile = UserBehaviorProfile(
            user_id=new_user.id,
            avg_login_hour=12.0,
            std_login_hour=1.0,
            common_city="Pune",
            common_country="India",
            common_browser="Chrome",
            common_os="Windows",
            login_frequency_per_day=3.0
        )
        self.db.add(profile)
        self.db.commit()

        print(f"[+] Real-Time Sign-Up Succeeded: Seeded user baseline for {payload.email}.")
        return {
            "success": True,
            "message": "User registered successfully inside PostgreSQL in real time.",
            "user_id": str(new_user.id)
        }
