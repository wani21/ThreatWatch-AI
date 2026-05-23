import uuid
from datetime import datetime
from typing import Dict, Any, Tuple
from fastapi import HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.models.user import User
from app.models.login_event import LoginEvent
from app.models.device import Device
from app.schemas.auth import LoginRequest
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
        Dynamically executes an ALTER TABLE script on database engine.
        Ensures the 'users' table is safely updated with the 'password' column.
        """
        try:
            if self.db.bind.dialect.name == "sqlite":
                result = self.db.execute(text("PRAGMA table_info(users);")).fetchall()
                cols = [r[1] for r in result]
                if "password" not in cols:
                    self.db.execute(text("ALTER TABLE users ADD COLUMN password VARCHAR(100) DEFAULT 'password123';"))
                    self.db.commit()
            else:
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

        # 1b. Check if the user is currently locked out (only for non-Admins)
        if user.role != "Administrator":
            from datetime import timedelta
            from app.models.risk_assessment import RiskAssessment
            
            five_minutes_ago = datetime.utcnow() - timedelta(minutes=5)
            
            recent_medium_threat = self.db.query(RiskAssessment).join(LoginEvent).filter(
                LoginEvent.user_id == user.id,
                RiskAssessment.total_score >= 45.0,
                RiskAssessment.total_score <= 75.0,
                LoginEvent.timestamp >= five_minutes_ago
            ).order_by(LoginEvent.timestamp.desc()).first()
            
            if recent_medium_threat:
                threat_time = recent_medium_threat.login_event.timestamp.replace(tzinfo=None)
                now = datetime.utcnow()
                elapsed = (now - threat_time).total_seconds()
                remaining_seconds = max(0, 300 - int(elapsed))
                if remaining_seconds > 0:
                    minutes = remaining_seconds // 60
                    seconds = remaining_seconds % 60
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Account temporarily locked for 5 minutes due to suspicious activity. Try again in {minutes}m {seconds}s."
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

        # 6b. Severe Risk Interceptor (>75) -> Trigger 2FA (only for non-Admins with valid credentials)
        if user.role != "Administrator" and is_authenticated and risk_report["risk_score"] > 75.0:
            import random
            otp = f"{random.randint(100000, 999999)}"
            event.otp_code = otp
            event.status = "mfa_pending"
            self.db.commit()
            
            # Dispatch OTP warning email in a resilient try-except block
            try:
                from app.services.alert_manager import AlertManager
                alert_manager = AlertManager(self.db)
                alert_manager.send_otp_email(user, event, otp)
            except Exception as otp_err:
                print(f"[AlertManager] [!] Warning: Failed to send 2FA OTP email: {otp_err}")
                
            return {
                "authenticated": False,
                "mfa_required": True,
                "event_id": str(event.id),
                "risk_score": risk_report["risk_score"],
                "risk_level": risk_report["risk_level"],
                "anomaly_score": risk_report["anomaly_score"],
                "triggered_factors": risk_report["reasons"]
            }

        # 7. Build and return unified security verdict
        return {
            "authenticated": is_authenticated,
            "event_id": str(event.id),
            "risk_score": risk_report["risk_score"],
            "risk_level": risk_report["risk_level"],
            "anomaly_score": risk_report["anomaly_score"],
            "triggered_factors": risk_report["reasons"],
            "role": user.role
        }

    def verify_otp(self, event_id: str, otp_code: str) -> Dict[str, Any]:
        """
        Verifies 2FA OTP tokens to validate high-risk access attempts.
        """
        import uuid
        try:
            event_uuid = uuid.UUID(event_id) if isinstance(event_id, str) else event_id
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid event ID structure. Must be a valid UUID."
            )
            
        event = self.db.query(LoginEvent).filter(LoginEvent.id == event_uuid).first()
        if not event:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="2FA session not found. Please try signing in again."
            )
            
        if not event.otp_code:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No 2-Factor authentication session is active for this login attempt."
            )
            
        if event.otp_code != otp_code:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid 2-Factor OTP verification code. Please check your inbox."
            )
            
        # Success! Mark event as success and clear OTP code
        event.status = "success"
        event.otp_code = None
        self.db.commit()
        
        return {
            "authenticated": True,
            "message": "2-Factor Authentication verified successfully.",
            "role": event.user.role if event.user else "user"
        }
