from sqlalchemy.orm import Session
from app.models.login_event import LoginEvent
from app.models.user_profile import UserBehaviorProfile
from app.detectors.base_detector import BaseDetector, DetectionResult


class UnusualTimingDetector(BaseDetector):
    """
    Compares the current login time against the user's baseline behavior profile.
    Triggers if the login hour falls outside of the historical range (avg_hour ± 2 * std_hour).
    """

    @property
    def name(self) -> str:
        return "timing"

    def analyze(self, event: LoginEvent, db: Session) -> DetectionResult:
        # Load the user's behavioral profile
        profile = db.query(UserBehaviorProfile).filter(
            UserBehaviorProfile.user_id == event.user_id
        ).first()

        # If no profile exists (e.g. new user), we cannot determine anomalous timing yet
        if not profile:
            return DetectionResult(
                detector_name=self.name,
                triggered=False,
                score=0.0,
                reason="No behavioral baseline profile established for this user"
            )

        # Convert event timestamp to a fractional hour (0.0 to 23.99)
        current_hour = event.timestamp.hour + (event.timestamp.minute / 60.0)
        
        # Enforce a minimum standard deviation of 1.0 hour to avoid division-by-zero or ultra-narrow ranges
        std = max(profile.std_login_hour, 1.0)
        allowed_delta = 2.0 * std

        # Compute circular distance in 24-hour clock space to handle wraps around midnight
        diff = abs(current_hour - profile.avg_login_hour)
        circular_diff = min(diff, 24.0 - diff)

        if circular_diff > allowed_delta:
            return DetectionResult(
                detector_name=self.name,
                triggered=True,
                score=20.0,
                reason="Login occurred outside normal user activity window"
            )

        return DetectionResult(
            detector_name=self.name,
            triggered=False,
            score=0.0,
            reason="Login occurred within normal user activity window"
        )
