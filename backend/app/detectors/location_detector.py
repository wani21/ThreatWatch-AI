from sqlalchemy.orm import Session
from app.models.login_event import LoginEvent
from app.models.user_profile import UserBehaviorProfile
from app.detectors.base_detector import BaseDetector, DetectionResult


class NewLocationDetector(BaseDetector):
    """
    Checks if the login event originated from a geographic location (city or country)
    that differs from the user's historical common location baseline.
    """

    @property
    def name(self) -> str:
        return "location"

    def analyze(self, event: LoginEvent, db: Session) -> DetectionResult:
        # Load the user's baseline behavior profile
        profile = db.query(UserBehaviorProfile).filter(
            UserBehaviorProfile.user_id == event.user_id
        ).first()

        # If no profile exists or the baseline location is unpopulated, we cannot evaluate
        if not profile or not profile.common_city or not profile.common_country:
            return DetectionResult(
                detector_name=self.name,
                triggered=False,
                score=0.0,
                reason="No behavioral baseline profile established for this user"
            )

        # Mismatch check for both city and country
        is_unusual_city = event.city != profile.common_city
        is_unusual_country = event.country != profile.common_country

        if is_unusual_city or is_unusual_country:
            return DetectionResult(
                detector_name=self.name,
                triggered=True,
                score=20.0,
                reason="Login from unusual location"
            )

        return DetectionResult(
            detector_name=self.name,
            triggered=False,
            score=0.0,
            reason="Login occurred from a common location"
        )
