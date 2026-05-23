from datetime import timedelta
from sqlalchemy.orm import Session
from app.models.login_event import LoginEvent
from app.detectors.base_detector import BaseDetector, DetectionResult


class FailedLoginDetector(BaseDetector):
    """
    Detects brute force and credential stuffing attacks by looking for
    5 or more FAILED authentication attempts within the previous 5 minutes.
    """

    @property
    def name(self) -> str:
        return "failed_login"

    def analyze(self, event: LoginEvent, db: Session) -> DetectionResult:
        # Define the sliding time window: previous 5 minutes
        time_limit = event.timestamp - timedelta(minutes=5)
        
        # Query the database for other failed login attempts by the same user in this window
        failed_count = db.query(LoginEvent).filter(
            LoginEvent.user_id == event.user_id,
            LoginEvent.status == "failed",
            LoginEvent.timestamp >= time_limit,
            LoginEvent.timestamp <= event.timestamp,
            LoginEvent.id != event.id  # Exclude the current event if it is already in the database
        ).count()
        
        # Add the current event to the count if the current event itself failed
        total_failed = failed_count + (1 if event.status == "failed" else 0)

        if total_failed >= 5:
            return DetectionResult(
                detector_name=self.name,
                triggered=True,
                score=60.0,
                reason="Multiple failed login attempts detected"
            )
            
        return DetectionResult(
            detector_name=self.name,
            triggered=False,
            score=0.0,
            reason="Failed login attempts within safe thresholds"
        )
