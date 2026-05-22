from sqlalchemy.orm import Session
from app.models.login_event import LoginEvent
from app.detectors.base_detector import BaseDetector, DetectionResult
from app.utils.geo_utils import calculate_distance_km, calculate_required_speed


class ImpossibleTravelDetector(BaseDetector):
    """
    Identifies if a user logged in from two distant geographic locations in a time window
    that is physically impossible to traverse by commercial flight (exceeding 900 km/h).
    """

    @property
    def name(self) -> str:
        return "travel"

    def analyze(self, event: LoginEvent, db: Session) -> DetectionResult:
        # If the current event doesn't contain coordinates, we cannot compute distance
        if event.latitude is None or event.longitude is None:
            return DetectionResult(
                detector_name=self.name,
                triggered=False,
                score=0.0,
                reason="Geographic coordinates missing for current login attempt"
            )

        # Retrieve the most recent successful login event prior to the current event
        prev_event = db.query(LoginEvent).filter(
            LoginEvent.user_id == event.user_id,
            LoginEvent.status == "success",
            LoginEvent.timestamp < event.timestamp
        ).order_by(LoginEvent.timestamp.desc()).first()

        # If there are no prior successful logins, we cannot evaluate travel velocity
        if not prev_event:
            return DetectionResult(
                detector_name=self.name,
                triggered=False,
                score=0.0,
                reason="No prior successful authentication logs found for this user"
            )

        # Ensure previous event also has geographic coordinates
        if prev_event.latitude is None or prev_event.longitude is None:
            return DetectionResult(
                detector_name=self.name,
                triggered=False,
                score=0.0,
                reason="Geographic coordinates missing for previous successful login"
            )

        # Calculate great-circle distance (km) and elapsed time (seconds)
        distance = calculate_distance_km(
            prev_event.latitude, prev_event.longitude,
            event.latitude, event.longitude
        )
        
        time_diff = (event.timestamp - prev_event.timestamp).total_seconds()
        
        # Calculate velocity required
        speed = calculate_required_speed(distance, time_diff)

        # Trigger if the required travel speed exceeds 900 km/h (average cruising speed of commercial jets)
        if speed > 900.0:
            return DetectionResult(
                detector_name=self.name,
                triggered=True,
                score=30.0,
                reason=f"Impossible travel behavior detected. Required speed: {speed:.1f} km/h (exceeding 900 km/h)"
            )

        return DetectionResult(
            detector_name=self.name,
            triggered=False,
            score=0.0,
            reason=f"Travel velocity within physical limits ({speed:.1f} km/h)"
        )
