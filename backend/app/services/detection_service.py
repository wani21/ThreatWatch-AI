from typing import Dict, Any, List
from sqlalchemy.orm import Session
from app.models.login_event import LoginEvent

# Import detectors
from app.detectors.failed_login_detector import FailedLoginDetector
from app.detectors.timing_detector import UnusualTimingDetector
from app.detectors.device_detector import NewDeviceDetector
from app.detectors.location_detector import NewLocationDetector
from app.detectors.travel_detector import ImpossibleTravelDetector

# Instantiate detectors list to reuse
DETECTORS = [
    FailedLoginDetector(),
    UnusualTimingDetector(),
    NewDeviceDetector(),
    NewLocationDetector(),
    ImpossibleTravelDetector()
]


class DetectionService:
    """
    Orchestration layer that aggregates all individual rule-based and behavioral detectors,
    running them against a single login attempt to produce a consolidated risk evaluation.
    """

    @staticmethod
    def analyze_event(event: LoginEvent, db: Session) -> Dict[str, Any]:
        """
        Accepts a LoginEvent, executes all configured security checks,
        and aggregates the individual threat findings and scores.
        """
        results = []
        triggered_detectors = []
        total_score = 0.0

        for detector in DETECTORS:
            result = detector.analyze(event, db)
            results.append({
                "detector_name": result.detector_name,
                "triggered": result.triggered,
                "score": result.score,
                "reason": result.reason
            })
            
            if result.triggered:
                triggered_detectors.append(result.detector_name)
                total_score += result.score

        return {
            "event_id": str(event.id),
            "total_score": total_score,
            "triggered_detectors": triggered_detectors,
            "results": results
        }
