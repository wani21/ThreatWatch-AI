import uuid
from typing import Dict, Any
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.models.login_event import LoginEvent
from app.models.risk_assessment import RiskAssessment
from app.services.detection_service import DetectionService
from app.services.anomaly_service import AnomalyService
from app.services.risk_engine import RiskEngine


class RiskAssessmentService:
    """
    Orchestration service that loads login events, coordinates heuristic detection 
    and machine learning behavior analysis, computes final threat scores, 
    and persists findings in the database.
    """

    def __init__(self, db: Session):
        self.db = db

    def _ensure_schema_upgraded(self) -> None:
        """
        Dynamically executes an idempotent ALTER TABLE query on PostgreSQL.
        Ensures that existing databases are upgraded with the 'risk_factors' JSON column.
        """
        try:
            self.db.execute(text("ALTER TABLE risk_assessments ADD COLUMN IF NOT EXISTS risk_factors JSON;"))
            self.db.commit()
        except Exception as e:
            self.db.rollback()
            print(f"[!] Warning: Failed to run schema self-healing upgrade for risk_factors: {e}")

    def evaluate_and_persist(self, event_id: uuid.UUID) -> Dict[str, Any]:
        """
        Executes a complete risk analysis lifecycle for a specific login attempt and saves results.

        1. Fetch the target login event.
        2. Run rule-based detection engine (failed attempts, location, travel, timing, device checks).
        3. Run AI behavioral anomaly detection service (Isolation Forest inference).
        4. Synthesize overall risk using RiskEngine.
        5. Store assessment report in the database.

        Args:
            event_id (uuid.UUID): Unique identifier of the LoginEvent to assess.

        Returns:
            Dict[str, Any]: Processed threat report for API exposure.
        """
        # Ensure database table is upgraded with risk_factors JSON column
        self._ensure_schema_upgraded()

        # 1. Fetch Login Event
        event = self.db.query(LoginEvent).filter(LoginEvent.id == event_id).first()
        if not event:
            raise ValueError(f"Login event with ID {event_id} does not exist.")

        # 2. Run Heuristic Rule-Based Detectors
        detection_res = DetectionService.analyze_event(event, self.db)
        detector_results = detection_res.get("results", [])

        # 3. Run AI Behavioral Anomaly Detector
        anomaly_service = AnomalyService(self.db)
        anomaly_res = anomaly_service.detect_anomaly(event_id)
        anomaly_score = anomaly_res.get("anomaly_score", 0.0)
        is_anomalous = anomaly_res.get("is_anomalous", False)

        # 4. Process combined risk scores through the RiskEngine
        risk_evaluation = RiskEngine.calculate_risk(
            detector_results=detector_results,
            anomaly_score=anomaly_score,
            is_anomalous=is_anomalous
        )

        # 5. Persist Risk Assessment results
        # Look for existing assessment to avoid unique constraint collisions
        assessment = self.db.query(RiskAssessment).filter(
            RiskAssessment.login_event_id == event_id
        ).first()

        if not assessment:
            assessment = RiskAssessment(login_event_id=event_id)
            self.db.add(assessment)

        # Map details to database columns
        assessment.failed_login_score = risk_evaluation["failed_login_score"]
        assessment.unusual_time_score = risk_evaluation["unusual_time_score"]
        assessment.new_device_score = risk_evaluation["new_device_score"]
        
        # Combine New Location Score + Travel Score into new_location_score 
        # to cleanly map geographical hazards in the DB schema
        assessment.new_location_score = risk_evaluation["new_location_score"] + risk_evaluation["travel_score"]
        
        assessment.anomaly_score = risk_evaluation["anomaly_score"]
        assessment.total_score = risk_evaluation["total_score"]
        assessment.risk_level = risk_evaluation["risk_level"]
        assessment.risk_factors = risk_evaluation["reasons"]

        self.db.commit()
        self.db.refresh(assessment)

        # Format and return the standard API response structure
        return {
            "event_id": str(event_id),
            "risk_score": int(assessment.total_score),
            "risk_level": assessment.risk_level,
            "anomaly_score": float(assessment.anomaly_score),
            "reasons": assessment.risk_factors
        }
