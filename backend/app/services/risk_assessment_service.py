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

        # 6. Real-Time Alert Manager & Email Notification Dispatch
        if assessment.risk_level in ["HIGH", "CRITICAL"]:
            # Check if alert already exists for this risk assessment
            from app.models.alert import Alert
            from app.services.email_service import EmailService
            
            existing_alert = self.db.query(Alert).filter(Alert.risk_assessment_id == assessment.id).first()
            if not existing_alert:
                # Resolve alert type dynamically based on triggered reasons
                alert_type = "suspicious_activity"
                reasons_str = " ".join(assessment.risk_factors or []).lower()
                
                if "impossible travel" in reasons_str:
                    alert_type = "impossible_travel"
                elif "brute force" in reasons_str or "multiple failed" in reasons_str:
                    alert_type = "brute_force"
                elif "device" in reasons_str or "unknown device" in reasons_str:
                    alert_type = "new_device"
                elif "location" in reasons_str or "unusual location" in reasons_str:
                    alert_type = "new_location"
                elif "timing" in reasons_str or "unusual timing" in reasons_str:
                    alert_type = "unusual_timings"

                # Standard detailed threat message
                threat_msg = f"Automated ThreatWatch Alert: Detected high-severity {alert_type.replace('_', ' ')} incident. " \
                             f"User account: {event.user.email if event.user else 'Unknown'}. Risk Score: {int(assessment.total_score)}/100."

                new_alert = Alert(
                    risk_assessment_id=assessment.id,
                    alert_type=alert_type,
                    severity=assessment.risk_level.lower(),  # "high" or "critical"
                    message=threat_msg,
                    status="open"
                )
                self.db.add(new_alert)
                self.db.commit()
                self.db.refresh(new_alert)
                print(f"[+] Alert ticket {new_alert.id} saved in Alert Manager database.")

                # Trigger Email Dispatch
                user_email = event.user.email if event.user else "security@sentinel.ai"
                geo_location = f"{event.city or 'Unknown'}, {event.country or 'Unknown'}"
                
                EmailService.send_security_alert(
                    user_email=user_email,
                    timestamp=event.timestamp,
                    location=geo_location,
                    risk_score=int(assessment.total_score),
                    risk_level=assessment.risk_level,
                    triggered_factors=assessment.risk_factors or []
                )

        # Format and return the standard API response structure
        return {
            "event_id": str(event_id),
            "risk_score": int(assessment.total_score),
            "risk_level": assessment.risk_level,
            "anomaly_score": float(assessment.anomaly_score),
            "reasons": assessment.risk_factors
        }
