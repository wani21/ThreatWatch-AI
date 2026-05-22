import uuid
from typing import Dict, Any
from sqlalchemy.orm import Session

from app.models.login_event import LoginEvent
from app.ml.feature_builder import FeatureBuilder
from app.ml.anomaly_detector import IsolationForestDetector

class AnomalyService:
    """
    Orchestrator service that bridges database operations, feature extraction,
    and Machine Learning inference to deliver real-time login anomaly analysis.
    """

    def __init__(self, db: Session):
        self.db = db
        self.feature_builder = FeatureBuilder(db)
        self.detector = IsolationForestDetector()

    def ensure_trained(self) -> None:
        """
        Ensures the Isolation Forest model is trained and active.
        If missing, it triggers an automatic self-healing training cycle.
        """
        if self.detector.model is not None:
            return

        print("[!] Isolation Forest model not found. Commencing self-healing auto-train...")
        
        # 1. Pre-build profiles for all users to ensure features can be correctly calculated
        from app.services.profile_builder import UserProfileBuilder
        profile_builder = UserProfileBuilder(self.db)
        profile_builder.build_all_profiles()

        # 2. Fetch historical successful login events
        events = (
            self.db.query(LoginEvent)
            .filter(LoginEvent.status == "success")
            .order_by(LoginEvent.timestamp.asc())
            .all()
        )

        if not events:
            raise ValueError("No historical successful login events found in database to train Isolation Forest.")

        # 3. Build feature vectors for all historical logins
        print(f"[*] Extracting feature vectors for {len(events)} login events...")
        X = []
        for event in events:
            try:
                features = self.feature_builder.build_features(event)
                X.append(features)
            except Exception as e:
                # Logging individual extraction errors, continuing chunk
                print(f"[!] Warning: Failed to extract features for event {event.id}: {e}")

        if not X:
            raise ValueError("Failed to extract feature vectors from historical login events.")

        # 4. Fit the Isolation Forest model and save it
        self.detector.fit(X)
        print("[+] Self-healing auto-train completed successfully!")

    def detect_anomaly(self, event_id: uuid.UUID) -> Dict[str, Any]:
        """
        Loads a LoginEvent by ID, executes feature engineering, runs
        the Isolation Forest anomaly detector, and outputs a formatted threat report.
        """
        # Fetch the target event
        event = self.db.query(LoginEvent).filter(LoginEvent.id == event_id).first()
        if not event:
            raise ValueError(f"Login event with ID {event_id} does not exist in database.")

        # Ensure the underlying ML model is trained and active
        self.ensure_trained()

        # Generate numerical feature vector for the login event
        features = self.feature_builder.build_features(event)

        # Run Isolation Forest prediction and risk scoring
        is_anomalous = self.detector.predict(features)
        anomaly_score = self.detector.score(features)

        # Return standardized anomaly detection response
        return {
            "anomaly_score": anomaly_score,
            "is_anomalous": is_anomalous
        }
