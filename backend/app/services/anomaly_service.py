import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, List
import numpy as np
from sqlalchemy.orm import Session

from app.models.login_event import LoginEvent
from app.ml.model_loader import model_loader
from app.detectors.device_detector import NewDeviceDetector
from app.detectors.location_detector import NewLocationDetector
from app.detectors.travel_detector import ImpossibleTravelDetector


def map_device_type(os_str: str) -> str:
    """
    Standardizes a database LoginEvent 'os' string to match one of the expected
    label-encoder classes: ['Android', 'Linux', 'MacOS', 'Windows', 'iPhone', 'nan']
    """
    if not os_str:
        return "nan"
    os_lower = os_str.lower()
    if "windows" in os_lower:
        return "Windows"
    if "android" in os_lower:
        return "Android"
    if "mac" in os_lower:
        return "MacOS"
    if "ios" in os_lower or "iphone" in os_lower or "ipad" in os_lower:
        return "iPhone"
    if "linux" in os_lower:
        return "Linux"
    return "nan"


def map_browser(browser_str: str) -> str:
    """
    Standardizes a database LoginEvent 'browser' string to match one of the expected
    label-encoder classes: ['Chrome', 'Edge', 'Firefox', 'Safari', 'nan']
    """
    if not browser_str:
        return "nan"
    browser_lower = browser_str.lower()
    if "chrome" in browser_lower:
        return "Chrome"
    if "edge" in browser_lower:
        return "Edge"
    if "firefox" in browser_lower:
        return "Firefox"
    if "safari" in browser_lower:
        return "Safari"
    return "nan"


class AnomalyService:
    """
    Service layer that bridges PostgreSQL, feature engineering, and our cached
    pre-trained Isolation Forest model to score login event behavioral anomalies in real-time.
    """

    def __init__(self, db: Session):
        self.db = db

    def extract_features(self, event: LoginEvent) -> List[float]:
        """
        Extracts and engineers the 18 numerical, boolean, and label-encoded 
        features from a given database LoginEvent.
        """
        # 1. login_hour
        login_hour = float(event.timestamp.hour)

        # 2. day_of_week
        day_of_week = float(event.timestamp.weekday())

        # 3. is_weekend
        is_weekend = float(1.0 if day_of_week >= 5.0 else 0.0)

        # 4. is_night
        is_night = float(1.0 if (login_hour < 6.0 or login_hour >= 22.0) else 0.0)

        # 5. is_business
        is_business = float(1.0 if 9.0 <= login_hour <= 17.0 else 0.0)

        # 6. failed_attempt_count (failed attempts by user in preceding 15 minutes)
        time_window_15m = event.timestamp - timedelta(minutes=15)
        failed_attempt_count = float(
            self.db.query(LoginEvent)
            .filter(
                LoginEvent.user_id == event.user_id,
                LoginEvent.status == "failed",
                LoginEvent.timestamp >= time_window_15m,
                LoginEvent.timestamp < event.timestamp
            )
            .count()
        )

        # 7. login_failed
        login_failed = float(1.0 if event.status == "failed" else 0.0)

        # 8. vpn_detected
        vpn_detected = float(
            1.0 if (event.isp and any(x in event.isp.lower() for x in ["vpn", "proxy", "hosting"]))
            else 0.0
        )

        # 9. tor_detected
        tor_detected = float(
            1.0 if (event.isp and "tor" in event.isp.lower())
            else 0.0
        )

        # 10. new_device
        new_device = float(1.0 if NewDeviceDetector().analyze(event, self.db).triggered else 0.0)

        # 11. new_location
        new_location = float(1.0 if NewLocationDetector().analyze(event, self.db).triggered else 0.0)

        # 12. impossible_travel
        impossible_travel = float(
            1.0 if ImpossibleTravelDetector().analyze(event, self.db).triggered else 0.0
        )

        # 13. country_enc (Categorical encoding with defensive fallback)
        country_val = event.country or "Unknown"
        le_country = model_loader.label_encoders.get("country")
        country_enc = float(
            le_country.transform([country_val])[0]
            if le_country and country_val in le_country.classes_
            else 0.0
        )

        # 14. city_enc
        city_val = event.city or "Unknown"
        le_city = model_loader.label_encoders.get("city")
        city_enc = float(
            le_city.transform([city_val])[0]
            if le_city and city_val in le_city.classes_
            else 0.0
        )

        # 15. device_type_enc (Mismatched mapping helper)
        device_type_val = map_device_type(event.os)
        le_device = model_loader.label_encoders.get("device_type")
        device_type_enc = float(
            le_device.transform([device_type_val])[0]
            if le_device and device_type_val in le_device.classes_
            else 0.0
        )

        # 16. browser_enc
        browser_val = map_browser(event.browser)
        le_browser = model_loader.label_encoders.get("browser")
        browser_enc = float(
            le_browser.transform([browser_val])[0]
            if le_browser and browser_val in le_browser.classes_
            else 0.0
        )

        # 17. login_frequency_7d
        seven_days_ago = event.timestamp - timedelta(days=7)
        login_frequency_7d = float(
            self.db.query(LoginEvent)
            .filter(
                LoginEvent.user_id == event.user_id,
                LoginEvent.timestamp >= seven_days_ago,
                LoginEvent.timestamp <= event.timestamp
            )
            .count()
        )

        # 18. avg_failed_7d
        total_attempts_7d = self.db.query(LoginEvent).filter(
            LoginEvent.user_id == event.user_id,
            LoginEvent.timestamp >= seven_days_ago,
            LoginEvent.timestamp <= event.timestamp
        ).count()
        
        failed_attempts_7d = self.db.query(LoginEvent).filter(
            LoginEvent.user_id == event.user_id,
            LoginEvent.status == "failed",
            LoginEvent.timestamp >= seven_days_ago,
            LoginEvent.timestamp <= event.timestamp
        ).count()
        
        avg_failed_7d = float(failed_attempts_7d / max(total_attempts_7d, 1))

        # Compile and return the raw 18-dimension feature vector
        return [
            login_hour, day_of_week, is_weekend, is_night, is_business,
            failed_attempt_count, login_failed, vpn_detected, tor_detected,
            new_device, new_location, impossible_travel,
            country_enc, city_enc, device_type_enc, browser_enc,
            login_frequency_7d, avg_failed_7d
        ]

    def detect_anomaly(self, event_id: uuid.UUID) -> Dict[str, Any]:
        """
        Loads a LoginEvent by ID, executes the 18-feature extraction pipeline, 
        scales features, scores anomaly via pre-trained Isolation Forest, and normalizes it.

        Args:
            event_id (uuid.UUID): Database login attempt unique key.

        Returns:
            Dict[str, Any]: AI Anomaly score and triggers evaluation dictionary.
        """
        # 1. Fetch Login Event
        event = self.db.query(LoginEvent).filter(LoginEvent.id == event_id).first()
        if not event:
            raise ValueError(f"Login event with ID {event_id} does not exist.")

        # 2. Extract 18-dimensional feature vector
        raw_vector = self.extract_features(event)

        # 3. Apply StandardScaler
        scaled_vector = model_loader.scaler.transform(np.array(raw_vector).reshape(1, -1))

        # 4. Perform Isolation Forest Prediction & Score
        prediction = model_loader.model.predict(scaled_vector)[0]  # -1 = anomaly, 1 = normal
        raw_score = model_loader.model.decision_function(scaled_vector)[0]

        # 5. Normalize score using cached bounds
        score_min = model_loader.score_bounds.get("score_min", -0.189369)
        score_max = model_loader.score_bounds.get("score_max", 0.138854)
        
        normalized_score = float(1 - (raw_score - score_min) / (score_max - score_min))
        normalized_score = float(np.clip(normalized_score, 0.0, 1.0))

        # Return standardized ML evaluation report
        return {
            "anomaly_score": round(normalized_score, 4),
            "is_anomalous": prediction == -1
        }
