import uuid
from datetime import datetime, timedelta
from typing import List, Optional
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.login_event import LoginEvent
from app.models.user_profile import UserBehaviorProfile

class FeatureBuilder:
    """
    Translates database login events and user behavioral profiles into 
    numerical feature vectors ready for Isolation Forest anomaly detection.
    """

    def __init__(self, db: Session):
        self.db = db

    def build_features(self, event: LoginEvent, profile: Optional[UserBehaviorProfile] = None) -> List[float]:
        """
        Extracts a feature vector for a given LoginEvent.
        
        Features included in vector:
        1. login_hour (float, 0.0 to 23.99)
        2. failed_attempt_count (count of failures in preceding 15 mins)
        3. new_device_flag (1.0 if device is untrusted or unseen, else 0.0)
        4. new_location_flag (1.0 if city/country is not common, else 0.0)
        5. city_frequency (frequency of current city in user's history)
        6. country_frequency (frequency of current country in user's history)
        7. device_frequency (frequency of current browser/os in user's history)
        8. login_frequency (historical average daily frequency from profile)
        """
        # 1. Ensure we have the user behavior profile
        if not profile:
            profile = (
                self.db.query(UserBehaviorProfile)
                .filter(UserBehaviorProfile.user_id == event.user_id)
                .first()
            )

        # 2. login_hour (Float value of decimal hour)
        login_hour = event.timestamp.hour + event.timestamp.minute / 60.0 + event.timestamp.second / 3600.0

        # 3. failed_attempt_count (failed logins in the last 15 minutes)
        time_window_start = event.timestamp - timedelta(minutes=15)
        failed_attempt_count = (
            self.db.query(LoginEvent)
            .filter(
                LoginEvent.user_id == event.user_id,
                LoginEvent.status == "failed",
                LoginEvent.timestamp >= time_window_start,
                LoginEvent.timestamp < event.timestamp
            )
            .count()
        )

        # 4. new_device_flag
        # Check if the device is explicit, if not check if it is untrusted
        new_device_flag = 0.0
        if event.device_id is None:
            new_device_flag = 1.0
        else:
            # Load associated device
            if not event.device or not event.device.trusted:
                new_device_flag = 1.0

        # 5. new_location_flag
        new_location_flag = 0.0
        if profile:
            is_new_city = event.city != profile.common_city if event.city and profile.common_city else True
            is_new_country = event.country != profile.common_country if event.country and profile.common_country else True
            if is_new_city or is_new_country:
                new_location_flag = 1.0

        # Calculate historical counts up to (and including) this event's timestamp
        # to ensure realistic frequencies and avoid future-leakage
        total_user_logins = (
            self.db.query(LoginEvent)
            .filter(
                LoginEvent.user_id == event.user_id,
                LoginEvent.status == "success",
                LoginEvent.timestamp <= event.timestamp
            )
            .count()
        )

        # Fallback to at least 1 to avoid division by zero
        total_user_logins = max(total_user_logins, 1)

        # 6. city_frequency
        city_count = 0
        if event.city:
            city_count = (
                self.db.query(LoginEvent)
                .filter(
                    LoginEvent.user_id == event.user_id,
                    LoginEvent.status == "success",
                    LoginEvent.city == event.city,
                    LoginEvent.timestamp <= event.timestamp
                )
                .count()
            )
        city_frequency = city_count / total_user_logins

        # 7. country_frequency
        country_count = 0
        if event.country:
            country_count = (
                self.db.query(LoginEvent)
                .filter(
                    LoginEvent.user_id == event.user_id,
                    LoginEvent.status == "success",
                    LoginEvent.country == event.country,
                    LoginEvent.timestamp <= event.timestamp
                )
                .count()
            )
        country_frequency = country_count / total_user_logins

        # 8. device_frequency (matching browser & OS)
        device_count = (
            self.db.query(LoginEvent)
            .filter(
                LoginEvent.user_id == event.user_id,
                LoginEvent.status == "success",
                LoginEvent.browser == event.browser,
                LoginEvent.os == event.os,
                LoginEvent.timestamp <= event.timestamp
            )
            .count()
        )
        device_frequency = device_count / total_user_logins

        # 9. login_frequency (from behavioral profile)
        login_frequency = profile.login_frequency_per_day if profile else 0.0

        return [
            float(login_hour),
            float(failed_attempt_count),
            float(new_device_flag),
            float(new_location_flag),
            float(city_frequency),
            float(country_frequency),
            float(device_frequency),
            float(login_frequency)
        ]
