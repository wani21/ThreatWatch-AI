import math
import uuid
from typing import List, Optional
from collections import Counter
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.models.login_event import LoginEvent
from app.models.user_profile import UserBehaviorProfile
from app.models.user import User

class UserProfileBuilder:
    """
    Service responsible for building and updating behavioral baselines
    for users based on their historical successful login activity.
    """

    def __init__(self, db: Session):
        self.db = db

    def build_profile_for_user(self, user_id: uuid.UUID) -> Optional[UserBehaviorProfile]:
        """
        Calculates behavior profile parameters for a specific user and persists them.
        """
        # Fetch historical SUCCESSFUL login events for the user to establish normal baseline behavior
        events = (
            self.db.query(LoginEvent)
            .filter(LoginEvent.user_id == user_id, LoginEvent.status == "success")
            .order_by(LoginEvent.timestamp.asc())
            .all()
        )

        if not events:
            return None

        # 1. Calculate average and standard deviation of login hours
        # Represent time as a decimal: hour + minute/60 + second/3600
        login_hours = [
            e.timestamp.hour + e.timestamp.minute / 60.0 + e.timestamp.second / 3600.0
            for e in events
        ]
        
        avg_login_hour = sum(login_hours) / len(login_hours)
        
        if len(login_hours) > 1:
            variance = sum((x - avg_login_hour) ** 2 for x in login_hours) / len(login_hours)
            std_login_hour = math.sqrt(variance)
        else:
            std_login_hour = 0.0

        # 2. Calculate modes (most common values) for categorical features
        def get_mode(values: List[str]) -> Optional[str]:
            filtered_values = [v for v in values if v]
            if not filtered_values:
                return None
            return Counter(filtered_values).most_common(1)[0][0]

        common_city = get_mode([e.city for e in events])
        common_country = get_mode([e.country for e in events])
        common_browser = get_mode([e.browser for e in events])
        common_os = get_mode([e.os for e in events])

        # 3. Calculate daily login frequency
        min_time = events[0].timestamp
        max_time = events[-1].timestamp
        
        # Calculate time span in days (minimum of 1 day to prevent division by zero)
        time_diff = (max_time - min_time).days
        active_days = max(time_diff, 1)
        
        login_frequency_per_day = len(events) / active_days

        # Check if behavior profile already exists for this user
        profile = (
            self.db.query(UserBehaviorProfile)
            .filter(UserBehaviorProfile.user_id == user_id)
            .first()
        )

        if not profile:
            profile = UserBehaviorProfile(user_id=user_id)
            self.db.add(profile)

        # Update profile values
        profile.avg_login_hour = float(avg_login_hour)
        profile.std_login_hour = float(std_login_hour)
        profile.common_city = common_city
        profile.common_country = common_country
        profile.common_browser = common_browser
        profile.common_os = common_os
        profile.login_frequency_per_day = float(login_frequency_per_day)
        profile.updated_at = datetime.now()

        self.db.commit()
        self.db.refresh(profile)
        return profile

    def build_all_profiles(self) -> int:
        """
        Builds behavioral profiles for all users in the system.
        Returns the number of profiles successfully built.
        """
        users = self.db.query(User).all()
        count = 0
        for user in users:
            profile = self.build_profile_for_user(user.id)
            if profile:
                count += 1
        return count
