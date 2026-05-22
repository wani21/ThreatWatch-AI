# Import all models to ensure they are registered with the metadata for migrations
from app.core.database import Base
from app.models.user import User
from app.models.device import Device
from app.models.login_event import LoginEvent
from app.models.user_profile import UserBehaviorProfile
from app.models.risk_assessment import RiskAssessment
from app.models.alert import Alert

# Export all models for easier imports elsewhere in the application
__all__ = [
    "Base",
    "User",
    "Device",
    "LoginEvent",
    "UserBehaviorProfile",
    "RiskAssessment",
    "Alert",
]
