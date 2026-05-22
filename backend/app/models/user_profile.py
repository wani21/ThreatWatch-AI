import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import String, Float, DateTime, ForeignKey, func, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class UserBehaviorProfile(Base):
    __tablename__ = "user_behavior_profiles"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True, index=True
    )
    
    avg_login_hour: Mapped[float] = mapped_column(Float, default=0.0)  # Average hour of login (0.0 to 23.99)
    std_login_hour: Mapped[float] = mapped_column(Float, default=0.0)  # Standard deviation of login hours
    
    common_country: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    common_city: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    common_browser: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    common_os: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    
    login_frequency_per_day: Mapped[float] = mapped_column(Float, default=0.0)
    
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="behavior_profile")

    def __repr__(self) -> str:
        return f"<UserBehaviorProfile user_id={self.user_id} avg_hour={self.avg_login_hour}>"
