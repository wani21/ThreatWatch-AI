import uuid
from datetime import datetime
from typing import List
from sqlalchemy import String, Float, DateTime, ForeignKey, func, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class RiskAssessment(Base):
    __tablename__ = "risk_assessments"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    login_event_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("login_events.id", ondelete="CASCADE"), nullable=False, unique=True, index=True
    )
    
    failed_login_score: Mapped[float] = mapped_column(Float, default=0.0)
    unusual_time_score: Mapped[float] = mapped_column(Float, default=0.0)
    new_device_score: Mapped[float] = mapped_column(Float, default=0.0)
    new_location_score: Mapped[float] = mapped_column(Float, default=0.0)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)
    
    total_score: Mapped[float] = mapped_column(Float, default=0.0)
    risk_level: Mapped[str] = mapped_column(String(20), default="low")  # low, medium, high, critical
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )

    # Relationships
    login_event: Mapped["LoginEvent"] = relationship("LoginEvent", back_populates="risk_assessment")
    alerts: Mapped[List["Alert"]] = relationship(
        "Alert", back_populates="risk_assessment", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<RiskAssessment event_id={self.login_event_id} level={self.risk_level} total_score={self.total_score}>"
