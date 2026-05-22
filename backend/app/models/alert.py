import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, ForeignKey, func, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    risk_assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("risk_assessments.id", ondelete="CASCADE"), nullable=False, index=True
    )
    
    alert_type: Mapped[str] = mapped_column(String(50), index=True)  # e.g., "brute_force", "impossible_travel", "unusual_timings"
    severity: Mapped[str] = mapped_column(String(20), default="medium")  # low, medium, high, critical
    message: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(20), default="open")  # open, acknowledged, resolved
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )

    # Relationships
    risk_assessment: Mapped["RiskAssessment"] = relationship("RiskAssessment", back_populates="alerts")

    def __repr__(self) -> str:
        return f"<Alert type={self.alert_type} severity={self.severity} status={self.status}>"
