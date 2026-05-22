import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Float, ForeignKey, func, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class LoginEvent(Base):
    __tablename__ = "login_events"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), index=True
    )
    status: Mapped[str] = mapped_column(String(20))  # e.g., "success", "failed"
    
    ip_address: Mapped[str] = mapped_column(String(45), index=True)  # Supports IPv4 and IPv6
    country: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    city: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    
    browser: Mapped[str] = mapped_column(String(50))
    os: Mapped[str] = mapped_column(String(50))
    
    device_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("devices.id", ondelete="SET NULL"), nullable=True, index=True
    )
    session_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    
    latitude: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    longitude: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="login_events")
    device: Mapped[Optional["Device"]] = relationship("Device")
    risk_assessment: Mapped[Optional["RiskAssessment"]] = relationship(
        "RiskAssessment", back_populates="login_event", uselist=False, cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<LoginEvent user_id={self.user_id} status={self.status} ip={self.ip_address}>"
