import uuid
from datetime import datetime
from sqlalchemy import String, Boolean, DateTime, ForeignKey, func, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_hash: Mapped[str] = mapped_column(String(64), index=True)  # SHA-256 or similar unique fingerprint
    
    browser: Mapped[str] = mapped_column(String(50))
    os: Mapped[str] = mapped_column(String(50))
    device_type: Mapped[str] = mapped_column(String(50))  # mobile, desktop, tablet
    
    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    trusted: Mapped[bool] = mapped_column(Boolean, default=False)

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="devices")

    def __repr__(self) -> str:
        return f"<Device user_id={self.user_id} os={self.os} browser={self.browser}>"
