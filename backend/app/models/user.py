import uuid
from datetime import datetime
from typing import List, Optional
from sqlalchemy import String, DateTime, func, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(100), unique=True, index=True)
    password: Mapped[str] = mapped_column(String(100), default="password123")
    role: Mapped[str] = mapped_column(String(30), default="user")
    department: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    last_login: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    devices: Mapped[List["Device"]] = relationship(
        "Device", back_populates="user", cascade="all, delete-orphan"
    )
    login_events: Mapped[List["LoginEvent"]] = relationship(
        "LoginEvent", back_populates="user", cascade="all, delete-orphan"
    )
    behavior_profile: Mapped[Optional["UserBehaviorProfile"]] = relationship(
        "UserBehaviorProfile", back_populates="user", uselist=False, cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<User username={self.username} email={self.email}>"
