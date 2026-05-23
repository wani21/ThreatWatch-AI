from typing import Generator
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from app.core.config import settings

# Create standard SQLAlchemy engine
# pool_pre_ping is enabled to prevent stale connection errors
db_url = settings.DATABASE_URL or "sqlite:///threatwatch.db"
if db_url.startswith("sqlite"):
    engine = create_engine(
        db_url,
        connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(
        db_url,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20
    )

# Create transactional SessionLocal class
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

# Standard Declarative Base for models
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """
    FastAPI Dependency to inject database sessions into path operations.
    Guarantees session closing after request lifecycle.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
