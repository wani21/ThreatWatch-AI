from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.database import get_db

router = APIRouter()


@router.get("/", status_code=status.HTTP_200_OK)
def get_login_events(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """
    Get historical login events for audit logs and risk analysis.
    """
    return {"events": [], "count": 0}
