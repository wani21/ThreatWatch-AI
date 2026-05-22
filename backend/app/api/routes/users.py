from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.database import get_db

router = APIRouter()


@router.get("/", status_code=status.HTTP_200_OK)
def get_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """
    Retrieve users list (primarily for dashboard analytics).
    """
    return {"users": [], "count": 0}


@router.get("/{user_id}/profile", status_code=status.HTTP_200_OK)
def get_user_behavior_profile(user_id: str, db: Session = Depends(get_db)):
    """
    Retrieve user behavioral baseline profile.
    """
    return {"user_id": user_id, "profile": {}}
