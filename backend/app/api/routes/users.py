from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.user import User
from app.models.user_profile import UserBehaviorProfile

router = APIRouter()


@router.get("/", status_code=status.HTTP_200_OK)
def get_users(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    """
    Retrieve seeded users list from the database, primarily for dashboard analytics.
    Supports pagination via `skip` and `limit`.
    """
    users = db.query(User).offset(skip).limit(limit).all()
    total = db.query(User).count()
    
    return {
        "total_users": total,
        "skip": skip,
        "limit": limit,
        "users": [
            {
                "id": str(u.id),
                "username": u.username,
                "email": u.email,
                "role": u.role,
                "department": u.department,
                "created_at": u.created_at,
                "last_login": u.last_login
            }
            for u in users
        ]
    }


@router.get("/{user_id}/profile", status_code=status.HTTP_200_OK)
def get_user_behavior_profile(user_id: str, db: Session = Depends(get_db)):
    """
    Retrieve the baseline behavioral trend profile for a specific user.
    """
    profile = db.query(UserBehaviorProfile).filter(UserBehaviorProfile.user_id == user_id).first()
    if not profile:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User behavioral profile with user_id {user_id} not found."
        )
        
    return {
        "user_id": str(profile.user_id),
        "avg_login_hour": profile.avg_login_hour,
        "std_login_hour": profile.std_login_hour,
        "common_country": profile.common_country,
        "common_city": profile.common_city,
        "common_browser": profile.common_browser,
        "common_os": profile.common_os,
        "login_frequency_per_day": profile.login_frequency_per_day,
        "updated_at": profile.updated_at
    }
