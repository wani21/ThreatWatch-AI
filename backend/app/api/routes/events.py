from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.login_event import LoginEvent

router = APIRouter()


@router.get("/", status_code=status.HTTP_200_OK)
def get_login_events(
    skip: int = 0,
    limit: int = 100,
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by login status ('success' or 'failed')"),
    user_id_filter: Optional[str] = Query(None, alias="user_id", description="Filter events for a specific user UUID"),
    db: Session = Depends(get_db)
):
    """
    Retrieve paginated login event audit logs from the database, sorted chronologically (newest first).
    Supports filtering by status (success/failed) and user.
    """
    query = db.query(LoginEvent)
    
    # Apply optional status filters
    if status_filter:
        query = query.filter(LoginEvent.status == status_filter)
        
    # Apply optional user filters
    if user_id_filter:
        query = query.filter(LoginEvent.user_id == user_id_filter)
        
    # Count total matching entries
    total = query.count()
    
    # Query matching slice, newest first
    events = query.order_by(LoginEvent.timestamp.desc()).offset(skip).limit(limit).all()
    
    return {
        "total_events": total,
        "skip": skip,
        "limit": limit,
        "events": [
            {
                "id": str(e.id),
                "user_id": str(e.user_id),
                "timestamp": e.timestamp,
                "status": e.status,
                "ip_address": e.ip_address,
                "country": e.country,
                "country_code": e.country_code,
                "city": e.city,
                "browser": e.browser,
                "os": e.os,
                "device_id": str(e.device_id) if e.device_id else None,
                "session_id": e.session_id,
                "latitude": e.latitude,
                "longitude": e.longitude,
                "auth_method": e.auth_method,
                "source": e.source,
                "isp": e.isp
            }
            for e in events
        ]
    }
