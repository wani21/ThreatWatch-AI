from typing import Optional
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.alert import Alert

router = APIRouter()


@router.get("/", status_code=status.HTTP_200_OK)
def get_alerts(
    skip: int = 0,
    limit: int = 100,
    status_filter: Optional[str] = Query(None, alias="status", description="Filter alerts by status ('open', 'acknowledged', 'resolved')"),
    severity_filter: Optional[str] = Query(None, alias="severity", description="Filter alerts by severity ('low', 'medium', 'high', 'critical')"),
    db: Session = Depends(get_db)
):
    """
    Retrieve triggered threat alerts from the database, sorted by creation date (newest first).
    Supports pagination and filtering by severity or status.
    """
    query = db.query(Alert)
    
    if status_filter:
        query = query.filter(Alert.status == status_filter)
        
    if severity_filter:
        query = query.filter(Alert.severity == severity_filter)
        
    total = query.count()
    alerts = query.order_by(Alert.created_at.desc()).offset(skip).limit(limit).all()
    
    return {
        "total_alerts": total,
        "skip": skip,
        "limit": limit,
        "alerts": [
            {
                "id": str(a.id),
                "risk_assessment_id": str(a.risk_assessment_id),
                "alert_type": a.alert_type,
                "severity": a.severity,
                "message": a.message,
                "status": a.status,
                "created_at": a.created_at
            }
            for a in alerts
        ]
    }


@router.patch("/{alert_id}/status", status_code=status.HTTP_200_OK)
def update_alert_status(
    alert_id: str,
    new_status: str = Query(..., alias="status", description="New status to apply ('open', 'acknowledged', 'resolved')"),
    db: Session = Depends(get_db)
):
    """
    Update the operational lifecycle status of an alert (e.g. Acknowledging or Resolving an active threat).
    """
    if new_status not in ["open", "acknowledged", "resolved"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid alert status. Must be one of: 'open', 'acknowledged', 'resolved'."
        )
        
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat alert with ID {alert_id} not found."
        )
        
    alert.status = new_status
    db.commit()
    db.refresh(alert)
    
    return {
        "message": f"Alert status updated successfully to '{new_status}'.",
        "alert": {
            "id": str(alert.id),
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "status": alert.status,
            "updated_at": datetime.utcnow() if hasattr(alert, 'updated_at') else None
        }
    }
