from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.login_event import LoginEvent
from app.services.detection_service import DetectionService

router = APIRouter()


@router.post("/analyze-event/{event_id}", status_code=status.HTTP_200_OK)
def analyze_login_event(event_id: str, db: Session = Depends(get_db)):
    """
    Accepts a login event UUID, retrieves the attempt telemetry from the database,
    triggers the complete ThreatWatch-AI Detection Engine check suite, and returns the threat evaluation.
    """
    # Load the login event from the database
    event = db.query(LoginEvent).filter(LoginEvent.id == event_id).first()
    
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Login event with ID {event_id} not found."
        )
        
    # Execute the detection suite via the service layer
    analysis_results = DetectionService.analyze_event(event, db)
    
    return {
        "event_id": str(event.id),
        "total_score": analysis_results["total_score"],
        "results": [
            {
                "detector_name": r["detector_name"],
                "triggered": r["triggered"],
                "score": r["score"]
            }
            for r in analysis_results["results"]
        ]
    }
