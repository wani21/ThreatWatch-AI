import uuid
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.services.anomaly_service import AnomalyService

router = APIRouter()


class AnomalyResponse(BaseModel):
    event_id: str = Field(..., description="The unique identifier of the analyzed login event.")
    anomaly_score: float = Field(..., description="The calculated AI anomaly score in the range [0.0, 1.0].")
    is_anomalous: bool = Field(..., description="Flag indicating if the login attempt was classified as anomalous.")


@router.post(
    "/anomaly-detect/{event_id}",
    response_model=AnomalyResponse,
    status_code=status.HTTP_200_OK,
    summary="Detect behavioral anomalies in a login event",
    description="Loads a login event, extracts features, calculates baseline deviations, and scores the event's risk via Isolation Forest.",
    response_description="Returns the anomaly classification status and the continuous risk score."
)
def detect_anomaly(event_id: str, db: Session = Depends(get_db)):
    """
    Infers whether a specific login event behaves as an anomaly relative to user history.
    """
    # 1. Validate event_id is a correct UUID string
    try:
        event_uuid = uuid.UUID(event_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid event ID: '{event_id}'. Must be a valid UUID string format."
        )

    try:
        # 2. Initialize orchestration service and execute evaluation
        anomaly_service = AnomalyService(db)
        result = anomaly_service.detect_anomaly(event_uuid)

        return AnomalyResponse(
            event_id=event_id,
            anomaly_score=result["anomaly_score"],
            is_anomalous=result["is_anomalous"]
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error analyzing event for anomalies: {str(e)}"
        )
