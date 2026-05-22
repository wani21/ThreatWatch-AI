import uuid
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.services.risk_assessment_service import RiskAssessmentService

router = APIRouter()


class RiskAssessmentResponse(BaseModel):
    event_id: str = Field(..., description="The unique identifier of the assessed login event.")
    risk_score: int = Field(..., description="The calculated normalized combined risk score [0, 100].")
    risk_level: str = Field(..., description="The threat classification level: LOW, MEDIUM, HIGH, CRITICAL.")
    reasons: List[str] = Field(..., description="List of explainable security hazard findings triggered by this login attempt.")


@router.post(
    "/risk-assessment/{event_id}",
    response_model=RiskAssessmentResponse,
    status_code=status.HTTP_200_OK,
    summary="Generate a comprehensive risk assessment for a login attempt",
    description="Loads a login attempt event, triggers both the heuristic security rule checks and the behavioral AI model anomaly detection, combines findings to produce a capped score [0, 100], determines the risk tier, compiles explainable threat reasons, and persists findings in the database.",
    response_description="Returns the consolidated threat score, threat tier level, and list of triggering factors."
)
def evaluate_event_risk(event_id: str, db: Session = Depends(get_db)):
    """
    Infers, scores, levels, and persists the security risk profile for a specific login attempt.
    """
    # 1. Validate event_id conforms to a correct UUID format
    try:
        event_uuid = uuid.UUID(event_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid event ID structure: '{event_id}'. Must be a valid UUID string format."
        )

    try:
        # 2. Coordinate risk assessment lifecycle
        risk_service = RiskAssessmentService(db)
        result = risk_service.evaluate_and_persist(event_uuid)

        return RiskAssessmentResponse(
            event_id=result["event_id"],
            risk_score=result["risk_score"],
            risk_level=result["risk_level"],
            reasons=result["reasons"]
        )

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Internal error processing risk scoring: {str(e)}"
        )
