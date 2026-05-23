from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.schemas.auth import LoginRequest, LoginResponse
from app.services.auth_service import AuthService

router = APIRouter()


@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Simulated user login and automatic security analysis pipeline trigger",
    description=(
        "Authenticates simulated user credentials, logs a LoginEvent inside PostgreSQL, "
        "immediately triggers the rule checks and ML behavioral Isolation Forest scoring, "
        "and compiles a persistent RiskAssessment security verdict in a single API call."
    ),
    response_description="Returns the authentication status, PostgreSQL event ID, combined threat score, risk tier, and triggered reasons list.",
    responses={
        200: {
            "description": "Unified authentication and real-time security pipeline verdict.",
            "content": {
                "application/json": {
                    "examples": {
                        "successful_login": {
                            "summary": "1. Successful Login",
                            "description": "Standard daytime successful login originating from a common location on a verified trusted device.",
                            "value": {
                                "authenticated": True,
                                "event_id": "038899cd-e916-4ffb-86aa-efc738d64fd5",
                                "risk_score": 6,
                                "risk_level": "LOW",
                                "anomaly_score": 0.2676,
                                "triggered_factors": []
                            }
                        },
                        "failed_login": {
                            "summary": "2. Failed Login",
                            "description": "Failed authentication event due to a wrong password entry from standard location and time.",
                            "value": {
                                "authenticated": False,
                                "event_id": "60f43992-18cc-43bc-a651-407b144abfe1",
                                "risk_score": 28,
                                "risk_level": "LOW",
                                "anomaly_score": 0.3455,
                                "triggered_factors": ["Unusual login timing detected"]
                            }
                        },
                        "multiple_failed_login": {
                            "summary": "3. Multiple Failed Logins",
                            "description": "High threat brute force attempt. Multiple consecutive password failures within a 5-minute sliding window.",
                            "value": {
                                "authenticated": False,
                                "event_id": "7157b24a-f49d-43b9-b65e-f2a76624f0c3",
                                "risk_score": 65,
                                "risk_level": "HIGH",
                                "anomaly_score": 0.234,
                                "triggered_factors": [
                                    "Multiple failed login attempts",
                                    "Unusual login timing detected"
                                ]
                            }
                        },
                        "new_device_scenario": {
                            "summary": "4. New Device Scenario",
                            "description": "A successful login matching baseline location and hour, but originating from an untrusted client device.",
                            "value": {
                                "authenticated": True,
                                "event_id": "47a9aab0-a604-4176-b130-279530213541",
                                "risk_score": 31,
                                "risk_level": "MEDIUM",
                                "anomaly_score": 0.467,
                                "triggered_factors": [
                                    "Unknown device detected",
                                    "AI anomaly detected"
                                ]
                            }
                        },
                        "impossible_travel_scenario": {
                            "summary": "5. Impossible Travel Scenario",
                            "description": "Critical security threat. Rapid velocity geographic displacement (e.g., Pune followed by New York in 10 minutes) on untrusted client device.",
                            "value": {
                                "authenticated": True,
                                "event_id": "32911401-b3f9-492b-9f5d-a5a4de5199c0",
                                "risk_score": 87,
                                "risk_level": "CRITICAL",
                                "anomaly_score": 0.7138,
                                "triggered_factors": [
                                    "Unknown device detected",
                                    "Login from unusual location",
                                    "Impossible travel behavior",
                                    "AI anomaly detected"
                                ]
                            }
                        }
                    }
                }
            }
        }
    }
)
def login(credentials: LoginRequest, db: Session = Depends(get_db)):
    """
    Simulated entrypoint that authenticates a user and triggers downstream threat analysis automatically.
    """
    auth_service = AuthService(db)
    return auth_service.authenticate_and_analyze(credentials)
