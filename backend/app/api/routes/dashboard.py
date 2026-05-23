from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.core.database import get_db
from app.models.login_event import LoginEvent
from app.models.risk_assessment import RiskAssessment
from app.models.alert import Alert
from app.models.user import User

router = APIRouter()


@router.get("/dashboard-stats", status_code=status.HTTP_200_OK)
def get_dashboard_stats(db: Session = Depends(get_db)):
    """
    Retrieves aggregated cyber security operational telemetry directly from PostgreSQL.
    No hardcoded counts or dummy values.
    """
    # Aggregate Login Statistics
    total_logins = db.query(LoginEvent).count()
    successful_logins = db.query(LoginEvent).filter(LoginEvent.status == "success").count()
    failed_logins = db.query(LoginEvent).filter(LoginEvent.status == "failed").count()

    # Aggregate Alert Statistics
    total_alerts = db.query(Alert).count()
    open_alerts = db.query(Alert).filter(Alert.status == "open").count()
    critical_alerts = db.query(Alert).filter(Alert.severity == "critical").count()

    # Aggregate High-Risk Events (where RiskAssessment total_score is high/critical)
    high_risk_events = db.query(RiskAssessment).filter(
        RiskAssessment.risk_level.in_(["HIGH", "CRITICAL"])
    ).count()

    # Fetch Recent Security Events (last 10 login attempts with user details and risk evaluation)
    # Perform a left join from LoginEvent to User and RiskAssessment
    recent_events_query = (
        db.query(LoginEvent, User.email, RiskAssessment)
        .join(User, LoginEvent.user_id == User.id)
        .outerjoin(RiskAssessment, LoginEvent.id == RiskAssessment.login_event_id)
        .order_by(LoginEvent.timestamp.desc())
        .limit(10)
        .all()
    )

    recent_events = []
    for event, email, assessment in recent_events_query:
        recent_events.append({
            "id": str(event.id),
            "email": email,
            "timestamp": event.timestamp,
            "status": event.status,
            "ip_address": event.ip_address,
            "location": f"{event.city or 'Unknown'}, {event.country or 'Unknown'}",
            "browser": event.browser,
            "os": event.os,
            "risk_score": int(assessment.total_score) if assessment else 0,
            "risk_level": assessment.risk_level if assessment else "LOW",
            "reasons": assessment.risk_factors if assessment else []
        })

    # Fetch Recent Alerts (last 10 Alert tickets joined with User and RiskAssessment)
    recent_alerts_query = (
        db.query(Alert, RiskAssessment, LoginEvent, User.email)
        .join(RiskAssessment, Alert.risk_assessment_id == RiskAssessment.id)
        .join(LoginEvent, RiskAssessment.login_event_id == LoginEvent.id)
        .join(User, LoginEvent.user_id == User.id)
        .order_by(Alert.created_at.desc())
        .limit(10)
        .all()
    )

    recent_alerts = []
    for alert, assessment, event, email in recent_alerts_query:
        recent_alerts.append({
            "id": str(alert.id),
            "risk_assessment_id": str(alert.risk_assessment_id),
            "email": email,
            "alert_type": alert.alert_type,
            "severity": alert.severity,
            "message": alert.message,
            "status": alert.status,
            "risk_score": int(assessment.total_score),
            "created_at": alert.created_at
        })

    return {
        "metrics": {
            "total_logins": total_logins,
            "successful_logins": successful_logins,
            "failed_logins": failed_logins,
            "total_alerts": total_alerts,
            "open_alerts": open_alerts,
            "critical_alerts": critical_alerts,
            "high_risk_events": high_risk_events
        },
        "recent_events": recent_events,
        "recent_alerts": recent_alerts
    }


@router.get("/user-stats", status_code=status.HTTP_200_OK)
def get_user_stats(email: str, db: Session = Depends(get_db)):
    """
    Retrieves personal security telemetry for a specific employee straight from PostgreSQL.
    """
    user = db.query(User).filter(User.email == email).first()
    if not user:
        return {"error": "User not found"}

    # Personal login statistics
    total_logins = db.query(LoginEvent).filter(LoginEvent.user_id == user.id).count()
    success_logins = db.query(LoginEvent).filter(LoginEvent.user_id == user.id, LoginEvent.status == "success").count()
    fail_logins = db.query(LoginEvent).filter(LoginEvent.user_id == user.id, LoginEvent.status == "failed").count()

    # Retrieve their recent logins
    recent_events_query = (
        db.query(LoginEvent, RiskAssessment)
        .outerjoin(RiskAssessment, LoginEvent.id == RiskAssessment.login_event_id)
        .filter(LoginEvent.user_id == user.id)
        .order_by(LoginEvent.timestamp.desc())
        .limit(10)
        .all()
    )

    recent_events = []
    for event, assessment in recent_events_query:
        recent_events.append({
            "id": str(event.id),
            "timestamp": event.timestamp,
            "status": event.status,
            "ip_address": event.ip_address,
            "location": f"{event.city or 'Unknown'}, {event.country or 'Unknown'}",
            "browser": event.browser,
            "os": event.os,
            "risk_score": int(assessment.total_score) if assessment else 0,
            "risk_level": assessment.risk_level if assessment else "LOW"
        })

    # Retrieve behavioral profile baseline
    baseline = user.behavior_profile
    baseline_data = {
        "common_city": baseline.common_city if baseline else "Pune",
        "common_country": baseline.common_country if baseline else "India",
        "common_browser": baseline.common_browser if baseline else "Chrome",
        "common_os": baseline.common_os if baseline else "Windows",
        "avg_login_hour": baseline.avg_login_hour if baseline else 12.0
    }

    return {
        "metrics": {
            "total_logins": total_logins,
            "success_logins": success_logins,
            "fail_logins": fail_logins
        },
        "recent_events": recent_events,
        "baseline": baseline_data,
        "username": user.username,
        "role": user.role,
        "department": user.department
    }
