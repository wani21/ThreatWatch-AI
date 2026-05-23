import uuid
from fastapi import APIRouter, Depends, Request, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
import os

from app.core.database import get_db
from app.models.alert import Alert
from app.models.risk_assessment import RiskAssessment
from app.models.login_event import LoginEvent
from app.models.user import User

router = APIRouter()

# Resolve correct templates directory absolute path relative to main app entrypoint
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))


@router.get("/", response_class=HTMLResponse)
@router.get("/login", response_class=HTMLResponse)
def serve_login_page(request: Request):
    """
    Renders the employee threatwatch portal login view.
    """
    return templates.TemplateResponse(request=request, name="login.html")


@router.get("/home", response_class=HTMLResponse)
def serve_employee_home_page(request: Request):
    """
    Renders the clean Employee Welcome Workspace landing home page.
    """
    return templates.TemplateResponse(request=request, name="home.html")


@router.get("/admin/dashboard", response_class=HTMLResponse)
def serve_admin_dashboard_page(request: Request):
    """
    Renders the main Security Operations Center (SOC) dashboard.
    """
    return templates.TemplateResponse(request=request, name="dashboard.html")


@router.get("/admin/alerts", response_class=HTMLResponse)
def serve_admin_alerts_page(request: Request):
    """
    Renders the active threat alerts inventory list.
    """
    return templates.TemplateResponse(request=request, name="alerts.html")


@router.get("/admin/investigation/{alert_id}", response_class=HTMLResponse)
def serve_admin_investigation_page(request: Request, alert_id: str, db: Session = Depends(get_db)):
    """
    Renders the forensic deep analysis screen for a specific active security alert,
    preloading direct database details from related events and profiles.
    """
    try:
        alert_uuid = uuid.UUID(alert_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid Alert UUID format.")

    # Retrieve matching Alert
    alert = db.query(Alert).filter(Alert.id == alert_uuid).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert ticket not found.")

    # Trace database relations
    risk_assessment = alert.risk_assessment
    login_event = risk_assessment.login_event if risk_assessment else None
    user = login_event.user if login_event else None

    # Load baseline profile if available
    baseline = user.behavior_profile if user else None

    return templates.TemplateResponse(
        request=request,
        name="investigation.html",
        context={
            "alert": alert,
            "risk_assessment": risk_assessment,
            "login_event": login_event,
            "user": user,
            "baseline": baseline
        }
    )
