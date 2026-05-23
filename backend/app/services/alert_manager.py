import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional, List
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.alert import Alert
from app.models.risk_assessment import RiskAssessment
from app.models.login_event import LoginEvent
from app.models.user import User


class AlertManager:
    """
    Alert Manager Service
    Responsible for generating database Alert records and dispatching real-time
    security email notifications to the affected User and system Administrator.
    """

    def __init__(self, db: Session):
        self.db = db

    def generate_and_route_alert(self, assessment: RiskAssessment) -> Optional[Alert]:
        """
        Evaluates a RiskAssessment, checks if it violates the safety threshold,
        generates a persistent Alert database record, and routes email alerts.
        """
        # 1. Check if the assessment meets the notification threshold
        if assessment.total_score < settings.ALERT_THRESHOLD_SCORE:
            print(
                f"[AlertManager] Event {assessment.login_event_id} risk score "
                f"({assessment.total_score}) is below threshold ({settings.ALERT_THRESHOLD_SCORE}). "
                f"Skipping alerting."
            )
            return None

        print(
            f"[AlertManager] SUSPICIOUS LOG IN: Event {assessment.login_event_id} scored "
            f"{assessment.total_score} ({assessment.risk_level.upper()}). Initiating Alert Chain..."
        )

        # 2. Check if an alert has already been generated to prevent duplicates
        alert = (
            self.db.query(Alert)
            .filter(Alert.risk_assessment_id == assessment.id)
            .first()
        )

        if not alert:
            # Determine type of threat based on factors
            alert_type = self._determine_alert_type(assessment)
            
            # Format high-fidelity explanation message
            factors_desc = ", ".join(assessment.risk_factors) if assessment.risk_factors else "Unusual behavior"
            message = f"Suspicious login activity flagged: {factors_desc}."
            
            # Write alert to database
            alert = Alert(
                risk_assessment_id=assessment.id,
                alert_type=alert_type,
                severity=assessment.risk_level.lower(),
                message=message,
                status="open"
            )
            
            self.db.add(alert)
            self.db.commit()
            self.db.refresh(alert)
            print(f"[AlertManager] [+] Database Alert record created: ID {alert.id}")
        else:
            print(f"[AlertManager] Alert record already exists for assessment: ID {alert.id}")

        # 3. Retrieve event and user relations to populate email contexts
        event = assessment.login_event
        if not event:
            print("[AlertManager] [!] Error: No LoginEvent associated with the assessment. Aborting email routing.")
            return alert

        user = event.user
        if not user:
            print("[AlertManager] [!] Error: No User associated with the login event. Aborting email routing.")
            return alert

        # 4. Dispatch security alerts
        self._send_user_email(user, event, assessment)
        self._send_admin_email(user, event, assessment)

        return alert

    def _determine_alert_type(self, assessment: RiskAssessment) -> str:
        """Helper to classify alert category based on triggered risk factors."""
        factors = [f.lower() for f in (assessment.risk_factors or [])]
        
        if any("failed" in f or "brute" in f for f in factors):
            return "brute_force"
        if any("travel" in f or "impossible" in f for f in factors):
            return "impossible_travel"
        if any("location" in f or "unusual" in f in f for f in factors):
            return "unusual_location"
        if any("device" in f or "new" in f in f for f in factors):
            return "new_device"
        if any("time" in f or "hour" in f for f in factors):
            return "unusual_timing"
        if any("ai" in f or "anomaly" in f for f in factors):
            return "behavioral_anomaly"
            
        return "unusual_login"

    def _send_email_via_smtp(self, recipient: str, subject: str, html_content: str, plain_text: str) -> bool:
        """Sends an email using standard SMTP. Returns True on success, False otherwise."""
        if not settings.SMTP_HOST:
            return False

        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = settings.ALERT_EMAIL_FROM
            msg["To"] = recipient

            part1 = MIMEText(plain_text, "plain")
            part2 = MIMEText(html_content, "html")

            msg.attach(part1)
            msg.attach(part2)

            with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
                if settings.SMTP_USER and settings.SMTP_PASSWORD:
                    server.starttls()
                    server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
                server.sendmail(settings.ALERT_EMAIL_FROM, recipient, msg.as_string())
            return True
        except Exception as e:
            print(f"[AlertManager] [!] Failed to send SMTP email to {recipient}: {e}")
            return False

    def _send_user_email(self, user: User, event: LoginEvent, assessment: RiskAssessment) -> None:
        """Dispatches a notification warning to the user."""
        subject = "Security Alert: Suspicious Login Attempt Detected"
        recipient = user.email or f"{user.username}@threatwatch.ai"
        
        factors_str = ", ".join(assessment.risk_factors) if assessment.risk_factors else "Unusual behavior patterns"
        
        plain_text = (
            f"Hello {user.username},\n\n"
            f"We detected a highly suspicious login attempt associated with your account on ThreatWatch-AI.\n\n"
            f"Security Risk Details:\n"
            f"- Risk Score: {assessment.total_score} ({assessment.risk_level.upper()})\n"
            f"- Time (UTC): {event.timestamp}\n"
            f"- IP Address: {event.ip_address}\n"
            f"- Location: {event.city}, {event.country}\n"
            f"- Device: {event.browser} on {event.os} ({event.source})\n"
            f"- Triggers: {factors_str}\n\n"
            f"If you logged in recently, you can safely ignore this alert. If you do not recognize this login, "
            f"please change your password immediately to protect your account.\n\n"
            f"Sincerely,\nThreatWatch-AI Security Team"
        )

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Suspicious Login Alert</title>
</head>
<body style="font-family: 'Inter', Arial, sans-serif; background-color: #f4f6f8; padding: 20px; color: #333; margin: 0;">
  <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; border: 1px solid #e1e4e6; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.05);">
    <div style="background-color: #1e293b; padding: 24px; text-align: center; color: #ffffff;">
      <h2 style="margin: 0; font-size: 22px; font-weight: 600; letter-spacing: 0.5px;">Security Alert: Suspicious Login</h2>
    </div>
    <div style="padding: 24px; line-height: 1.6;">
      <p>Hello <strong>{user.username}</strong>,</p>
      <p>We detected an unusual or highly suspicious login attempt associated with your account on ThreatWatch-AI.</p>
      <div style="background-color: #f8fafc; border-left: 4px solid #ef4444; padding: 16px; margin: 20px 0; border-radius: 4px;">
        <h4 style="margin: 0 0 10px 0; color: #b91c1c; font-size: 16px;">Security Risk Details:</h4>
        <table style="width: 100%; font-size: 14px; border-collapse: collapse;">
          <tr>
            <td style="padding: 4px 0; font-weight: 600; width: 120px; color: #475569;">Risk Score:</td>
            <td style="padding: 4px 0; font-weight: 600; color: #ef4444;">{assessment.total_score} ({assessment.risk_level.upper()})</td>
          </tr>
          <tr>
            <td style="padding: 4px 0; color: #475569;">Time (UTC):</td>
            <td style="padding: 4px 0; color: #0f172a;">{event.timestamp}</td>
          </tr>
          <tr>
            <td style="padding: 4px 0; color: #475569;">IP Address:</td>
            <td style="padding: 4px 0; color: #0f172a;">{event.ip_address}</td>
          </tr>
          <tr>
            <td style="padding: 4px 0; color: #475569;">Location:</td>
            <td style="padding: 4px 0; color: #0f172a;">{event.city}, {event.country}</td>
          </tr>
          <tr>
            <td style="padding: 4px 0; color: #475569;">Device:</td>
            <td style="padding: 4px 0; color: #0f172a;">{event.browser} on {event.os} ({event.source})</td>
          </tr>
          <tr>
            <td style="padding: 4px 0; color: #475569;">Triggers:</td>
            <td style="padding: 4px 0; color: #ef4444; font-style: italic;">{factors_str}</td>
          </tr>
        </table>
      </div>
      <p style="margin-top: 24px;"><strong>Was this you?</strong></p>
      <p style="font-size: 14px; color: #64748b;">If you logged in recently from this location or device, you can safely ignore this alert. If you do not recognize this login, please <strong>change your password immediately</strong> to secure your account.</p>
    </div>
    <div style="background-color: #f1f5f9; padding: 16px; text-align: center; font-size: 12px; color: #94a3b8; border-top: 1px solid #e2e8f0;">
      This is an automated security notification from ThreatWatch-AI. Please do not reply directly to this email.
    </div>
  </div>
</body>
</html>"""

        # Try to send via SMTP; if host config is missing, fall back to console print
        sent = self._send_email_via_smtp(recipient, subject, html_content, plain_text)
        if not sent:
            print("\n" + "="*80)
            print(f"[CONSOLE LOG FALLBACK] DISPATCHING USER SECURITY EMAIL TO: {recipient}")
            print(f"SUBJECT: {subject}")
            print("-"*80)
            print(plain_text)
            print("="*80 + "\n")

    def _send_admin_email(self, user: User, event: LoginEvent, assessment: RiskAssessment) -> None:
        """Dispatches an audit threat warning to the security administrator."""
        subject = f"[Alert] Security Threat Detected - User: {user.username}"
        recipient = settings.ADMIN_EMAIL
        
        factors_str = ", ".join(assessment.risk_factors) if assessment.risk_factors else "Unusual behavior patterns"
        
        plain_text = (
            f"ADMIN SECURITY DISPATCH\n"
            f"=======================\n"
            f"A login attempt has triggered a {assessment.risk_level.upper()} risk assessment event exceeding safety thresholds.\n\n"
            f"Security Metrics:\n"
            f"- User Impacted: {user.username} (ID: {user.id})\n"
            f"- Risk Score: {assessment.total_score} / 100.0\n"
            f"- Timestamp (UTC): {event.timestamp}\n"
            f"- IP Address: {event.ip_address}\n"
            f"- ISP / Net: {event.isp or 'Unknown'}\n"
            f"- Location: {event.city}, {event.country} (Coords: {event.latitude}, {event.longitude})\n"
            f"- Device Specs: {event.browser} on {event.os} ({event.source})\n"
            f"- Triggered Flags: {factors_str}\n\n"
            f"Please check security database logs for event ID: {event.id} to initiate responsive controls.\n"
        )

        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Admin Critical Security Alert</title>
</head>
<body style="font-family: 'Inter', Arial, sans-serif; background-color: #0f172a; padding: 20px; color: #f8fafc; margin: 0;">
  <div style="max-width: 650px; margin: 0 auto; background-color: #1e293b; border-radius: 8px; border: 1px solid #334155; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.15);">
    <div style="background-color: #991b1b; padding: 24px; text-align: center; color: #ffffff;">
      <h2 style="margin: 0; font-size: 22px; font-weight: 600; letter-spacing: 0.5px;">[ALERT] Critical Threat Detected</h2>
    </div>
    <div style="padding: 24px; line-height: 1.6;">
      <p style="color: #cbd5e1;">A login attempt has triggered a <strong>{assessment.risk_level.upper()}</strong> risk assessment event exceeding safety thresholds.</p>
      
      <div style="background-color: #311010; border-left: 4px solid #ef4444; padding: 16px; margin: 20px 0; border-radius: 4px;">
        <h4 style="margin: 0 0 10px 0; color: #f87171; font-size: 16px;">Security Assessment Metrics:</h4>
        <table style="width: 100%; font-size: 14px; border-collapse: collapse; color: #e2e8f0;">
          <tr>
            <td style="padding: 4px 0; font-weight: 600; width: 140px; color: #94a3b8;">User Impacted:</td>
            <td style="padding: 4px 0; font-weight: 600; color: #f8fafc;">{user.username} (ID: {user.id})</td>
          </tr>
          <tr>
            <td style="padding: 4px 0; font-weight: 600; color: #94a3b8;">Risk Score:</td>
            <td style="padding: 4px 0; font-weight: 600; color: #f87171;">{assessment.total_score} / 100.0</td>
          </tr>
          <tr>
            <td style="padding: 4px 0; color: #94a3b8;">Timestamp (UTC):</td>
            <td style="padding: 4px 0; color: #e2e8f0;">{event.timestamp}</td>
          </tr>
          <tr>
            <td style="padding: 4px 0; color: #94a3b8;">IP Address:</td>
            <td style="padding: 4px 0; color: #e2e8f0;">{event.ip_address}</td>
          </tr>
          <tr>
            <td style="padding: 4px 0; color: #94a3b8;">ISP / Organization:</td>
            <td style="padding: 4px 0; color: #e2e8f0;">{event.isp or 'Unknown'}</td>
          </tr>
          <tr>
            <td style="padding: 4px 0; color: #94a3b8;">Location:</td>
            <td style="padding: 4px 0; color: #e2e8f0;">{event.city}, {event.country} (Coordinates: {event.latitude}, {event.longitude})</td>
          </tr>
          <tr>
            <td style="padding: 4px 0; color: #94a3b8;">Device Specs:</td>
            <td style="padding: 4px 0; color: #e2e8f0;">{event.browser} on {event.os} ({event.source})</td>
          </tr>
          <tr>
            <td style="padding: 4px 0; color: #94a3b8;">Triggered Flags:</td>
            <td style="padding: 4px 0; color: #f87171; font-weight: 600;">{factors_str}</td>
          </tr>
        </table>
      </div>
      
      <p style="font-size: 14px; color: #94a3b8; margin-top: 24px;">Please check security database logs for event ID <code>{event.id}</code> to initiate investigation and response guidelines.</p>
    </div>
    <div style="background-color: #0f172a; padding: 16px; text-align: center; font-size: 12px; color: #475569; border-top: 1px solid #334155;">
      ThreatWatch-AI Security Alert Orchestrator Daemon.
    </div>
  </div>
</body>
</html>"""

        # Try to send via SMTP; if host config is missing, fall back to console print
        sent = self._send_email_via_smtp(recipient, subject, html_content, plain_text)
        if not sent:
            print("\n" + "="*80)
            print(f"[CONSOLE LOG FALLBACK] DISPATCHING ADMIN SECURITY ALERT TO: {recipient}")
            print(f"SUBJECT: {subject}")
            print("-"*80)
            print(plain_text)
            print("="*80 + "\n")

    def send_otp_email(self, user: User, event: LoginEvent, otp: str) -> None:
        """
        Dispatches a beautiful, high-fidelity 2-Factor OTP verification email to the user.
        """
        subject = "Security Alert: 2-Factor OTP Verification Code Required"
        recipient = user.email or f"{user.username}@threatwatch.ai"
        
        plain_text = (
            f"Hello {user.username},\n\n"
            f"A login attempt was initiated on your ThreatWatch-AI account that has triggered our severe security risk threshold.\n\n"
            f"To complete authentication, please enter the following 6-digit OTP verification code on the login page:\n\n"
            f"   >>> {otp} <<<\n\n"
            f"MFA Details:\n"
            f"- Time (UTC): {event.timestamp}\n"
            f"- IP Address: {event.ip_address}\n"
            f"- Location: {event.city or 'Unknown'}, {event.country or 'Unknown'}\n"
            f"- Device: {event.browser} on {event.os} ({event.source})\n\n"
            f"If you did not initiate this login attempt, please secure your account credentials immediately.\n\n"
            f"Sincerely,\nThreatWatch-AI Security Daemon"
        )
        
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>2-Factor Verification Code</title>
</head>
<body style="font-family: 'Inter', Arial, sans-serif; background-color: #f8fafc; padding: 20px; color: #1e293b; margin: 0;">
  <div style="max-width: 550px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; border: 1px solid #e2e8f0; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
    <div style="background: linear-gradient(135deg, #4f46e5 0%, #6366f1 100%); padding: 24px; text-align: center; color: #ffffff;">
      <h2 style="margin: 0; font-size: 20px; font-weight: 600; letter-spacing: 0.5px;">2-Factor OTP Verification</h2>
    </div>
    <div style="padding: 28px; line-height: 1.6;">
      <p>Hello <strong>{user.username}</strong>,</p>
      <p>A login attempt was initiated on your ThreatWatch-AI account that has triggered our severe security risk thresholds due to a highly unusual context.</p>
      
      <p style="margin-top: 24px; text-align: center; font-size: 14px; color: #64748b; text-transform: uppercase; letter-spacing: 1px; font-weight: 600;">Your 6-Digit OTP Code:</p>
      <div style="background-color: #f1f5f9; border: 1px dashed #cbd5e1; border-radius: 8px; padding: 16px; margin: 10px 0; text-align: center; font-size: 32px; font-weight: 800; letter-spacing: 6px; color: #4f46e5;">
        {otp}
      </div>
      <p style="font-size: 12px; text-align: center; color: #94a3b8; margin-top: 4px; margin-bottom: 24px;">(This code is valid for 10 minutes and should not be shared.)</p>
      
      <div style="background-color: #f8fafc; border-left: 4px solid #4f46e5; padding: 14px; border-radius: 4px; font-size: 13px; color: #334155; margin-bottom: 24px;">
        <table style="width: 100%; border-collapse: collapse;">
          <tr>
            <td style="padding: 2px 0; font-weight: 600; width: 100px; color: #64748b;">Time (UTC):</td>
            <td style="padding: 2px 0; color: #0f172a;">{event.timestamp}</td>
          </tr>
          <tr>
            <td style="padding: 2px 0; font-weight: 600; color: #64748b;">IP Address:</td>
            <td style="padding: 2px 0; color: #0f172a;">{event.ip_address}</td>
          </tr>
          <tr>
            <td style="padding: 2px 0; font-weight: 600; color: #64748b;">Location:</td>
            <td style="padding: 2px 0; color: #0f172a;">{event.city or 'Unknown'}, {event.country or 'Unknown'}</td>
          </tr>
          <tr>
            <td style="padding: 2px 0; font-weight: 600; color: #64748b;">Device:</td>
            <td style="padding: 2px 0; color: #0f172a;">{event.browser} on {event.os} ({event.source})</td>
          </tr>
        </table>
      </div>
      
      <p style="font-size: 13px; color: #64748b;">If you did not initiate this login request, please ignore this email or change your password immediately to protect your account.</p>
    </div>
    <div style="background-color: #f1f5f9; padding: 16px; text-align: center; font-size: 11px; color: #94a3b8; border-top: 1px solid #e2e8f0;">
      This is an automated verification message from ThreatWatch-AI. Please do not reply directly.
    </div>
  </div>
</body>
</html>"""
        
        sent = self._send_email_via_smtp(recipient, subject, html_content, plain_text)
        if not sent:
            print("\n" + "="*80)
            print(f"[CONSOLE LOG FALLBACK] DISPATCHING 2FA OTP CODE TO: {recipient}")
            print(f"SUBJECT: {subject}")
            print("-"*80)
            print(plain_text)
            print("="*80 + "\n")
