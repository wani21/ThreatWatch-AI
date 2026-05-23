import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, Any, Optional
from datetime import datetime
from app.core.config import settings


class EmailService:
    """
    Service responsible for constructing and sending high-fidelity security alert notifications
    via SMTP. Supports custom HTML layouts with severity badges and triggers console telemetry logging
    as a robust fallback when SMTP environment variables are unconfigured.
    """

    @staticmethod
    def send_security_alert(
        user_email: str,
        timestamp: datetime,
        location: str,
        risk_score: int,
        risk_level: str,
        triggered_factors: list
    ) -> bool:
        """
        Sends an HTML-styled security alert email. Falls back to detailed console log if SMTP is unconfigured.
        """
        subject = f"ThreatWatch Alert: [ {risk_level} Risk ] Suspicious Login Detected"
        
        # Color palettes for severity branding
        primary_color = "#dc3545" if risk_level == "CRITICAL" else "#fd7e14" # Crimson red vs safety orange
        badge_text_color = "#ffffff"
        
        factors_html = "".join([f"<li style='margin-bottom: 5px; color: #495057;'>{f}</li>" for f in triggered_factors])
        if not factors_html:
            factors_html = "<li>No specific factors matched (AI behavioral anomaly trigger)</li>"

        # Build highly-styled modern HTML Email template
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>{subject}</title>
        </head>
        <body style="font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f8f9fa; margin: 0; padding: 20px; color: #333333;">
            <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.08); border-top: 5px solid {primary_color};">
                
                <!-- Header -->
                <div style="background-color: #212529; padding: 25px; text-align: center; color: #ffffff;">
                    <h1 style="margin: 0; font-size: 24px; font-weight: 700; letter-spacing: 1px; color: #ffffff;">THREATWATCH<span style="color: {primary_color}; font-weight: 900;">-AI</span></h1>
                    <p style="margin: 5px 0 0 0; font-size: 13px; color: #adb5bd; text-transform: uppercase;">Real-Time Security Threat Intelligence</p>
                </div>

                <!-- Body -->
                <div style="padding: 30px;">
                    <div style="text-align: center; margin-bottom: 25px;">
                        <span style="background-color: {primary_color}; color: {badge_text_color}; padding: 8px 18px; border-radius: 20px; font-weight: bold; font-size: 14px; text-transform: uppercase; letter-spacing: 0.5px;">
                            {risk_level} RISK DETECTED
                        </span>
                        <h2 style="margin-top: 15px; font-size: 20px; color: #212529; font-weight: 600;">Suspicious User Access Attempt</h2>
                    </div>

                    <p style="font-size: 15px; line-height: 1.5; color: #495057;">
                        The ThreatWatch engine has flagged an anomalous authentication event matching high-severity threat signatures. Review the access telemetry below:
                    </p>

                    <!-- Telemetry Details Table -->
                    <table style="width: 100%; border-collapse: collapse; margin: 25px 0; background-color: #f8f9fa; border-radius: 6px; overflow: hidden;">
                        <tr>
                            <td style="padding: 12px 15px; font-weight: bold; color: #495057; border-bottom: 1px solid #dee2e6; width: 35%;">User Account</td>
                            <td style="padding: 12px 15px; color: #212529; border-bottom: 1px solid #dee2e6;">{user_email}</td>
                        </tr>
                        <tr>
                            <td style="padding: 12px 15px; font-weight: bold; color: #495057; border-bottom: 1px solid #dee2e6;">Time (UTC)</td>
                            <td style="padding: 12px 15px; color: #212529; border-bottom: 1px solid #dee2e6;">{timestamp.strftime('%Y-%m-%d %H:%M:%S')}</td>
                        </tr>
                        <tr>
                            <td style="padding: 12px 15px; font-weight: bold; color: #495057; border-bottom: 1px solid #dee2e6;">Source Location</td>
                            <td style="padding: 12px 15px; color: #212529; border-bottom: 1px solid #dee2e6;">{location}</td>
                        </tr>
                        <tr>
                            <td style="padding: 12px 15px; font-weight: bold; color: #495057; border-bottom: 1px solid #dee2e6;">Combined Risk Score</td>
                            <td style="padding: 12px 15px; color: {primary_color}; font-weight: bold; border-bottom: 1px solid #dee2e6; font-size: 18px;">{risk_score} / 100</td>
                        </tr>
                    </table>

                    <!-- Risk Factors -->
                    <div style="background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; border-radius: 4px; margin-bottom: 25px;">
                        <h4 style="margin: 0 0 8px 0; color: #856404; font-size: 14px; text-transform: uppercase;">Triggered Risk Factors</h4>
                        <ul style="margin: 0; padding-left: 20px; font-size: 14px;">
                            {factors_html}
                        </ul>
                    </div>

                    <!-- CTA -->
                    <div style="text-align: center; margin-top: 30px; margin-bottom: 15px;">
                        <p style="font-size: 12px; color: #6c757d; margin-bottom: 15px;">Please log in to the ThreatWatch-AI operations console to inspect the complete payload details.</p>
                    </div>
                </div>

                <!-- Footer -->
                <div style="background-color: #f1f3f5; padding: 15px 25px; text-align: center; font-size: 11px; color: #868e96; border-top: 1px solid #e9ecef;">
                    This is an automated alert generated by the ThreatWatch-AI Security System.<br>
                    &copy; 2026 Sentinel-AI Security Operations Centre.
                </div>
            </div>
        </body>
        </html>
        """

        # Verify SMTP configurations
        has_creds = (
            settings.EMAIL_USERNAME is not None and 
            settings.EMAIL_PASSWORD is not None and 
            settings.EMAIL_RECEIVER is not None
        )

        # Resolve all target recipients (Deduplicated Admin and User email)
        target_recipients = list(set(filter(None, [settings.EMAIL_RECEIVER, user_email])))

        if not has_creds:
            # High-fidelity Console Telemetry Fallback
            print("=" * 80)
            print("                     THREATWATCH-AI SMTP SECURITY TELEMETRY")
            print("=" * 80)
            print(f" [!] SMTP Credentials not configured in .env. Falling back to Console Broadcast.")
            print(f" [>] TARGETS: {', '.join(target_recipients)}")
            print(f" [>] SUBJECT: {subject}")
            print(f" [>] USER ACCOUNT:   {user_email}")
            print(f" [>] DETECTED TIME:  {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f" [>] SOURCE GEO:     {location}")
            print(f" [>] RISK SCORE:     {risk_score} / 100  ({risk_level} RISK)")
            print(f" [>] RISK FACTORS:")
            for f in triggered_factors:
                print(f"      - {f}")
            print("=" * 80)
            return True

        try:
            # Construct standard SMTP Mail envelope
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = settings.EMAIL_USERNAME
            msg["To"] = ", ".join(target_recipients)

            # Attach styled HTML layout
            msg.attach(MIMEText(html_body, "html"))

            # Dispatch over standard SMTP connection
            with smtplib.SMTP(settings.EMAIL_HOST, settings.EMAIL_PORT) as server:
                server.starttls() # Secure socket connection upgrade
                server.login(settings.EMAIL_USERNAME, settings.EMAIL_PASSWORD)
                server.sendmail(settings.EMAIL_USERNAME, target_recipients, msg.as_string())

            print(f"[+] Security Alert email dispatched successfully to {', '.join(target_recipients)} via {settings.EMAIL_HOST}!")
            return True
        except Exception as e:
            print(f"[!] Error: Failed to dispatch security alert email over SMTP: {e}")
            return False
