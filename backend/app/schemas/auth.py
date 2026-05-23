from typing import List
from pydantic import BaseModel, Field, EmailStr


class LoginRequest(BaseModel):
    """
    Pydantic schema model representing a simulated hackathon user authentication request,
    containing both user credentials and contextual environmental metrics.
    """
    email: EmailStr = Field(..., description="Simulated user email address.", example="admin@sentinel.ai")
    password: str = Field(..., description="Simulated login password.", example="password123")
    city: str = Field(..., description="Simulated login source city.", example="Pune")
    country: str = Field(..., description="Simulated login source country.", example="India")
    device_type: str = Field(..., description="Simulated login operating system (maps to os database column).", example="Windows")
    browser: str = Field(..., description="Simulated login client browser.", example="Chrome")
    ip_address: str = Field(..., description="Simulated login client IP address.", example="192.168.1.10")


class LoginResponse(BaseModel):
    """
    Pydantic schema model representing the complete real-time security pipeline response,
    combining authentication results with instant ML threat scores and rule detections.
    """
    authenticated: bool = Field(..., description="Flag indicating if user credentials matched.")
    event_id: str = Field(..., description="The unique UUID key of the generated LoginEvent record.")
    risk_score: int = Field(..., description="Unified normalized threat risk score [0, 100].")
    risk_level: str = Field(..., description="Unified risk level classification: LOW, MEDIUM, HIGH, CRITICAL.")
    anomaly_score: float = Field(..., description="Pre-trained Isolation Forest behavioral anomaly score [0.0, 1.0].")
    triggered_factors: List[str] = Field(..., description="Detailed list of explanation factors triggered across all security layers.")
