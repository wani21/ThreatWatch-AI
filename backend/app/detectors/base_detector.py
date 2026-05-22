from abc import ABC, abstractmethod
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from app.models.login_event import LoginEvent


class DetectionResult(BaseModel):
    """
    Standard Pydantic contract mapping the results of any threat check execution.
    """
    detector_name: str = Field(..., description="Unique name identifying the detector.")
    triggered: bool = Field(..., description="Flag indicating if an anomaly was identified.")
    score: float = Field(..., description="The risk score grade assigned by this detector (0 if not triggered).")
    reason: str = Field(..., description="Multi-line descriptive justification explaining the trigger state.")


class BaseDetector(ABC):
    """
    Abstract Base Class defining the contract every ThreatWatch-AI detector must implement.
    """
    
    @property
    @abstractmethod
    def name(self) -> str:
        """
        The name identifying this specific detector.
        """
        pass

    @abstractmethod
    def analyze(self, event: LoginEvent, db: Session) -> DetectionResult:
        """
        Execute security baseline analysis on a single login event against historical database logs.
        """
        pass
