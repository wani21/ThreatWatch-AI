from sqlalchemy.orm import Session
from app.models.login_event import LoginEvent
from app.models.device import Device
from app.detectors.base_detector import BaseDetector, DetectionResult


class NewDeviceDetector(BaseDetector):
    """
    Checks if the login event originated from an unknown or untrusted client device.
    """

    @property
    def name(self) -> str:
        return "device"

    def analyze(self, event: LoginEvent, db: Session) -> DetectionResult:
        # If no device_id is associated with the event, it's immediately unrecognized
        if not event.device_id:
            return DetectionResult(
                detector_name=self.name,
                triggered=True,
                score=20.0,
                reason="Unknown device detected"
            )

        # Check if the device exists in the devices database and belongs to this user
        device = db.query(Device).filter(
            Device.id == event.device_id,
            Device.user_id == event.user_id
        ).first()

        # Trigger if the device is not found, or if it is explicitly untrusted
        if not device or not device.trusted:
            return DetectionResult(
                detector_name=self.name,
                triggered=True,
                score=20.0,
                reason="Unknown device detected"
            )

        return DetectionResult(
            detector_name=self.name,
            triggered=False,
            score=0.0,
            reason="Trusted device verified"
        )
