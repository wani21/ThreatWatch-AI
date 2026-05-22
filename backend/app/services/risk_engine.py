from typing import Dict, Any, List, Optional


class RiskEngine:
    """
    Core security scoring engine that combines rule-based detector outputs
    with behavioral machine learning anomaly scores to assess login event risk.
    """

    @staticmethod
    def calculate_risk(
        detector_results: List[Dict[str, Any]],
        anomaly_score: float,
        is_anomalous: bool
    ) -> Dict[str, Any]:
        """
        Processes heuristic detector results and AI anomaly metrics to calculate
        the final normalized risk score, category level, and explainable reasons.

        Args:
            detector_results (List[Dict[str, Any]]): List of detector dictionaries from DetectionService.
                Each dict has: {'detector_name': str, 'triggered': bool, 'score': float, 'reason': str}
            anomaly_score (float): The AI behavioral anomaly score in range [0.0, 1.0].
            is_anomalous (bool): Flag indicating if the AI model classified the event as anomalous.

        Returns:
            Dict[str, Any]: Consolidated threat report containing scores, level, and reasons.
        """
        # Initialize default values
        failed_login_score = 0.0
        timing_score = 0.0
        device_score = 0.0
        location_score = 0.0
        travel_score = 0.0
        reasons: List[str] = []

        # Parse heuristic detector outcomes
        for result in detector_results:
            detector_name = result.get("detector_name")
            triggered = result.get("triggered", False)
            score = result.get("score", 0.0)

            if triggered:
                if detector_name == "failed_login":
                    failed_login_score = score
                    reasons.append("Multiple failed login attempts")
                elif detector_name == "timing":
                    timing_score = score
                    reasons.append("Unusual login timing detected")
                elif detector_name == "device":
                    device_score = score
                    reasons.append("Unknown device detected")
                elif detector_name == "location":
                    location_score = score
                    reasons.append("Login from unusual location")
                elif detector_name == "travel":
                    travel_score = score
                    reasons.append("Impossible travel behavior")

        # Process AI Anomaly impact
        ai_contribution = anomaly_score * 25.0
        if is_anomalous:
            reasons.append("AI anomaly detected")

        # Sum rules + AI contributions
        raw_total_score = (
            failed_login_score
            + timing_score
            + device_score
            + location_score
            + travel_score
            + ai_contribution
        )

        # Normalize/Cap final score at 100
        total_score = min(100.0, raw_total_score)

        # Map to Risk Level
        # 0-30 LOW, 31-60 MEDIUM, 61-80 HIGH, 81-100 CRITICAL
        if total_score <= 30.0:
            risk_level = "LOW"
        elif total_score <= 60.0:
            risk_level = "MEDIUM"
        elif total_score <= 80.0:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        return {
            "failed_login_score": failed_login_score,
            "unusual_time_score": timing_score,
            "new_device_score": device_score,
            "new_location_score": location_score,
            "travel_score": travel_score,
            "anomaly_score": anomaly_score,
            "raw_total_score": raw_total_score,
            "total_score": round(total_score, 2),
            "risk_level": risk_level,
            "reasons": reasons
        }
