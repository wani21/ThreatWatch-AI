import os
import pickle
from typing import List
from sklearn.ensemble import IsolationForest

class IsolationForestDetector:
    """
    Machine Learning wrapper for scikit-learn's Isolation Forest model.
    Responsible for training, saving, loading, and predicting anomalies on login features.
    """

    def __init__(self, model_path: str = None):
        if model_path is None:
            # Set default path relative to this file: backend/app/ml/models/isolation_forest.pkl
            base_dir = os.path.dirname(os.path.abspath(__file__))
            model_path = os.path.join(base_dir, "models", "isolation_forest.pkl")
            
        self.model_path = model_path
        self.model: Optional[IsolationForest] = None
        self.load_model()

    def load_model(self) -> None:
        """Loads the serialized Isolation Forest model from disk if it exists."""
        if os.path.exists(self.model_path):
            try:
                with open(self.model_path, "rb") as f:
                    self.model = pickle.load(f)
                print(f"[+] Loaded Isolation Forest model from {self.model_path}")
            except Exception as e:
                print(f"[!] Error loading model from {self.model_path}: {e}")
                self.model = None

    def save_model(self) -> None:
        """Serializes and saves the active Isolation Forest model to disk."""
        if self.model is None:
            raise ValueError("No active model to save. Please fit the model first.")
            
        # Ensure the target directory exists
        os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
        
        try:
            with open(self.model_path, "wb") as f:
                pickle.dump(self.model, f)
            print(f"[+] Saved Isolation Forest model to {self.model_path}")
        except Exception as e:
            print(f"[!] Error saving model to {self.model_path}: {e}")

    def fit(self, X: List[List[float]]) -> None:
        """
        Trains the Isolation Forest model on a collection of feature vectors.
        Uses standard parameters optimized for network access outlier detection.
        """
        if not X:
            raise ValueError("Cannot train model on empty training data.")

        print(f"[*] Fitting Isolation Forest model on {len(X)} training samples...")
        # contamination represents expected anomaly rate. Standard is ~2-3% in normal login datasets,
        # but 0.05 (5%) is standard for robust threat filtering.
        self.model = IsolationForest(
            n_estimators=150,
            max_samples="auto",
            contamination=0.03,
            random_state=42
        )
        self.model.fit(X)
        self.save_model()

    def predict(self, X: List[float]) -> bool:
        """
        Predicts if a single feature vector is anomalous.
        Returns True if anomalous (outlier), False if normal (inlier).
        """
        if self.model is None:
            raise RuntimeError("Model has not been trained or loaded.")
            
        # Isolation Forest predict returns 1 for inliers and -1 for outliers
        prediction = self.model.predict([X])[0]
        return prediction == -1

    def score(self, X: List[float]) -> float:
        """
        Computes a normalized anomaly score in the range [0.0, 1.0].
        A value closer to 1.0 represents high risk/extreme anomaly,
        while a value closer to 0.0 is completely normal.
        """
        if self.model is None:
            raise RuntimeError("Model has not been trained or loaded.")

        # decision_function returns negative values for anomalies, positive for normal
        # Typical range is [-0.5, 0.5]
        raw_score = self.model.decision_function([X])[0]
        
        # Map decision score to anomaly score [0, 1] where:
        # - Negative decision_score (anomaly) maps to higher values (e.g. > 0.5)
        # - Positive decision_score (normal) maps to lower values (e.g. < 0.5)
        # Standard mapping: anomaly_score = 0.5 - raw_score
        # Let's map it linearly to give realistic high scores to true outliers:
        anomaly_score = 0.5 - raw_score
        
        # Clip to ensure bounds [0.0, 1.0]
        return float(max(0.0, min(1.0, anomaly_score)))
