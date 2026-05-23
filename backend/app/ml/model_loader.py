import json
import os
import threading
from typing import Dict, List, Any
import joblib


class ModelLoader:
    """
    Thread-safe Singleton class that loads and caches machine learning models
    and pre-processing pipeline artifacts exactly once at application startup.
    """
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        if not cls._instance:
            with cls._lock:
                if not cls._instance:
                    cls._instance = super(ModelLoader, cls).__new__(cls)
                    cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        # Prevent re-initialization in multi-threaded initialization calls
        if getattr(self, "_initialized", False):
            return

        self.model = None
        self.scaler = None
        self.label_encoders: Dict[str, Any] = {}
        self.feature_cols: List[str] = []
        self.score_bounds: Dict[str, float] = {}
        
        # Load artifacts
        self.load_artifacts()
        self._initialized = True

    def load_artifacts(self) -> None:
        """
        Loads machine learning model, scaler, encoders, features list,
        and decision scores normalization bounds from the local models folder.
        """
        # Determine the directory path containing the models
        base_dir = os.path.dirname(os.path.abspath(__file__))
        models_dir = os.path.join(base_dir, "models")

        # Define file paths
        model_path = os.path.join(models_dir, "isolation_forest.pkl")
        scaler_path = os.path.join(models_dir, "scaler.pkl")
        encoders_path = os.path.join(models_dir, "label_encoders.pkl")
        features_path = os.path.join(models_dir, "feature_cols.json")
        bounds_path = os.path.join(models_dir, "score_bounds.json")

        print("[*] ModelLoader: Initializing and caching ML pipeline assets...")

        # 1. Load Isolation Forest Model
        if os.path.exists(model_path):
            self.model = joblib.load(model_path)
            print(f"  [+] Isolation Forest model loaded successfully. Features: {self.model.n_features_in_}")
        else:
            print(f"  [!] Warning: Missing required model asset: {model_path}. Isolation Forest will run in mock mode.")
            self.model = None

        # 2. Load StandardScaler
        if os.path.exists(scaler_path):
            self.scaler = joblib.load(scaler_path)
            print("  [+] StandardScaler loaded successfully.")
        else:
            print(f"  [!] Warning: Missing required scaling asset: {scaler_path}. StandardScaler will run in mock mode.")
            self.scaler = None

        # 3. Load Label Encoders dictionary
        if os.path.exists(encoders_path):
            self.label_encoders = joblib.load(encoders_path)
            print(f"  [+] Label encoders loaded successfully for columns: {list(self.label_encoders.keys())}")
        else:
            print(f"  [!] Warning: Missing required encoding asset: {encoders_path}. Label encoders will run in mock mode.")
            self.label_encoders = {}

        # 4. Load Feature Columns list
        if os.path.exists(features_path):
            with open(features_path, "r") as f:
                self.feature_cols = json.load(f)
            print(f"  [+] Feature columns schema verified: {len(self.feature_cols)} features.")
        else:
            print(f"  [!] Warning: Missing required features schema: {features_path}. Using empty features schema.")
            self.feature_cols = []

        # 5. Load Decision Score Normalization bounds
        if os.path.exists(bounds_path):
            with open(bounds_path, "r") as f:
                self.score_bounds = json.load(f)
            print(f"  [+] Score normalization limits: Min={self.score_bounds.get('score_min')}, Max={self.score_bounds.get('score_max')}")
        else:
            print(f"  [!] Warning: Missing required score bounds: {bounds_path}. Using default normalization bounds.")
            self.score_bounds = {}

        print("[+] ModelLoader: Initialization completed (ready in dry-run/active mode)!")


# Expose singleton instance directly for easy importing across services
model_loader = ModelLoader()
