import os
import json
from pathlib import Path
from typing import Dict, Any, Tuple, Optional, Union
from backend.config.settings import settings
from backend.ml.features import FeatureExtractor
from backend.ml.train import MODEL_VERSION, ModelTrainer

try:
    import numpy as np
    import joblib
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False


class MLDetector:
    """
    CyberOrbit Anomaly Detector powered by Isolation Forest.
    Identifies statistical network anomalies without claiming specific attack types.

    Returns:
    {
        "anomaly_score": float (0.0 to 1.0),
        "is_anomaly": bool,
        "model_version": str,
        "description": "Anomalous network behavior detected"
    }
    """

    def __init__(self, model_dir: Optional[Path] = None):
        self.model_dir = Path(model_dir) if model_dir else settings.MODEL_DIR
        self.model_path = self.model_dir / "isolation_forest.pkl"
        self.scaler_path = self.model_dir / "scaler.pkl"
        self.meta_path = self.model_dir / "model_meta.json"

        self.model = None
        self.scaler = None
        self.model_version = MODEL_VERSION

        self._ensure_and_load_artifacts()

    def _ensure_and_load_artifacts(self):
        """Loads model artifacts from disk, training a fresh model if missing."""
        if not HAS_SKLEARN:
            print("[MLDetector Warning] scikit-learn or joblib not installed. Using statistical fallback.")
            return

        # Train model if missing
        if not self.model_path.exists() or not self.scaler_path.exists():
            print("[MLDetector] Model artifacts not found. Initiating auto-training pipeline...")
            trainer = ModelTrainer(model_dir=self.model_dir)
            trainer.train_and_save()

        if self.model_path.exists() and self.scaler_path.exists():
            try:
                self.model = joblib.load(self.model_path)
                self.scaler = joblib.load(self.scaler_path)

                if self.meta_path.exists():
                    with open(self.meta_path, "r") as f:
                        meta = json.load(f)
                        self.model_version = meta.get("model_version", MODEL_VERSION)

                print(f"[MLDetector] Loaded IsolationForest model {self.model_version} from {self.model_path}")
            except Exception as err:
                print(f"[MLDetector Warning] Failed to load ML artifacts: {err}")

    def detect_anomaly(
        self,
        event: Dict[str, Any],
        context_stats: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Predicts if a network telemetry event represents anomalous behavior.

        Returns dictionary strictly containing:
        - anomaly_score: float (0.0 to 1.0)
        - is_anomaly: bool
        - model_version: str
        """
        features = FeatureExtractor.extract_features(event, context_stats=context_stats)

        if self.model and self.scaler and HAS_SKLEARN:
            try:
                X_scaled = self.scaler.transform([features])
                # Isolation Forest decision_function: lower/negative values indicate anomalies
                raw_decision = float(self.model.decision_function(X_scaled)[0])
                prediction = self.model.predict(X_scaled)[0]  # -1 = anomaly, 1 = normal

                is_anomaly = bool(prediction == -1)

                # Normalize decision function score into 0.0 to 1.0 anomaly score range
                # decision_function ranges roughly -0.5 (extreme anomaly) to +0.5 (normal)
                anomaly_score = float(max(0.0, min(1.0, round(0.5 - raw_decision, 4))))

                return {
                    "anomaly_score": anomaly_score,
                    "is_anomaly": is_anomaly,
                    "model_version": self.model_version,
                    "description": "Anomalous network behavior detected" if is_anomaly else "Normal network behavior",
                }
            except Exception as err:
                print(f"[MLDetector Error] Model prediction failed: {err}")

        # Statistical heuristic fallback when sklearn is absent
        pps = features[0]
        bps = features[1]
        failed_cnt = features[5]

        heuristic_score = 0.0
        if pps > 500 or bps > 100000:
            heuristic_score += 0.5
        if failed_cnt >= 5:
            heuristic_score += 0.4

        anomaly_score = min(1.0, heuristic_score)
        is_anomaly = anomaly_score >= 0.5

        return {
            "anomaly_score": float(round(anomaly_score, 4)),
            "is_anomaly": is_anomaly,
            "model_version": f"{self.model_version}-fallback",
            "description": "Anomalous network behavior detected" if is_anomaly else "Normal network behavior",
        }

    def predict_batch(
        self,
        events: List[Dict[str, Any]],
        context_stats: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Runs anomaly detection on a batch of telemetry events.
        """
        return [self.detect_anomaly(e, context_stats=context_stats) for e in events]


# Global instance helper
_detector_instance: Optional[MLDetector] = None


def detect_anomaly(
    event: Dict[str, Any],
    context_stats: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Convenience function returning {anomaly_score, is_anomaly, model_version}.
    """
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = MLDetector()
    return _detector_instance.detect_anomaly(event, context_stats=context_stats)
