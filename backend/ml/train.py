import os
import random
import json
from pathlib import Path
from typing import List, Dict, Any, Tuple
from backend.config.settings import settings
from backend.ml.features import FEATURE_NAMES

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    import joblib
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False

MODEL_VERSION = "v1.0.0"


class ModelTrainer:
    """
    CyberOrbit Anomaly Detection Training Pipeline.
    Trains an IsolationForest model on normal baseline network telemetry features:
    [packets_per_second, bytes_per_second, connection_duration, destination_port,
     unique_destination_count, failed_connection_count, dns_request_count]

    Saves model artifacts outside frontend source code in backend/ml/models/.
    """

    def __init__(self, model_dir: Optional[Path] = None):
        self.model_dir = Path(model_dir) if model_dir else settings.MODEL_DIR
        self.model_dir.mkdir(parents=True, exist_ok=True)
        self.model_path = self.model_dir / "isolation_forest.pkl"
        self.scaler_path = self.model_dir / "scaler.pkl"
        self.meta_path = self.model_dir / "model_meta.json"

    def generate_baseline_dataset(self, num_samples: int = 1000) -> List[List[float]]:
        """
        Generates normal network traffic baseline feature vectors.
        Includes 95% standard operational flows and 5% tail variance.
        """
        samples: List[List[float]] = []

        # 1. Standard normal web, DNS, and internal microservice flows (95% of data)
        for _ in range(int(num_samples * 0.95)):
            duration = float(random.uniform(0.1, 15.0))
            pkts = float(random.randint(2, 50))
            bytes_cnt = float(random.randint(120, 5000))

            pps = pkts / duration
            bps = bytes_cnt / duration
            dest_port = float(random.choice([80, 443, 53, 8080, 5432, 22]))
            uniq_dest = float(random.choice([1, 1, 1, 2]))
            failed_cnt = float(random.choice([0, 0, 0, 0, 1]))
            dns_cnt = float(random.choice([0, 1, 1, 2]))

            samples.append([
                pps,
                bps,
                duration,
                dest_port,
                uniq_dest,
                failed_cnt,
                dns_cnt,
            ])

        # 2. Add subtle normal traffic fluctuations (5% tail variance)
        for _ in range(int(num_samples * 0.05)):
            duration = float(random.uniform(10.0, 60.0))
            pkts = float(random.randint(50, 200))
            bytes_cnt = float(random.randint(5000, 50000))

            pps = pkts / duration
            bps = bytes_cnt / duration
            dest_port = float(random.choice([80, 443, 8080]))
            uniq_dest = float(random.randint(2, 4))
            failed_cnt = float(random.choice([0, 1]))
            dns_cnt = float(random.randint(1, 5))

            samples.append([
                pps,
                bps,
                duration,
                dest_port,
                uniq_dest,
                failed_cnt,
                dns_cnt,
            ])

        return samples

    def train_and_save(self, num_samples: int = 1000) -> bool:
        """
        Trains IsolationForest and StandardScaler, persisting artifacts outside frontend code.
        """
        if not HAS_SKLEARN:
            print("[ModelTrainer Warning] scikit-learn or joblib not installed. Cannot train IsolationForest.")
            return False

        print(f"[ModelTrainer] Generating {num_samples} baseline telemetry samples...")
        X_raw = np.array(self.generate_baseline_dataset(num_samples=num_samples))

        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X_raw)

        model = IsolationForest(
            n_estimators=100,
            contamination=getattr(settings, "ANOMALY_CONTAMINATION", 0.05),
            random_state=42,
        )
        model.fit(X_scaled)

        # Save artifacts outside frontend source code
        joblib.dump(model, self.model_path)
        joblib.dump(scaler, self.scaler_path)

        metadata = {
            "model_version": MODEL_VERSION,
            "algorithm": "IsolationForest",
            "features": FEATURE_NAMES,
            "num_samples_trained": len(X_raw),
            "contamination": getattr(settings, "ANOMALY_CONTAMINATION", 0.05),
            "created_at": settings.BASE_DIR.name,
        }

        with open(self.meta_path, "w") as f:
            json.dump(metadata, f, indent=2)

        print(f"[ModelTrainer] Successfully trained and saved IsolationForest model to {self.model_path}")
        return True


if __name__ == "__main__":
    trainer = ModelTrainer()
    trainer.train_and_save()
