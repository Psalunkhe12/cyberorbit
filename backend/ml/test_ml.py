import unittest
import os
import tempfile
from pathlib import Path
from backend.ml.features import FeatureExtractor, FEATURE_NAMES
from backend.ml.train import ModelTrainer
from backend.ml.detector import MLDetector, detect_anomaly


class TestCyberOrbitMLAnomalyDetection(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.model_dir = Path(self.temp_dir.name)
        self.sample_event = {
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.1",
            "destination_port": 443,
            "protocol": "TCP",
            "duration": 2.5,
            "packets_in": 50,
            "packets_out": 50,
            "bytes_in": 2500,
            "bytes_out": 2500,
            "application": "https",
            "raw_event": {
                "flow": {"pkts_toserver": 50, "pkts_toclient": 50, "bytes_toserver": 2500, "bytes_toclient": 2500, "age": 2.5},
                "dest_port": 443,
            },
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_7_feature_extraction(self):
        """Verify feature vector contains all 7 required features"""
        vector = FeatureExtractor.extract_features(self.sample_event)
        self.assertEqual(len(vector), 7)
        self.assertEqual(len(vector), len(FEATURE_NAMES))

        features_dict = FeatureExtractor.extract_features_dict(self.sample_event)
        required_features = {
            "packets_per_second",
            "bytes_per_second",
            "connection_duration",
            "destination_port",
            "unique_destination_count",
            "failed_connection_count",
            "dns_request_count",
        }
        self.assertEqual(required_features, set(features_dict.keys()))
        self.assertEqual(features_dict["destination_port"], 443.0)
        self.assertEqual(features_dict["connection_duration"], 2.5)

    def test_model_training_and_artifact_saving(self):
        """Verify training pipeline trains IsolationForest and saves artifacts outside frontend source code"""
        trainer = ModelTrainer(model_dir=self.model_dir)
        success = trainer.train_and_save(num_samples=200)
        
        self.assertTrue(success)
        self.assertTrue((self.model_dir / "isolation_forest.pkl").exists())
        self.assertTrue((self.model_dir / "scaler.pkl").exists())
        self.assertTrue((self.model_dir / "model_meta.json").exists())

    def test_prediction_output_structure(self):
        """
        Verify prediction function returns dictionary with:
        - anomaly_score
        - is_anomaly
        - model_version
        """
        # Train model in temp dir
        trainer = ModelTrainer(model_dir=self.model_dir)
        trainer.train_and_save(num_samples=200)

        detector = MLDetector(model_dir=self.model_dir)
        result = detector.detect_anomaly(self.sample_event)

        self.assertIn("anomaly_score", result)
        self.assertIn("is_anomaly", result)
        self.assertIn("model_version", result)

        self.assertIsInstance(result["anomaly_score"], float)
        self.assertIsInstance(result["is_anomaly"], bool)
        self.assertIsInstance(result["model_version"], str)
        self.assertTrue(0.0 <= result["anomaly_score"] <= 1.0)

    def test_no_specific_attack_type_claimed(self):
        """Verify anomaly detector identifies anomalous behavior without claiming specific attack types"""
        detector = MLDetector(model_dir=self.model_dir)
        anomalous_event = {
            "packets_in": 10000,
            "packets_out": 0,
            "bytes_in": 500000,
            "duration": 0.5,
            "destination_port": 4444,
        }
        res = detector.detect_anomaly(anomalous_event)

        description = str(res.get("description", "")).lower()
        forbidden_attack_labels = ["ddos", "syn flood", "sqli", "xss", "rce", "port scan"]
        for forbidden in forbidden_attack_labels:
            self.assertNotIn(forbidden, description)

    def test_global_detect_anomaly_helper(self):
        """Verify detect_anomaly helper function"""
        res = detect_anomaly(self.sample_event)
        self.assertIn("anomaly_score", res)
        self.assertIn("is_anomaly", res)
        self.assertIn("model_version", res)


if __name__ == "__main__":
    unittest.main()
