import unittest
from backend.detection.scoring import RiskScorer, ScoringConfig


class TestCyberOrbitRiskScorer(unittest.TestCase):
    def setUp(self):
        self.scorer = RiskScorer()

    def test_severity_mapping_bands(self):
        """
        Verify exact band mappings:
        0-24 LOW
        25-49 MEDIUM
        50-74 HIGH
        75-100 CRITICAL
        """
        # Test low score mapped to LOW (0-24)
        score, sev = self.scorer.calculate_score(
            rule_severity="LOW",
            rule_confidence=50.0,
            asset_criticality="LOW"
        )
        self.assertLessEqual(score, 24)
        self.assertEqual(sev, "LOW")

        # Test medium score mapped to MEDIUM (25-49)
        score_med, sev_med = self.scorer.calculate_score(
            rule_severity="MEDIUM",
            rule_confidence=80.0,
            asset_criticality="MEDIUM"
        )
        self.assertTrue(25 <= score_med <= 49, f"Expected 25-49, got {score_med}")
        self.assertEqual(sev_med, "MEDIUM")

        # Test high score mapped to HIGH (50-74)
        score_high, sev_high = self.scorer.calculate_score(
            rule_severity="HIGH",
            rule_confidence=90.0,
            asset_criticality="HIGH"
        )
        self.assertTrue(50 <= score_high <= 74, f"Expected 50-74, got {score_high}")
        self.assertEqual(sev_high, "HIGH")

        # Test critical score mapped to CRITICAL (75-100)
        score_crit, sev_crit = self.scorer.calculate_score(
            rule_severity="CRITICAL",
            rule_confidence=95.0,
            asset_criticality="CRITICAL"
        )
        self.assertTrue(75 <= score_crit <= 100, f"Expected 75-100, got {score_crit}")
        self.assertEqual(sev_crit, "CRITICAL")

    def test_ml_anomaly_score_impact(self):
        """Verify ML anomaly score increases overall risk score"""
        score_without_ml, _ = self.scorer.calculate_score(
            rule_severity="MEDIUM",
            rule_confidence=80.0,
            ml_anomaly_score=None
        )
        score_with_ml, _ = self.scorer.calculate_score(
            rule_severity="MEDIUM",
            rule_confidence=80.0,
            ml_anomaly_score=0.9
        )
        self.assertGreater(score_with_ml, score_without_ml)

    def test_repeated_occurrence_count_impact(self):
        """Verify repeated occurrence count increases risk score"""
        single_occ, _ = self.scorer.calculate_score(
            rule_severity="MEDIUM",
            repeated_occurrence_count=1
        )
        multi_occ, _ = self.scorer.calculate_score(
            rule_severity="MEDIUM",
            repeated_occurrence_count=5
        )
        self.assertGreater(multi_occ, single_occ)

    def test_threat_intelligence_match_impact(self):
        """Verify threat intelligence match increases risk score"""
        no_intel, _ = self.scorer.calculate_score(
            rule_severity="MEDIUM",
            threat_intelligence_match=False
        )
        with_intel, _ = self.scorer.calculate_score(
            rule_severity="MEDIUM",
            threat_intelligence_match=True
        )
        self.assertGreater(with_intel, no_intel)

    def test_asset_criticality_impact(self):
        """Verify asset criticality multipliers apply correctly"""
        low_asset_score, _ = self.scorer.calculate_score(
            rule_severity="HIGH",
            asset_criticality="LOW"
        )
        crit_asset_score, _ = self.scorer.calculate_score(
            rule_severity="HIGH",
            asset_criticality="CRITICAL"
        )
        self.assertGreater(crit_asset_score, low_asset_score)

    def test_clamping_bounds_0_to_100(self):
        """Verify output risk score never exceeds 100 or drops below 0"""
        max_score, _ = self.scorer.calculate_score(
            rule_severity="CRITICAL",
            rule_confidence=100.0,
            ml_anomaly_score=1.0,
            repeated_occurrence_count=100,
            threat_intelligence_match=True,
            asset_criticality="CRITICAL"
        )
        self.assertLessEqual(max_score, 100)
        self.assertGreaterEqual(max_score, 0)

    def test_configurable_custom_scoring_config(self):
        """Verify single-file configurability via ScoringConfig"""
        custom_config = ScoringConfig(
            severity_base_scores={"CUSTOM": 95.0},
            threshold_critical=90
        )
        custom_scorer = RiskScorer(config=custom_config)
        score, sev = custom_scorer.calculate_score(
            rule_severity="CUSTOM",
            rule_confidence=100.0
        )
        self.assertGreaterEqual(score, 90)
        self.assertEqual(sev, "CRITICAL")

    def test_score_alert_dict(self):
        """Verify score_alert dictionary interface"""
        alert_dict = {
            "rule_id": "RL-2001",
            "severity": "HIGH",
            "confidence": 85,
            "repeated_occurrence_count": 3,
            "threat_intelligence_match": True,
            "asset_criticality": "db-cluster-primary",
        }
        scored = self.scorer.score_alert(alert_dict)
        self.assertIn("risk_score", scored)
        self.assertIn("severity", scored)
        self.assertTrue(0 <= scored["risk_score"] <= 100)


if __name__ == "__main__":
    unittest.main()
