import os
from dataclasses import dataclass, field
from typing import Dict, Any, Tuple, Optional, Union
from backend.config.settings import settings


@dataclass
class ScoringConfig:
    """
    Configurable parameters for CyberOrbit Risk Scoring Engine.
    All weights, multipliers, and threshold bands are configurable in one place.
    """

    severity_base_scores: Dict[str, float] = field(
        default_factory=lambda: {
            "CRITICAL": 85.0,
            "HIGH": 65.0,
            "MEDIUM": 40.0,
            "LOW": 20.0,
        }
    )

    asset_criticality_multipliers: Dict[str, float] = field(
        default_factory=lambda: {
            "CRITICAL": 1.4,
            "HIGH": 1.2,
            "MEDIUM": 1.0,
            "LOW": 0.8,
            # Common named asset mappings
            "auth-gateway-01": 1.3,
            "db-cluster-primary": 1.4,
            "edge-api-01": 1.1,
            "bastion-ssh-01": 1.25,
            "dns-resolver-04": 1.0,
            "soc-dashboard-web": 1.0,
        }
    )

    ml_anomaly_max_weight: float = 20.0
    occurrence_weight_per_count: float = 5.0
    occurrence_max_boost: float = 25.0
    threat_intel_match_boost: float = 15.0

    # Strictly specified severity band thresholds:
    # 0-24 LOW, 25-49 MEDIUM, 50-74 HIGH, 75-100 CRITICAL
    threshold_critical: int = 75
    threshold_high: int = 50
    threshold_medium: int = 25


class RiskScorer:
    """
    CyberOrbit Risk Scoring Engine.
    Calculates a numerical risk score (0 to 100) based on:
    - Rule severity
    - Rule confidence
    - ML anomaly score
    - Repeated occurrence count
    - Threat intelligence match
    - Asset criticality

    Maps risk score to severity bands:
    0-24   -> LOW
    25-49  -> MEDIUM
    50-74  -> HIGH
    75-100 -> CRITICAL
    """

    def __init__(self, config: Optional[ScoringConfig] = None):
        self.config = config or ScoringConfig()

    def calculate_score(
        self,
        rule_severity: str = "MEDIUM",
        rule_confidence: float = 80.0,
        ml_anomaly_score: Optional[float] = None,
        repeated_occurrence_count: int = 1,
        threat_intelligence_match: Union[bool, float] = False,
        asset_criticality: Union[str, float] = "MEDIUM",
        # Backward compatibility keyword aliases:
        severity: Optional[str] = None,
        confidence: Optional[float] = None,
        asset: Optional[str] = None,
        rule_matches_count: Optional[int] = None,
        threat_intel_match: Optional[bool] = None,
    ) -> Tuple[int, str]:
        """
        Calculates composite risk score (0 to 100) and mapped severity string.
        """
        # Resolve aliases if provided
        actual_severity = (severity or rule_severity or "MEDIUM").upper()
        actual_confidence = float(confidence if confidence is not None else rule_confidence)
        actual_occurrences = rule_matches_count if rule_matches_count is not None else repeated_occurrence_count
        actual_threat_intel = threat_intel_match if threat_intel_match is not None else threat_intelligence_match
        actual_asset = asset if asset is not None else asset_criticality

        # 1. Base Score from Rule Severity
        base_score = self.config.severity_base_scores.get(actual_severity, 30.0)

        # 2. Rule Confidence Factor (0.0 to 1.0)
        conf_factor = max(0.0, min(1.0, actual_confidence / 100.0 if actual_confidence > 1.0 else actual_confidence))

        # Core weighted base
        weighted_base = base_score * conf_factor

        # 3. ML Anomaly Score Boost (when available)
        ml_boost = 0.0
        if ml_anomaly_score is not None and ml_anomaly_score > 0:
            norm_ml = min(1.0, max(0.0, float(ml_anomaly_score)))
            ml_boost = norm_ml * self.config.ml_anomaly_max_weight

        # 4. Repeated Occurrence Count Boost
        occurrence_boost = 0.0
        if actual_occurrences > 1:
            raw_boost = (actual_occurrences - 1) * self.config.occurrence_weight_per_count
            occurrence_boost = min(self.config.occurrence_max_boost, raw_boost)

        # 5. Threat Intelligence Match Boost
        threat_boost = 0.0
        if isinstance(actual_threat_intel, bool):
            if actual_threat_intel:
                threat_boost = self.config.threat_intel_match_boost
        elif isinstance(actual_threat_intel, (int, float)):
            if actual_threat_intel > 0:
                threat_boost = min(1.0, float(actual_threat_intel)) * self.config.threat_intel_match_boost

        # 6. Asset Criticality Multiplier
        if isinstance(actual_asset, (int, float)):
            asset_multiplier = float(actual_asset)
        elif isinstance(actual_asset, str):
            asset_upper = actual_asset.upper()
            if asset_upper in self.config.asset_criticality_multipliers:
                asset_multiplier = self.config.asset_criticality_multipliers[asset_upper]
            elif actual_asset in self.config.asset_criticality_multipliers:
                asset_multiplier = self.config.asset_criticality_multipliers[actual_asset]
            else:
                asset_multiplier = self.config.asset_criticality_multipliers.get("MEDIUM", 1.0)
        else:
            asset_multiplier = 1.0

        # Composite Calculation
        raw_score = (weighted_base + ml_boost + occurrence_boost + threat_boost) * asset_multiplier

        # Output bounded strictly from 0 to 100
        final_risk_score = int(max(0, min(100, round(raw_score))))

        # Map to Severity Bands:
        # 0-24 LOW, 25-49 MEDIUM, 50-74 HIGH, 75-100 CRITICAL
        if final_risk_score >= self.config.threshold_critical:
            mapped_severity = "CRITICAL"
        elif final_risk_score >= self.config.threshold_high:
            mapped_severity = "HIGH"
        elif final_risk_score >= self.config.threshold_medium:
            mapped_severity = "MEDIUM"
        else:
            mapped_severity = "LOW"

        return final_risk_score, mapped_severity

    def score_alert(
        self,
        alert: Dict[str, Any],
        asset: str = "MEDIUM",
        ml_anomaly_score: Optional[float] = None,
        threat_intelligence_match: Union[bool, float] = False,
    ) -> Dict[str, Any]:
        """
        Computes risk score for a detection alert dictionary and returns updated alert.
        """
        sev = alert.get("severity", "MEDIUM")
        conf = float(alert.get("confidence", 80))
        occurrences = int(alert.get("repeated_occurrence_count", alert.get("rule_matches_count", 1)))
        intel_match = alert.get("threat_intelligence_match", alert.get("threat_intel_match", threat_intelligence_match))
        target_asset = alert.get("asset_criticality", alert.get("asset", asset))

        score, mapped_sev = self.calculate_score(
            rule_severity=sev,
            rule_confidence=conf,
            ml_anomaly_score=ml_anomaly_score or alert.get("ml_anomaly_score"),
            repeated_occurrence_count=occurrences,
            threat_intelligence_match=intel_match,
            asset_criticality=target_asset,
        )

        scored_alert = dict(alert)
        scored_alert["risk_score"] = score
        scored_alert["severity"] = mapped_sev
        return scored_alert

    @classmethod
    def calculate(
        cls,
        rule_severity: str = "MEDIUM",
        rule_confidence: float = 80.0,
        ml_anomaly_score: Optional[float] = None,
        repeated_occurrence_count: int = 1,
        threat_intelligence_match: Union[bool, float] = False,
        asset_criticality: Union[str, float] = "MEDIUM",
    ) -> Tuple[int, str]:
        """
        Class method helper using default configuration.
        """
        default_scorer = cls()
        return default_scorer.calculate_score(
            rule_severity=rule_severity,
            rule_confidence=rule_confidence,
            ml_anomaly_score=ml_anomaly_score,
            repeated_occurrence_count=repeated_occurrence_count,
            threat_intelligence_match=threat_intelligence_match,
            asset_criticality=asset_criticality,
        )
