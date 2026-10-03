import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from backend.collector.suricata_collector import SuricataCollector
from backend.normalizer.normalizer import (
    normalize_suricata_event,
    normalize_zeek_event,
    EventNormalizer,
)
from backend.detection.rules import DetectionRules
from backend.detection.scoring import RiskScorer
from backend.detection.correlation import EventCorrelator
from backend.config.settings import settings

try:
    from supabase import create_client, Client
except ImportError:
    create_client = None
    Client = Any


class DetectionEngine:
    """
    CyberOrbit Core Detection Engine.
    Orchestrates:
    1. Log telemetry ingestion (Suricata, Zeek, raw logs)
    2. Canonical schema normalization (normalize_suricata_event, normalize_zeek_event)
    3. Configurable rule detection evaluation across all 7 core rules (DetectionRules)
    4. Risk scoring (RiskScorer)
    5. Alert correlation (EventCorrelator)
    6. Alert syncing (Supabase alerts table)

    NOTE: Detections produce security alerts ONLY. Does NOT execute automated blocking actions.
    """

    def __init__(self, rules_config: Optional[Dict[str, Any]] = None):
        self.collector = SuricataCollector()
        self.normalizer_legacy = EventNormalizer()
        self.rules_engine = DetectionRules(config_override=rules_config)
        self.scorer = RiskScorer()
        self.correlator = EventCorrelator()
        self.supabase_client: Optional[Client] = None

        if getattr(settings, "SUPABASE_URL", None) and getattr(settings, "SUPABASE_KEY", None) and create_client:
            try:
                self.supabase_client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
                print("[DetectionEngine] Supabase client initialized successfully.")
            except Exception as e:
                print(f"[DetectionEngine Warning] Could not initialize Supabase client: {e}")

    def process_raw_events(self, raw_events: List[Dict[str, Any]], source_type: str = "suricata") -> List[Dict[str, Any]]:
        """
        Ingests a list of raw telemetry JSON events, normalizes them into canonical schema,
        evaluates against 7 detection rules, scores risk, and correlates alerts.
        """
        canonical_events: List[Dict[str, Any]] = []

        for raw in raw_events:
            if source_type.lower() == "zeek":
                norm = normalize_zeek_event(raw)
            else:
                norm = normalize_suricata_event(raw)

            if norm and norm.get("source_ip"):
                canonical_events.append(norm)

        if not canonical_events:
            return []

        # Evaluate against the 7 detection rules
        detection_alerts = self.rules_engine.evaluate_batch_events(canonical_events)

        # Apply risk scoring to each detection alert
        scored_alerts: List[Dict[str, Any]] = []
        for alert in detection_alerts:
            target_asset = EventNormalizer.resolve_asset(
                alert.get("destination_ip", "0.0.0.0"),
                None
            )
            scored = self.scorer.score_alert(alert, asset=target_asset)
            scored_alerts.append(scored)

        # Correlate alerts
        correlated = self.correlator.correlate_alerts(scored_alerts)

        # Sync alerts to Supabase if configured
        if self.supabase_client and correlated:
            self.sync_to_supabase(correlated)

        return correlated

    def process_raw_log_file(self, limit: int = 100) -> List[Dict[str, Any]]:
        """
        Reads recent raw events from Suricata collector and runs full detection pipeline.
        """
        raw_events = self.collector.read_latest_events(limit=limit)
        return self.process_raw_events(raw_events, source_type="suricata")

    def sync_to_supabase(self, alerts: List[Dict[str, Any]]) -> bool:
        """
        Syncs generated security detection alerts into Supabase 'alerts' table.
        Does NOT execute automated blocking actions.
        """
        if not self.supabase_client:
            return False
        try:
            db_records = []
            now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

            for alt in alerts:
                db_records.append({
                    "id": str(uuid.uuid4()),
                    "severity": alt.get("severity", "MEDIUM"),
                    "event": alt.get("rule_name", "CyberOrbit Security Alert"),
                    "ip": alt.get("source_ip", "0.0.0.0"),
                    "asset": EventNormalizer.resolve_asset(alt.get("destination_ip", "0.0.0.0"), None),
                    "timestamp": now_iso,
                    "status": "UNREVIEWED",
                    "confidence": alt.get("confidence", 80),
                    "payload_snippet": alt.get("evidence", ""),
                    "geo_origin": EventNormalizer.resolve_geo(alt.get("source_ip", "0.0.0.0")),
                    "attack_vector": alt.get("rule_id", "RL-GENERIC"),
                })

            self.supabase_client.from_("alerts").upsert(db_records).execute()
            print(f"[DetectionEngine] Synced {len(db_records)} security alerts to Supabase 'alerts' table.")
            return True
        except Exception as err:
            print(f"[DetectionEngine Error] Supabase sync failed: {err}")
            return False


if __name__ == "__main__":
    engine = DetectionEngine()
    alerts = engine.process_raw_log_file(limit=10)
    print(f"Processed {len(alerts)} correlated detection alerts.")

