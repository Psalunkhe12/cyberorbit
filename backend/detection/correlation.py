import os
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set, Union
from enum import Enum
from collections import defaultdict


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


ACTIVE_INCIDENT_STATUSES: Set[str] = {
    IncidentStatus.OPEN.value,
    IncidentStatus.ACKNOWLEDGED.value,
    IncidentStatus.INVESTIGATING.value,
    IncidentStatus.CONTAINED.value,
}

CLOSED_INCIDENT_STATUSES: Set[str] = {
    IncidentStatus.RESOLVED.value,
    IncidentStatus.FALSE_POSITIVE.value,
}

DEFAULT_RELATED_RULE_GROUPS: List[Set[str]] = [
    {"RL-2001", "RL-2002"},  # High Packet Rate & SYN Flood (DDoS)
    {"RL-2003", "RL-2005"},  # Port Scanning & Suspicious Port (Reconnaissance)
    {"RL-2004", "RL-2006"},  # Failed Connections & Repeated Attempts (Brute Force)
    {"RL-2007", "RL-2005"},  # Abnormal Outbound Traffic & Suspicious Port (Exfiltration/C2)
]


class IncidentCorrelator:
    """
    CyberOrbit Incident Correlation Engine.
    Groups related security alerts into composite Incidents based on:
    - Same source IP
    - Same destination
    - Same attack category
    - Configurable time window
    - Related rule IDs

    Updates existing open incidents rather than creating duplicates.
    Enforces Incident Lifecycle:
    [OPEN, ACKNOWLEDGED, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE]

    NOTE: Does NOT automatically mark incidents resolved.
    """

    def __init__(
        self,
        time_window_seconds: Optional[int] = None,
        related_rule_groups: Optional[List[Set[str]]] = None,
    ):
        env_window = os.getenv("INCIDENT_CORRELATION_WINDOW_SECONDS", "300")
        self.time_window_seconds = (
            time_window_seconds
            if time_window_seconds is not None
            else int(env_window)
        )
        self.related_rule_groups = (
            related_rule_groups
            if related_rule_groups is not None
            else DEFAULT_RELATED_RULE_GROUPS
        )
        self.incidents: Dict[str, Dict[str, Any]] = {}

    def _parse_timestamp(self, ts_val: Any) -> float:
        """Helper to convert string ISO timestamp or float epoch to epoch seconds float."""
        if isinstance(ts_val, (int, float)):
            return float(ts_val)
        if isinstance(ts_val, str):
            try:
                # Handle ISO 8601 string
                clean_ts = ts_val.replace("Z", "+00:00")
                dt = datetime.fromisoformat(clean_ts)
                return dt.timestamp()
            except Exception:
                pass
        return datetime.now(timezone.utc).timestamp()

    def is_related_rule(self, rule_a: str, rule_b: str) -> bool:
        """Checks if two rule IDs belong to a known related rule group."""
        if rule_a == rule_b:
            return True
        for group in self.related_rule_groups:
            if rule_a in group and rule_b in group:
                return True
        return False

    def matches_incident(
        self, alert: Dict[str, Any], incident: Dict[str, Any]
    ) -> bool:
        """
        Evaluates whether an incoming alert correlates with an existing incident based on:
        1. Active incident status (OPEN, ACKNOWLEDGED, INVESTIGATING, CONTAINED)
        2. Configurable time window
        3. Same source IP, destination IP, attack category, or related rule IDs.
        """
        # 1. Status Check: Do not correlate into CLOSED/RESOLVED/FALSE_POSITIVE incidents
        inc_status = str(incident.get("status", IncidentStatus.OPEN.value)).upper()
        if inc_status in CLOSED_INCIDENT_STATUSES:
            return False

        # 2. Time Window Check
        alert_ts = self._parse_timestamp(alert.get("timestamp"))
        inc_updated_ts = self._parse_timestamp(incident.get("updated_at"))
        if abs(alert_ts - inc_updated_ts) > self.time_window_seconds:
            return False

        # Extract telemetry parameters
        alert_src_ip = alert.get("source_ip") or alert.get("ip")
        inc_src_ip = incident.get("source_ip")

        alert_dest_ip = alert.get("destination_ip") or alert.get("dest_ip")
        inc_dest_ip = incident.get("destination_ip")

        alert_category = (
            alert.get("attack_category")
            or alert.get("attackVector")
            or alert.get("rule_name")
        )
        inc_category = incident.get("attack_category")

        alert_rule_id = alert.get("rule_id", "")
        inc_rule_ids = set(incident.get("rule_ids", []))

        # 3. Factor Matching
        same_src_ip = bool(
            alert_src_ip and inc_src_ip and alert_src_ip == inc_src_ip
        )
        same_dest_ip = bool(
            alert_dest_ip and inc_dest_ip and alert_dest_ip == inc_dest_ip
        )
        same_category = bool(
            alert_category
            and inc_category
            and str(alert_category).lower() == str(inc_category).lower()
        )
        related_rule = any(
            self.is_related_rule(alert_rule_id, rid) for rid in inc_rule_ids
        )

        # Correlation Trigger: Same source IP with matching dest, category, or related rule
        if same_src_ip and (same_dest_ip or same_category or related_rule):
            return True

        # Secondary Trigger: Same destination IP with related rule ID or same category
        if same_dest_ip and (related_rule or same_category):
            return True

        return False

    def correlate_alert(self, alert: Dict[str, Any]) -> Dict[str, Any]:
        """
        Correlates a single alert into an existing active incident or creates a new incident.
        Updates existing incidents rather than creating duplicate incidents.
        """
        now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        # Check for existing matching active incident
        for inc_id, incident in list(self.incidents.items()):
            if self.matches_incident(alert, incident):
                # Update existing incident
                alert_rule_id = alert.get("rule_id", "RL-GENERIC")
                if alert_rule_id not in incident["rule_ids"]:
                    incident["rule_ids"].append(alert_rule_id)

                incident["alert_count"] += 1
                incident["alerts"].append(alert)
                incident["updated_at"] = alert.get("timestamp") or now_iso

                # Update composite severity and risk score if incoming alert is higher
                alert_sev = str(alert.get("severity", "LOW")).upper()
                if self._sev_rank(alert_sev) > self._sev_rank(incident["severity"]):
                    incident["severity"] = alert_sev

                alert_score = alert.get("risk_score", 0)
                if alert_score > incident["risk_score"]:
                    incident["risk_score"] = alert_score

                # Append new evidence snippet
                ev_snippet = alert.get("evidence") or alert.get("payloadSnippet", "")
                if ev_snippet and ev_snippet not in incident["evidence_summary"]:
                    incident["evidence_summary"] += f" | {ev_snippet}"

                # NOTE: Preserve current status (e.g. OPEN, ACKNOWLEDGED, INVESTIGATING, CONTAINED)
                # DO NOT automatically mark incident as RESOLVED or FALSE_POSITIVE
                return incident

        # No matching active incident found -> Create new incident
        new_inc_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        src_ip = str(alert.get("source_ip") or alert.get("ip") or "0.0.0.0")
        dest_ip = str(
            alert.get("destination_ip") or alert.get("dest_ip") or "0.0.0.0"
        )
        rule_id = str(alert.get("rule_id", "RL-GENERIC"))
        category = str(
            alert.get("attack_category")
            or alert.get("attackVector")
            or alert.get("rule_name")
            or "Security Intrusion"
        )
        title = alert.get("rule_name") or f"Security Incident from {src_ip}"
        evidence = alert.get("evidence") or alert.get("payloadSnippet", "")

        new_incident = {
            "incident_id": new_inc_id,
            "title": title,
            "status": IncidentStatus.OPEN.value,  # New incidents start OPEN
            "severity": str(alert.get("severity", "MEDIUM")).upper(),
            "risk_score": int(alert.get("risk_score", 50)),
            "source_ip": src_ip,
            "destination_ip": dest_ip,
            "attack_category": category,
            "rule_ids": [rule_id],
            "alert_count": 1,
            "alerts": [alert],
            "created_at": alert.get("timestamp") or now_iso,
            "updated_at": alert.get("timestamp") or now_iso,
            "evidence_summary": str(evidence),
        }

        self.incidents[new_inc_id] = new_incident
        return new_incident

    def process_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Processes a list/stream of alerts, updating existing incidents or creating new ones.
        Returns list of all active correlated incidents.
        """
        for alert in alerts:
            self.correlate_alert(alert)
        return list(self.incidents.values())

    def update_incident_status(
        self, incident_id: str, new_status: Union[str, IncidentStatus]
    ) -> Optional[Dict[str, Any]]:
        """
        Manual SOC Analyst lifecycle status transition helper.
        Valid statuses: [OPEN, ACKNOWLEDGED, INVESTIGATING, CONTAINED, RESOLVED, FALSE_POSITIVE]
        """
        if incident_id not in self.incidents:
            return None

        status_str = (
            new_status.value if isinstance(new_status, IncidentStatus) else str(new_status).upper()
        )
        if status_str not in IncidentStatus.__members__:
            raise ValueError(
                f"Invalid incident status '{new_status}'. Must be one of {[s.value for s in IncidentStatus]}"
            )

        self.incidents[incident_id]["status"] = status_str
        self.incidents[incident_id]["updated_at"] = (
            datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        )
        return self.incidents[incident_id]

    @staticmethod
    def _sev_rank(sev: str) -> int:
        ranks = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        return ranks.get(str(sev).upper(), 0)


class EventCorrelator:
    """
    Wrapper for CyberOrbit Event/Incident Correlator.
    Maintains backward compatibility while delegating correlation to IncidentCorrelator.
    """

    def __init__(self, time_window_seconds: int = 300):
        self.incident_correlator = IncidentCorrelator(
            time_window_seconds=time_window_seconds
        )

    def correlate_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return self.incident_correlator.process_alerts(alerts)

    def correlate_events(self, events: List[Any]) -> List[Any]:
        if not events:
            return []
        if isinstance(events[0], dict):
            return self.correlate_alerts(events)

        # Legacy object fallback
        return events
