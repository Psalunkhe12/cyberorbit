"""
CyberOrbit Audit Logger Engine
------------------------------
Logs security-critical actions and state transitions for compliance and SOC forensics.

Supported Audit Actions:
- LOGIN
- ALERT_ACKNOWLEDGED
- INCIDENT_CREATED
- INCIDENT_UPDATED
- INCIDENT_RESOLVED
- RULE_CREATED
- RULE_UPDATED
- AI_ANALYSIS_GENERATED
- RESPONSE_REQUESTED
- RESPONSE_APPROVED
- RESPONSE_REJECTED

Required Fields Stored:
- user (operator email or name)
- action (action name)
- entity (target ID or entity name)
- old_value (previous state / JSON payload)
- new_value (updated state / JSON payload)
- timestamp (ISO 8601 string)
"""

import uuid
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from backend.config.settings import settings

try:
    from supabase import create_client, Client
except ImportError:
    create_client = None
    Client = Any


VALID_AUDIT_ACTIONS = {
    "LOGIN",
    "ALERT_ACKNOWLEDGED",
    "INCIDENT_CREATED",
    "INCIDENT_UPDATED",
    "INCIDENT_RESOLVED",
    "RULE_CREATED",
    "RULE_UPDATED",
    "AI_ANALYSIS_GENERATED",
    "RESPONSE_REQUESTED",
    "RESPONSE_APPROVED",
    "RESPONSE_REJECTED",
}


@dataclass
class AuditLogRecord:
    id: str
    user: str
    action: str
    entity: str
    old_value: Optional[Any]
    new_value: Optional[Any]
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AuditLogger:
    """
    Central Audit Logging Engine for CyberOrbit.
    """

    def __init__(self):
        self.supabase_client: Optional[Client] = None
        self.logs_registry: List[AuditLogRecord] = []

        if getattr(settings, "SUPABASE_URL", None) and getattr(settings, "SUPABASE_KEY", None) and create_client:
            try:
                self.supabase_client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
            except Exception as err:
                print(f"[AuditLogger Warning] Supabase client initialization failed: {err}")

        self._seed_default_audit_logs()

    def _seed_default_audit_logs(self):
        """Seed baseline audit log records for demonstration."""
        now = datetime.now(timezone.utc).isoformat()
        seeds = [
            AuditLogRecord(
                id="audit-101",
                user="admin@cyberorbit.sec",
                action="LOGIN",
                entity="session-admin-01",
                old_value=None,
                new_value={"status": "AUTHENTICATED", "role": "ADMIN"},
                timestamp=now,
            ),
            AuditLogRecord(
                id="audit-102",
                user="sarah.chen@cyberorbit.sec",
                action="RESPONSE_APPROVED",
                entity="act-101",
                old_value={"status": "PENDING"},
                new_value={"status": "APPROVED", "action": "BLOCK_IP", "target": "198.51.100.99"},
                timestamp=now,
            ),
        ]
        self.logs_registry.extend(seeds)

    def log_action(
        self,
        user: str,
        action: str,
        entity: str,
        old_value: Optional[Any] = None,
        new_value: Optional[Any] = None,
        timestamp: Optional[str] = None,
    ) -> AuditLogRecord:
        """
        Records a structured audit log entry.
        
        Args:
            user: Operator email or name.
            action: Action string (must be one of 11 supported types).
            entity: Entity ID or descriptor (e.g. alert-101, rule-1001).
            old_value: Previous state dictionary or string (optional).
            new_value: New state dictionary or string (optional).
            timestamp: ISO datetime string (defaults to current UTC time).
        """
        action_clean = action.upper().strip()
        if action_clean not in VALID_AUDIT_ACTIONS:
            raise ValueError(f"Invalid audit action '{action}'. Must be one of: {sorted(list(VALID_AUDIT_ACTIONS))}")

        log_id = f"audit-{uuid.uuid4().hex[:8]}"
        ts = timestamp or datetime.now(timezone.utc).isoformat()

        record = AuditLogRecord(
            id=log_id,
            user=user or "SYSTEM",
            action=action_clean,
            entity=entity,
            old_value=old_value,
            new_value=new_value,
            timestamp=ts,
        )

        self.logs_registry.insert(0, record)
        self.sync_to_supabase(record)

        print(f"[AuditLogger] Recorded '{action_clean}' by '{user}' on entity '{entity}'.")
        return record

    def get_audit_logs(self, action_filter: Optional[str] = None) -> List[AuditLogRecord]:
        """Returns sorted list of audit log records."""
        if action_filter:
            act_clean = action_filter.upper().strip()
            return [l for l in self.logs_registry if l.action == act_clean]
        return sorted(self.logs_registry, key=lambda l: l.timestamp, reverse=True)

    def sync_to_supabase(self, record: AuditLogRecord) -> bool:
        """Syncs audit log record to Supabase audit_logs table."""
        if not self.supabase_client:
            return False

        try:
            db_data = {
                "id": record.id if len(record.id) == 36 else None,
                "user": record.user,
                "action": record.action,
                "entity": record.entity,
                "old_value": json.dumps(record.old_value) if isinstance(record.old_value, (dict, list)) else record.old_value,
                "new_value": json.dumps(record.new_value) if isinstance(record.new_value, (dict, list)) else record.new_value,
                "timestamp": record.timestamp,
            }
            db_data = {k: v for k, v in db_data.items() if v is not None}
            self.supabase_client.from_("audit_logs").upsert(db_data).execute()
            return True
        except Exception as err:
            print(f"[AuditLogger Error] Supabase sync failed: {err}")
            return False


# Singleton instance
audit_logger = AuditLogger()
