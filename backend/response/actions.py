"""
CyberOrbit Response Manager & Human-in-the-Loop Orchestrator
------------------------------------------------------------
Orchestrates simulated response actions (BLOCK_IP, UNBLOCK_IP, ISOLATE_HOST, MONITOR_HOST),
records response actions, generates audit logs, updates incident statuses, and guarantees
that real OS firewalls are NOT modified by default.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict

from backend.config.settings import settings
from backend.response.firewall import FirewallAdapter, SimulatedFirewallAdapter
from backend.audit.logger import audit_logger

try:
    from supabase import create_client, Client
except ImportError:
    create_client = None
    Client = Any


VALID_SIMULATED_ACTIONS = {"BLOCK_IP", "UNBLOCK_IP", "ISOLATE_HOST", "MONITOR_HOST", "block_ip", "unblock_ip", "isolate_host", "monitor_host"}


@dataclass
class ResponseActionRecord:
    id: str
    requested_by: str
    approved_by: str
    action: str
    target: str
    reason: str
    timestamp: str
    status: str
    command_executed: Optional[str] = None
    incident_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AuditLogRecord:
    id: str
    operator_name: str
    action: str
    entity_type: str
    entity_id: str
    target: str
    details: str
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# Backward compatibility alias
ActionExecutionResult = ResponseActionRecord


class HumanInTheLoopResponseManager:
    """
    Simulated Response Action & Human-in-the-Loop Orchestrator.
    Uses FirewallAdapter abstraction layer (defaults to SimulatedFirewallAdapter).
    """

    def __init__(self, firewall_adapter: Optional[FirewallAdapter] = None):
        self.firewall_adapter: FirewallAdapter = firewall_adapter or SimulatedFirewallAdapter()
        self.supabase_client: Optional[Client] = None
        self.actions_registry: Dict[str, ResponseActionRecord] = {}
        self.audit_logs: List[AuditLogRecord] = []
        self.incident_updates: Dict[str, Dict[str, Any]] = {}

        if getattr(settings, "SUPABASE_URL", None) and getattr(settings, "SUPABASE_KEY", None) and create_client:
            try:
                self.supabase_client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
            except Exception as err:
                print(f"[ResponseManager Warning] Could not initialize Supabase client: {err}")

        self._seed_default_records()

    def _seed_default_records(self):
        """Seed baseline pending and executed response action records."""
        now = datetime.now(timezone.utc).isoformat()
        seeds = [
            ResponseActionRecord(
                id="act-101",
                requested_by="Gemini SOC Copilot",
                approved_by="Pending Analyst Review",
                action="BLOCK_IP",
                target="198.51.100.99",
                reason="Volumetric HTTP/2 flood & SYN surge detected from source IP.",
                timestamp=now,
                status="PENDING",
            ),
            ResponseActionRecord(
                id="act-102",
                requested_by="Gemini SOC Copilot",
                approved_by="Pending Analyst Review",
                action="ISOLATE_HOST",
                target="auth-gateway-01",
                reason="Potential credential stuffing surge & multi-stage brute force.",
                timestamp=now,
                status="PENDING",
            ),
            ResponseActionRecord(
                id="act-103",
                requested_by="Gemini SOC Copilot",
                approved_by="Sarah Chen (SOC Lead)",
                action="MONITOR_HOST",
                target="db-cluster-primary",
                reason="Automated vulnerability scanning payload detected.",
                timestamp=datetime.now(timezone.utc).isoformat(),
                status="APPROVED",
                command_executed="[SIMULATED] tcpdump -i any host db-cluster-primary -w /var/log/cyberorbit/monitor-db-cluster-primary.pcap",
            ),
        ]
        for s in seeds:
            self.actions_registry[s.id] = s

    def set_firewall_adapter(self, adapter: FirewallAdapter):
        """Plugs in a custom or real firewall adapter."""
        self.firewall_adapter = adapter
        print(f"[ResponseManager] Registered firewall adapter: {adapter.adapter_name}")

    def execute_simulated_action(
        self,
        action: str,
        target: str,
        reason: str = "Analyst initiated response action",
        requested_by: str = "Gemini SOC Copilot",
        approved_by: str = "Sarah Chen (SOC Lead)",
        incident_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes a simulated response action (BLOCK_IP, UNBLOCK_IP, ISOLATE_HOST, MONITOR_HOST).
        
        Steps performed:
        1. Invokes firewall abstraction layer (SimulatedFirewallAdapter by default).
        2. Creates response action record with status (SIMULATED or SUCCESS).
        3. Creates audit log entry.
        4. Updates associated incident status (CONTAINED, INVESTIGATING, etc.).
        5. Returns complete payload with simulated results preview.
        """
        action_upper = action.upper().strip().replace(" ", "_")
        if action_upper not in {"BLOCK_IP", "UNBLOCK_IP", "ISOLATE_HOST", "MONITOR_HOST"}:
            action_upper = "BLOCK_IP"

        # 1. Execute action via Firewall Adapter (No real OS firewall modification by default)
        if action_upper == "BLOCK_IP":
            sim_res = self.firewall_adapter.block_ip(target)
        elif action_upper == "UNBLOCK_IP":
            sim_res = self.firewall_adapter.unblock_ip(target)
        elif action_upper == "ISOLATE_HOST":
            sim_res = self.firewall_adapter.isolate_host(target)
        elif action_upper == "MONITOR_HOST":
            sim_res = self.firewall_adapter.monitor_host(target)
        else:
            sim_res = self.firewall_adapter.block_ip(target)

        action_id = f"act-{uuid.uuid4().hex[:8]}"
        timestamp = datetime.now(timezone.utc).isoformat()
        status = sim_res.get("status", "SIMULATED")
        cmd_executed = sim_res.get("command_executed", f"[SIMULATED] execute --action={action_upper} --target={target}")

        # 2. Create Response Action Record
        action_record = ResponseActionRecord(
            id=action_id,
            requested_by=requested_by,
            approved_by=approved_by,
            action=action_upper,
            target=target,
            reason=reason,
            timestamp=timestamp,
            status=status,
            command_executed=cmd_executed,
            incident_id=incident_id,
        )
        self.actions_registry[action_id] = action_record

        # 3. Create Audit Log Record
        audit_entry_record = audit_logger.log_action(
            user=approved_by,
            action="RESPONSE_APPROVED",
            entity=action_id,
            old_value={"status": "PENDING"},
            new_value={"status": status, "target": target, "action": action_upper, "command_executed": cmd_executed},
            timestamp=timestamp,
        )
        audit_entry = AuditLogRecord(
            id=audit_entry_record.id,
            operator_name=approved_by,
            action=f"RESPONSE_ACTION_{action_upper}",
            entity_type="response_action",
            entity_id=action_id,
            target=target,
            details=sim_res.get("details", f"Executed {action_upper} on {target}"),
            timestamp=timestamp,
        )
        self.audit_logs.append(audit_entry)

        # 4. Update Incident Status
        incident_update = None
        if incident_id:
            new_incident_status = "CONTAINED" if action_upper in {"BLOCK_IP", "ISOLATE_HOST"} else "INVESTIGATING" if action_upper == "MONITOR_HOST" else "ACKNOWLEDGED"
            incident_update = {
                "incident_id": incident_id,
                "status": new_incident_status,
                "last_action": action_upper,
                "updated_at": timestamp,
            }
            self.incident_updates[incident_id] = incident_update
            self.sync_incident_to_supabase(incident_id, new_incident_status)

        # 5. Sync Action & Audit to Supabase
        self.sync_action_to_supabase(action_record)
        self.sync_audit_to_supabase(audit_entry)

        result_payload = {
            "response_action": action_record.to_dict(),
            "audit_log": audit_entry.to_dict(),
            "incident_update": incident_update,
            "simulated_result": sim_res,
        }

        print(f"[ResponseManager] Executed simulated action {action_upper} on target {target}. Status: {status}.")
        return result_payload

    def recommend_action(
        self,
        action: str,
        target: str,
        reason: str,
        requested_by: str = "Gemini SOC Copilot",
    ) -> ResponseActionRecord:
        """AI Endpoint to recommend a security action (creates PENDING record only)."""
        action_clean = action.upper().strip().replace(" ", "_")
        if action_clean not in {"BLOCK_IP", "UNBLOCK_IP", "ISOLATE_HOST", "MONITOR_HOST", "INVESTIGATE_HOST", "MONITOR_TRAFFIC"}:
            action_clean = "MONITOR_HOST"

        rec_id = f"act-{uuid.uuid4().hex[:8]}"
        timestamp = datetime.now(timezone.utc).isoformat()

        record = ResponseActionRecord(
            id=rec_id,
            requested_by=requested_by,
            approved_by="Pending Analyst Review",
            action=action_clean,
            target=target,
            reason=reason,
            timestamp=timestamp,
            status="PENDING",
        )

        self.actions_registry[rec_id] = record
        audit_logger.log_action(
            user=requested_by,
            action="RESPONSE_REQUESTED",
            entity=rec_id,
            old_value=None,
            new_value={"status": "PENDING", "target": target, "action": action_clean, "reason": reason},
            timestamp=timestamp,
        )
        self.sync_action_to_supabase(record)
        return record

    def decide_action(
        self,
        action_id: str,
        decision: str,
        approved_by: str = "Sarah Chen (SOC Lead)",
    ) -> ResponseActionRecord:
        """Human Analyst Endpoint to Approve or Reject a recommended security action."""
        record = self.actions_registry.get(action_id)
        if not record:
            raise KeyError(f"Response action record '{action_id}' not found.")

        decision_clean = decision.upper().strip()
        if decision_clean not in {"APPROVED", "REJECTED"}:
            raise ValueError("Decision must be either 'APPROVED' or 'REJECTED'.")

        timestamp = datetime.now(timezone.utc).isoformat()
        record.approved_by = approved_by
        record.timestamp = timestamp

        if decision_clean == "APPROVED":
            # Execute simulated action via firewall adapter
            res = self.execute_simulated_action(
                action=record.action,
                target=record.target,
                reason=record.reason,
                requested_by=record.requested_by,
                approved_by=approved_by,
                incident_id=record.incident_id,
            )
            record.status = res["response_action"]["status"]
            record.command_executed = res["response_action"]["command_executed"]
        else:
            record.status = "REJECTED"
            audit_logger.log_action(
                user=approved_by,
                action="RESPONSE_REJECTED",
                entity=action_id,
                old_value={"status": "PENDING"},
                new_value={"status": "REJECTED", "target": record.target, "action": record.action},
                timestamp=timestamp,
            )

        self.actions_registry[action_id] = record
        self.sync_action_to_supabase(record)
        return record

    def get_pending_actions(self) -> List[ResponseActionRecord]:
        return [r for r in self.actions_registry.values() if r.status == "PENDING"]

    def get_all_actions(self) -> List[ResponseActionRecord]:
        return sorted(self.actions_registry.values(), key=lambda r: r.timestamp, reverse=True)

    def get_audit_logs(self) -> List[AuditLogRecord]:
        return sorted(self.audit_logs, key=lambda a: a.timestamp, reverse=True)

    def sync_action_to_supabase(self, record: ResponseActionRecord) -> bool:
        if not self.supabase_client:
            return False
        try:
            db_data = {
                "id": record.id if len(record.id) == 36 else None,
                "requested_by": record.requested_by,
                "approved_by": record.approved_by,
                "action": record.action,
                "target": record.target,
                "reason": record.reason,
                "timestamp": record.timestamp,
                "status": record.status,
                "command_executed": record.command_executed,
            }
            db_data = {k: v for k, v in db_data.items() if v is not None}
            self.supabase_client.from_("response_actions").upsert(db_data).execute()
            return True
        except Exception as err:
            print(f"[ResponseManager Error] Supabase action sync failed: {err}")
            return False

    def sync_audit_to_supabase(self, audit: AuditLogRecord) -> bool:
        if not self.supabase_client:
            return False
        try:
            db_data = {
                "id": audit.id if len(audit.id) == 36 else None,
                "operator_name": audit.operator_name,
                "action": audit.action,
                "entity_type": audit.entity_type,
                "entity_id": audit.entity_id,
                "details": {"target": audit.target, "log": audit.details},
                "created_at": audit.timestamp,
            }
            db_data = {k: v for k, v in db_data.items() if v is not None}
            self.supabase_client.from_("audit_logs").upsert(db_data).execute()
            return True
        except Exception as err:
            print(f"[ResponseManager Error] Supabase audit sync failed: {err}")
            return False

    def sync_incident_to_supabase(self, incident_id: str, status: str) -> bool:
        if not self.supabase_client:
            return False
        try:
            self.supabase_client.from_("incidents").update({"status": status, "updated_at": datetime.now(timezone.utc).isoformat()}).eq("id", incident_id).execute()
            return True
        except Exception as err:
            print(f"[ResponseManager Error] Supabase incident update failed: {err}")
            return False


# Backward compatibility alias
ResponseManager = HumanInTheLoopResponseManager
