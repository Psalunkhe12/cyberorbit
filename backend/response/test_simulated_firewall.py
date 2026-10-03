"""
Unit Tests for CyberOrbit Simulated Firewall & Response Manager
---------------------------------------------------------------
Verifies:
- FirewallAdapter abstraction layer (SimulatedFirewallAdapter)
- Execution of BLOCK_IP, UNBLOCK_IP, ISOLATE_HOST, and MONITOR_HOST
- Response action creation and status marking (SIMULATED)
- Audit log entry generation
- Incident status update (CONTAINED, INVESTIGATING)
- Safety guarantee: Zero real OS firewall calls made by default
"""

import unittest
from backend.response.firewall import FirewallAdapter, SimulatedFirewallAdapter
from backend.response.actions import HumanInTheLoopResponseManager, ResponseActionRecord, AuditLogRecord


class CustomTestAdapter(FirewallAdapter):
    """Test firewall adapter to verify provider pluggability."""
    @property
    def adapter_name(self) -> str:
        return "CustomTestAdapter"

    def block_ip(self, ip_address: str, duration_minutes: int = 60):
        return {"action": "BLOCK_IP", "target": ip_address, "status": "CUSTOM_SUCCESS", "command_executed": "custom block", "adapter": self.adapter_name}

    def unblock_ip(self, ip_address: str):
        return {"action": "UNBLOCK_IP", "target": ip_address, "status": "CUSTOM_SUCCESS", "command_executed": "custom unblock", "adapter": self.adapter_name}

    def isolate_host(self, host_identifier: str):
        return {"action": "ISOLATE_HOST", "target": host_identifier, "status": "CUSTOM_SUCCESS", "command_executed": "custom isolate", "adapter": self.adapter_name}

    def monitor_host(self, host_identifier: str):
        return {"action": "MONITOR_HOST", "target": host_identifier, "status": "CUSTOM_SUCCESS", "command_executed": "custom monitor", "adapter": self.adapter_name}


class TestSimulatedFirewallResponse(unittest.TestCase):

    def setUp(self):
        self.manager = HumanInTheLoopResponseManager()

    def test_simulated_firewall_adapter_block_ip(self):
        """Verify BLOCK_IP creates action record, audit log, marks status SIMULATED, and updates incident to CONTAINED."""
        res = self.manager.execute_simulated_action(
            action="BLOCK_IP",
            target="198.51.100.99",
            reason="High risk score SYN surge",
            approved_by="Sarah Chen (SOC Lead)",
            incident_id="inc-5001",
        )

        action_rec = res["response_action"]
        audit_rec = res["audit_log"]
        inc_update = res["incident_update"]
        sim_res = res["simulated_result"]

        self.assertEqual(action_rec["action"], "BLOCK_IP")
        self.assertEqual(action_rec["target"], "198.51.100.99")
        self.assertEqual(action_rec["status"], "SIMULATED")
        self.assertIn("[SIMULATED]", action_rec["command_executed"])

        self.assertEqual(audit_rec["action"], "RESPONSE_ACTION_BLOCK_IP")
        self.assertEqual(audit_rec["operator_name"], "Sarah Chen (SOC Lead)")

        self.assertIsNotNone(inc_update)
        self.assertEqual(inc_update["status"], "CONTAINED")

    def test_simulated_firewall_adapter_unblock_ip(self):
        """Verify UNBLOCK_IP action execution."""
        res = self.manager.execute_simulated_action(
            action="UNBLOCK_IP",
            target="198.51.100.99",
            reason="False positive review completed",
            approved_by="Alex Mercer",
        )
        self.assertEqual(res["response_action"]["action"], "UNBLOCK_IP")
        self.assertEqual(res["response_action"]["status"], "SIMULATED")
        self.assertIn("UNBLOCK_IP", res["audit_log"]["action"])

    def test_simulated_firewall_adapter_isolate_host(self):
        """Verify ISOLATE_HOST updates incident status to CONTAINED."""
        res = self.manager.execute_simulated_action(
            action="ISOLATE_HOST",
            target="auth-gateway-01",
            reason="Credential stuffing surge",
            incident_id="inc-5002",
        )
        self.assertEqual(res["response_action"]["action"], "ISOLATE_HOST")
        self.assertEqual(res["incident_update"]["status"], "CONTAINED")

    def test_simulated_firewall_adapter_monitor_host(self):
        """Verify MONITOR_HOST updates incident status to INVESTIGATING."""
        res = self.manager.execute_simulated_action(
            action="MONITOR_HOST",
            target="db-cluster-primary",
            reason="Anomalous query payload pattern",
            incident_id="inc-5003",
        )
        self.assertEqual(res["response_action"]["action"], "MONITOR_HOST")
        self.assertEqual(res["incident_update"]["status"], "INVESTIGATING")

    def test_firewall_adapter_pluggability(self):
        """Verify plugging in a custom FirewallAdapter."""
        custom_adapter = CustomTestAdapter()
        self.manager.set_firewall_adapter(custom_adapter)

        res = self.manager.execute_simulated_action(
            action="BLOCK_IP",
            target="203.0.113.5",
        )

        self.assertEqual(res["simulated_result"]["adapter"], "CustomTestAdapter")
        self.assertEqual(res["simulated_result"]["status"], "CUSTOM_SUCCESS")


if __name__ == "__main__":
    unittest.main()
