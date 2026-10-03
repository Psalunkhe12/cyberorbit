"""
Unit Tests for CyberOrbit Human-in-the-Loop Response Workflow
--------------------------------------------------------------
Verifies that AI recommendations remain PENDING (no direct execution),
and that human analyst decisions (Approve/Reject) correctly record:
- requested_by
- approved_by
- action
- target
- reason
- timestamp
- status
"""

import unittest
from backend.response.actions import HumanInTheLoopResponseManager, ResponseActionRecord


class TestHumanInTheLoopResponseWorkflow(unittest.TestCase):

    def setUp(self):
        self.manager = HumanInTheLoopResponseManager()

    def test_ai_cannot_directly_execute_actions(self):
        """Verify AI recommendations are strictly created as PENDING without executing."""
        rec = self.manager.recommend_action(
            action="block_ip",
            target="198.51.100.42",
            reason="High risk score and SQL injection attempt.",
            requested_by="Gemini SOC Copilot"
        )

        self.assertEqual(rec.requested_by, "Gemini SOC Copilot")
        self.assertEqual(rec.approved_by, "Pending Analyst Review")
        self.assertEqual(rec.action.lower(), "block_ip")
        self.assertEqual(rec.target, "198.51.100.42")
        self.assertEqual(rec.status, "PENDING")
        self.assertIsNone(rec.command_executed)

    def test_human_analyst_approve_decision(self):
        """Verify human analyst approving a recommendation records decision details and status."""
        rec = self.manager.recommend_action(
            action="isolate_host",
            target="auth-gateway-01",
            reason="Multi-stage attack campaign detected.",
            requested_by="Gemini SOC Copilot"
        )

        approved = self.manager.decide_action(
            action_id=rec.id,
            decision="APPROVED",
            approved_by="Sarah Chen (SOC Lead)"
        )

        self.assertEqual(approved.id, rec.id)
        self.assertEqual(approved.requested_by, "Gemini SOC Copilot")
        self.assertEqual(approved.approved_by, "Sarah Chen (SOC Lead)")
        self.assertEqual(approved.action.lower(), "isolate_host")
        self.assertEqual(approved.target, "auth-gateway-01")
        self.assertEqual(approved.status, "SIMULATED")
        self.assertIsNotNone(approved.command_executed)

    def test_human_analyst_reject_decision(self):
        """Verify human analyst rejecting a recommendation records decision status as REJECTED."""
        rec = self.manager.recommend_action(
            action="monitor_traffic",
            target="dns-server-02",
            reason="Anomalous UDP traffic spike.",
            requested_by="Gemini SOC Copilot"
        )

        rejected = self.manager.decide_action(
            action_id=rec.id,
            decision="REJECTED",
            approved_by="Alex Mercer (Senior Threat Hunter)"
        )

        self.assertEqual(rejected.status, "REJECTED")
        self.assertEqual(rejected.approved_by, "Alex Mercer (Senior Threat Hunter)")
        self.assertIsNone(rejected.command_executed)

    def test_supported_action_types(self):
        """Verify support for block_ip, investigate_host, monitor_traffic, isolate_host."""
        for act in ["block_ip", "investigate_host", "monitor_traffic", "isolate_host"]:
            rec = self.manager.recommend_action(
                action=act,
                target="test-target",
                reason=f"Testing {act}",
                requested_by="Gemini SOC Copilot"
            )
            self.assertEqual(rec.action.lower(), act.lower())
            self.assertEqual(rec.status, "PENDING")


if __name__ == "__main__":
    unittest.main()
