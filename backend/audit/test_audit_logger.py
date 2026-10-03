"""
Unit Tests for CyberOrbit Audit Logger Engine
---------------------------------------------
Verifies audit logging for all 11 required action types:
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

Verifies storing: user, action, entity, old_value, new_value, timestamp.
"""

import unittest
from backend.audit.logger import AuditLogger, AuditLogRecord, VALID_AUDIT_ACTIONS


class TestAuditLoggerEngine(unittest.TestCase):

    def setUp(self):
        self.logger = AuditLogger()

    def test_all_11_audit_actions_logged(self):
        """Verify all 11 action types log successfully with user, action, entity, old_value, new_value, timestamp."""
        test_actions = [
            ("LOGIN", "session-01", None, {"status": "SUCCESS"}),
            ("ALERT_ACKNOWLEDGED", "alert-101", {"status": "UNREVIEWED"}, {"status": "ACKNOWLEDGED"}),
            ("INCIDENT_CREATED", "inc-5001", None, {"title": "SYN Surge", "status": "OPEN"}),
            ("INCIDENT_UPDATED", "inc-5001", {"status": "OPEN"}, {"status": "INVESTIGATING"}),
            ("INCIDENT_RESOLVED", "inc-5001", {"status": "INVESTIGATING"}, {"status": "RESOLVED"}),
            ("RULE_CREATED", "RL-1005", None, {"name": "XSS Filter", "action": "BLOCK"}),
            ("RULE_UPDATED", "RL-1005", {"status": "ACTIVE"}, {"status": "PAUSED"}),
            ("AI_ANALYSIS_GENERATED", "alert-101", None, {"confidence": 0.95, "attack": "SQLi"}),
            ("RESPONSE_REQUESTED", "act-101", None, {"action": "BLOCK_IP", "target": "198.51.100.99"}),
            ("RESPONSE_APPROVED", "act-101", {"status": "PENDING"}, {"status": "APPROVED"}),
            ("RESPONSE_REJECTED", "act-102", {"status": "PENDING"}, {"status": "REJECTED"}),
        ]

        for act, entity, old_val, new_val in test_actions:
            rec = self.logger.log_action(
                user="sarah.chen@cyberorbit.sec",
                action=act,
                entity=entity,
                old_value=old_val,
                new_value=new_val,
            )

            self.assertEqual(rec.user, "sarah.chen@cyberorbit.sec")
            self.assertEqual(rec.action, act)
            self.assertEqual(rec.entity, entity)
            self.assertEqual(rec.old_value, old_val)
            self.assertEqual(rec.new_value, new_val)
            self.assertIsNotNone(rec.timestamp)

    def test_invalid_action_raises_value_error(self):
        """Verify invalid action type raises ValueError."""
        with self.assertRaises(ValueError):
            self.logger.log_action(
                user="test@sec.com",
                action="INVALID_ACTION_NAME",
                entity="test-entity"
            )

    def test_get_audit_logs_filter(self):
        """Verify filtering audit logs by action type."""
        self.logger.log_action(user="admin@sec.com", action="LOGIN", entity="session-99")
        logs = self.logger.get_audit_logs(action_filter="LOGIN")
        self.assertTrue(all(l.action == "LOGIN" for l in logs))


if __name__ == "__main__":
    unittest.main()
