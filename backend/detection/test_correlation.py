import unittest
import time
from backend.detection.correlation import IncidentCorrelator, IncidentStatus


class TestCyberOrbitIncidentCorrelation(unittest.TestCase):
    def setUp(self):
        self.correlator = IncidentCorrelator(time_window_seconds=300)

    def test_incident_lifecycle_statuses(self):
        """Verify all required lifecycle states exist in IncidentStatus enum"""
        expected_statuses = {
            "OPEN",
            "ACKNOWLEDGED",
            "INVESTIGATING",
            "CONTAINED",
            "RESOLVED",
            "FALSE_POSITIVE",
        }
        actual_statuses = {s.value for s in IncidentStatus}
        self.assertEqual(expected_statuses, actual_statuses)

    def test_correlation_by_same_source_ip(self):
        """Verify multiple alerts from same source IP correlate into a single incident"""
        alert1 = {
            "rule_id": "RL-2001",
            "rule_name": "High Packet Rate",
            "source_ip": "192.168.1.150",
            "destination_ip": "10.0.0.1",
            "attack_category": "DDoS",
            "severity": "HIGH",
            "risk_score": 65,
            "evidence": "High traffic volume observed",
            "timestamp": "2026-10-03T12:00:00Z",
        }
        alert2 = {
            "rule_id": "RL-2002",
            "rule_name": "Possible SYN Flood",
            "source_ip": "192.168.1.150",
            "destination_ip": "10.0.0.1",
            "attack_category": "DDoS",
            "severity": "CRITICAL",
            "risk_score": 90,
            "evidence": "TCP SYN flood pattern identified",
            "timestamp": "2026-10-03T12:01:00Z",
        }

        incidents = self.correlator.process_alerts([alert1, alert2])
        self.assertEqual(len(incidents), 1)

        inc = incidents[0]
        self.assertEqual(inc["source_ip"], "192.168.1.150")
        self.assertEqual(inc["alert_count"], 2)
        self.assertEqual(set(inc["rule_ids"]), {"RL-2001", "RL-2002"})
        self.assertEqual(inc["severity"], "CRITICAL")
        self.assertEqual(inc["risk_score"], 90)

    def test_correlation_by_same_destination_and_category(self):
        """Verify correlation by same destination IP and attack category"""
        alert1 = {
            "rule_id": "RL-2003",
            "rule_name": "Port Scanning",
            "source_ip": "192.168.1.201",
            "destination_ip": "10.0.0.5",
            "attack_category": "Reconnaissance",
            "severity": "HIGH",
            "timestamp": "2026-10-03T12:00:00Z",
        }
        alert2 = {
            "rule_id": "RL-2005",
            "rule_name": "Suspicious Destination Port",
            "source_ip": "192.168.1.201",
            "destination_ip": "10.0.0.5",
            "attack_category": "Reconnaissance",
            "severity": "HIGH",
            "timestamp": "2026-10-03T12:02:00Z",
        }

        incidents = self.correlator.process_alerts([alert1, alert2])
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["alert_count"], 2)

    def test_related_rule_ids_correlation(self):
        """Verify related rule IDs (e.g. RL-2004 Failed Conns & RL-2006 Repeated Attempts) correlate"""
        self.assertTrue(self.correlator.is_related_rule("RL-2004", "RL-2006"))
        self.assertTrue(self.correlator.is_related_rule("RL-2001", "RL-2002"))

        alert1 = {
            "rule_id": "RL-2004",
            "rule_name": "Repeated Failed Connections",
            "source_ip": "172.16.0.44",
            "destination_ip": "10.0.0.10",
            "timestamp": "2026-10-03T12:00:00Z",
        }
        alert2 = {
            "rule_id": "RL-2006",
            "rule_name": "Repeated Connection Attempts",
            "source_ip": "172.16.0.44",
            "destination_ip": "10.0.0.10",
            "timestamp": "2026-10-03T12:01:00Z",
        }

        incidents = self.correlator.process_alerts([alert1, alert2])
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["alert_count"], 2)

    def test_no_duplicate_incidents_created(self):
        """Verify updating existing incidents rather than creating duplicates for active streams"""
        alerts = [
            {
                "rule_id": "RL-2001",
                "source_ip": "192.168.1.50",
                "destination_ip": "10.0.0.2",
                "timestamp": f"2026-10-03T12:00:0{i}Z",
            }
            for i in range(5)
        ]
        incidents = self.correlator.process_alerts(alerts)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["alert_count"], 5)

    def test_time_window_expiration_creates_new_incident(self):
        """Verify alerts outside the configurable time window create a new incident"""
        correlator_short = IncidentCorrelator(time_window_seconds=10)
        alert1 = {
            "rule_id": "RL-2001",
            "source_ip": "192.168.1.99",
            "destination_ip": "10.0.0.2",
            "timestamp": "2026-10-03T12:00:00Z",
        }
        alert2 = {
            "rule_id": "RL-2001",
            "source_ip": "192.168.1.99",
            "destination_ip": "10.0.0.2",
            "timestamp": "2026-10-03T12:05:00Z",  # 300s later > 10s window
        }

        incidents = correlator_short.process_alerts([alert1, alert2])
        self.assertEqual(len(incidents), 2)

    def test_incidents_are_never_automatically_resolved(self):
        """Verify that incidents remain in active states and are NEVER automatically marked RESOLVED"""
        alert1 = {
            "rule_id": "RL-2001",
            "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.1",
            "timestamp": "2026-10-03T12:00:00Z",
        }
        inc = self.correlator.correlate_alert(alert1)
        self.assertEqual(inc["status"], IncidentStatus.OPEN.value)

        # Process 10 more alerts
        for i in range(10):
            self.correlator.correlate_alert(
                {
                    "rule_id": "RL-2002",
                    "source_ip": "192.168.1.10",
                    "destination_ip": "10.0.0.1",
                    "timestamp": f"2026-10-03T12:00:{i+1:02d}Z",
                }
            )

        self.assertEqual(inc["status"], IncidentStatus.OPEN.value)
        self.assertNotEqual(inc["status"], IncidentStatus.RESOLVED.value)
        self.assertNotEqual(inc["status"], IncidentStatus.FALSE_POSITIVE.value)

    def test_manual_status_transitions(self):
        """Verify manual status update by SOC analyst across lifecycle states"""
        alert = {
            "rule_id": "RL-2001",
            "source_ip": "192.168.1.77",
            "destination_ip": "10.0.0.1",
            "timestamp": "2026-10-03T12:00:00Z",
        }
        inc = self.correlator.correlate_alert(alert)
        inc_id = inc["incident_id"]

        # Analyst acknowledges
        updated = self.correlator.update_incident_status(inc_id, IncidentStatus.ACKNOWLEDGED)
        self.assertEqual(updated["status"], "ACKNOWLEDGED")

        # Analyst moves to investigating
        updated = self.correlator.update_incident_status(inc_id, IncidentStatus.INVESTIGATING)
        self.assertEqual(updated["status"], "INVESTIGATING")

        # Analyst moves to contained
        updated = self.correlator.update_incident_status(inc_id, IncidentStatus.CONTAINED)
        self.assertEqual(updated["status"], "CONTAINED")

        # Analyst marks resolved
        updated = self.correlator.update_incident_status(inc_id, IncidentStatus.RESOLVED)
        self.assertEqual(updated["status"], "RESOLVED")


if __name__ == "__main__":
    unittest.main()
