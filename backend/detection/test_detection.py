import unittest
from backend.detection.rules import DetectionRules, DetectionAlert
from backend.detection.scoring import RiskScorer
from backend.detection.correlation import EventCorrelator
from backend.detection.engine import DetectionEngine


class TestDetectionRules(unittest.TestCase):
    def setUp(self):
        self.rules = DetectionRules()

    def test_rule_1_high_packet_rate(self):
        event = {
            "source_ip": "192.168.1.50",
            "destination_ip": "10.0.0.5",
            "packets_in": 300,
            "packets_out": 250,
        }
        alert = self.rules.detect_high_packet_rate(event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.rule_id, "RL-2001")
        self.assertEqual(alert.rule_name, "High Packet Rate")
        self.assertEqual(alert.severity, "HIGH")

    def test_rule_2_syn_flood(self):
        event = {
            "source_ip": "172.16.0.4",
            "destination_ip": "10.0.0.1",
            "protocol": "TCP",
            "raw_event": {"tcp": {"syn": 60, "tcp_flags": "syn"}},
        }
        alert = self.rules.detect_syn_flood(event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.rule_id, "RL-2002")
        self.assertEqual(alert.rule_name, "Possible SYN Flood")
        self.assertEqual(alert.severity, "CRITICAL")

    def test_rule_3_port_scanning(self):
        batch = [
            {"source_ip": "192.168.1.99", "destination_ip": "10.0.0.1", "destination_port": port}
            for port in [21, 22, 80, 443, 3389, 8080]
        ]
        alerts = self.rules.evaluate_batch_events(batch)
        port_scan_alerts = [a for a in alerts if a["rule_id"] == "RL-2003"]
        self.assertGreaterEqual(len(port_scan_alerts), 1)
        self.assertEqual(port_scan_alerts[0]["rule_name"], "Port Scanning")
        self.assertEqual(port_scan_alerts[0]["source_ip"], "192.168.1.99")

    def test_rule_4_repeated_failed_connections(self):
        batch = [
            {
                "source_ip": "192.168.1.88",
                "destination_ip": "10.0.0.2",
                "application": "401 Unauthorized",
                "raw_event": "login failed reset",
            }
            for _ in range(6)
        ]
        alerts = self.rules.evaluate_batch_events(batch)
        failed_alerts = [a for a in alerts if a["rule_id"] == "RL-2004"]
        self.assertGreaterEqual(len(failed_alerts), 1)
        self.assertEqual(failed_alerts[0]["rule_name"], "Repeated Failed Connections")

    def test_rule_5_suspicious_destination_port(self):
        event = {
            "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.20",
            "destination_port": 4444,
        }
        alert = self.rules.detect_suspicious_destination_port(event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.rule_id, "RL-2005")
        self.assertEqual(alert.rule_name, "Suspicious Destination Port")

    def test_rule_6_repeated_connection_attempts(self):
        batch = [
            {"source_ip": "192.168.1.44", "destination_ip": "10.0.0.30", "destination_port": 80}
            for _ in range(12)
        ]
        alerts = self.rules.evaluate_batch_events(batch)
        repeat_alerts = [a for a in alerts if a["rule_id"] == "RL-2006"]
        self.assertGreaterEqual(len(repeat_alerts), 1)
        self.assertEqual(repeat_alerts[0]["rule_name"], "Repeated Connection Attempts")

    def test_rule_7_abnormal_outbound_traffic(self):
        event = {
            "source_ip": "10.0.0.15",
            "destination_ip": "198.51.100.4",
            "bytes_out": 250000,
        }
        alert = self.rules.detect_abnormal_outbound_traffic(event)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.rule_id, "RL-2007")
        self.assertEqual(alert.rule_name, "Abnormal Outbound Traffic")

    def test_alert_dictionary_schema(self):
        event = {
            "source_ip": "192.168.1.50",
            "destination_ip": "10.0.0.5",
            "packets_in": 600,
            "packets_out": 0,
        }
        alert = self.rules.detect_high_packet_rate(event)
        alert_dict = alert.to_dict()
        required_keys = {
            "rule_id",
            "rule_name",
            "severity",
            "confidence",
            "source_ip",
            "destination_ip",
            "evidence",
        }
        self.assertTrue(required_keys.issubset(set(alert_dict.keys())))

    def test_configurable_thresholds(self):
        custom_rules = DetectionRules(config_override={"high_packet_rate_threshold": 100})
        event = {
            "source_ip": "192.168.1.1",
            "destination_ip": "10.0.0.1",
            "packets_in": 150,
        }
        alert = custom_rules.detect_high_packet_rate(event)
        self.assertIsNotNone(alert)


class TestDetectionEngine(unittest.TestCase):
    def setUp(self):
        self.engine = DetectionEngine()

    def test_full_detection_pipeline(self):
        raw_events = [
            {
                "timestamp": "2026-10-03T12:00:00Z",
                "src_ip": "192.168.1.105",
                "dest_ip": "10.0.0.2",
                "dest_port": 4444,
                "proto": "TCP",
                "flow": {"pkts_toserver": 600, "bytes_toserver": 150000},
            },
            {
                "timestamp": "2026-10-03T12:00:01Z",
                "src_ip": "192.168.1.105",
                "dest_ip": "10.0.0.2",
                "dest_port": 3389,
                "proto": "TCP",
                "flow": {"pkts_toserver": 700, "bytes_toserver": 200000},
            },
        ]
        alerts = self.engine.process_raw_events(raw_events)
        self.assertIsInstance(alerts, list)
        self.assertGreater(len(alerts), 0)
        
        first_alert = alerts[0]
        self.assertIn("source_ip", first_alert)
        self.assertIn("destination_ip", first_alert)
        self.assertIn("incident_id", first_alert)
        self.assertIn("alerts", first_alert)



if __name__ == "__main__":
    unittest.main()
