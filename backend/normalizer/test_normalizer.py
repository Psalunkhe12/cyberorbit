import unittest
from backend.normalizer.normalizer import (
    normalize_suricata_event,
    normalize_zeek_event,
    CANONICAL_KEYS
)


class TestNormalizer(unittest.TestCase):
    def test_canonical_keys_presence(self):
        raw = {"event_type": "alert", "src_ip": "192.168.1.100"}
        result = normalize_suricata_event(raw)
        
        self.assertIsInstance(result, dict)
        for key in CANONICAL_KEYS:
            self.assertIn(key, result, f"Missing canonical key: {key}")

    def test_suricata_alert_normalization(self):
        raw_alert = {
            "timestamp": "2026-10-01T15:43:32.221390+0000",
            "event_type": "alert",
            "src_ip": "185.220.101.42",
            "src_port": 54321,
            "dest_ip": "10.0.0.5",
            "dest_port": 80,
            "proto": "TCP",
            "alert": {
                "action": "allowed",
                "gid": 1,
                "signature_id": 2000001,
                "rev": 1,
                "signature": "ET MALWARE Suspicious User Agent",
                "category": "A Network Trojan was Detected",
                "severity": 1,
                "payload_printable": "GET /malicious/payload HTTP/1.1"
            }
        }
        res = normalize_suricata_event(raw_alert)

        self.assertEqual(res["source"], "suricata")
        self.assertEqual(res["timestamp"], "2026-10-01T15:43:32.221390+0000")
        self.assertEqual(res["source_ip"], "185.220.101.42")
        self.assertEqual(res["source_port"], 54321)
        self.assertEqual(res["destination_ip"], "10.0.0.5")
        self.assertEqual(res["destination_port"], 80)
        self.assertEqual(res["protocol"], "TCP")
        self.assertEqual(res["event_type"], "alert")
        self.assertEqual(res["raw_event"], raw_alert)

    def test_suricata_flow_normalization(self):
        raw_flow = {
            "timestamp": "2026-10-01T15:57:23.607333+0000",
            "event_type": "flow",
            "src_ip": "192.168.1.50",
            "src_port": 49152,
            "dest_ip": "1.1.1.1",
            "dest_port": 53,
            "proto": "UDP",
            "flow": {
                "pkts_toserver": 15,
                "pkts_toclient": 12,
                "bytes_toserver": 1050,
                "bytes_toclient": 2400,
                "age": 4.5
            }
        }
        res = normalize_suricata_event(raw_flow)

        self.assertEqual(res["bytes_in"], 1050)
        self.assertEqual(res["bytes_out"], 2400)
        self.assertEqual(res["packets_in"], 15)
        self.assertEqual(res["packets_out"], 12)
        self.assertEqual(res["duration"], 4.5)

    def test_suricata_http_normalization(self):
        raw_http = {
            "timestamp": "2026-10-01T16:00:00Z",
            "event_type": "http",
            "src_ip": "10.0.0.15",
            "dest_ip": "10.0.0.2",
            "proto": "TCP",
            "http": {
                "hostname": "api.cyberorbit.io",
                "url": "/v1/auth/login",
                "http_method": "POST"
            }
        }
        res = normalize_suricata_event(raw_http)

        self.assertEqual(res["application"], "POST api.cyberorbit.io /v1/auth/login")

    def test_suricata_dns_normalization(self):
        raw_dns = {
            "timestamp": "2026-10-01T16:05:00Z",
            "event_type": "dns",
            "src_ip": "10.0.0.10",
            "dest_ip": "8.8.8.8",
            "proto": "UDP",
            "dns": {
                "rrname": "malicious-c2.com",
                "rrtype": "A"
            }
        }
        res = normalize_suricata_event(raw_dns)

        self.assertEqual(res["application"], "DNS A malicious-c2.com")

    def test_suricata_missing_fields_safety(self):
        raw_empty = {}
        res = normalize_suricata_event(raw_empty)

        # Ensure no invented data is returned
        self.assertIsNone(res["timestamp"])
        self.assertIsNone(res["source_ip"])
        self.assertIsNone(res["source_port"])
        self.assertIsNone(res["destination_ip"])
        self.assertIsNone(res["destination_port"])
        self.assertIsNone(res["protocol"])
        self.assertIsNone(res["event_type"])
        self.assertEqual(res["bytes_in"], 0)
        self.assertEqual(res["bytes_out"], 0)
        self.assertEqual(res["packets_in"], 0)
        self.assertEqual(res["packets_out"], 0)
        self.assertIsNone(res["duration"])
        self.assertIsNone(res["application"])
        self.assertEqual(res["source"], "suricata")
        self.assertEqual(res["raw_event"], {})

    def test_zeek_event_normalization(self):
        raw_zeek = {
            "ts": 1696176000.0,
            "_path": "conn",
            "id.orig_h": "192.168.1.10",
            "id.orig_p": 12345,
            "id.resp_h": "142.250.190.46",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "orig_bytes": 500,
            "resp_bytes": 2500,
            "orig_pkts": 5,
            "resp_pkts": 8,
            "duration": 1.2
        }
        res = normalize_zeek_event(raw_zeek)

        self.assertEqual(res["source"], "zeek")
        self.assertEqual(res["source_ip"], "192.168.1.10")
        self.assertEqual(res["source_port"], 12345)
        self.assertEqual(res["destination_ip"], "142.250.190.46")
        self.assertEqual(res["destination_port"], 443)
        self.assertEqual(res["bytes_in"], 500)
        self.assertEqual(res["bytes_out"], 2500)
        self.assertEqual(res["application"], "ssl")


if __name__ == "__main__":
    unittest.main()
