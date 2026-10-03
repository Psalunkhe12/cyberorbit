import unittest
from backend.threat_intel.matcher import (
    ThreatIntelMatcher,
    InternalDatabaseProvider,
    ThreatIntelProvider,
    ThreatIndicatorMatch,
)


class DummyCustomProvider(ThreatIntelProvider):
    @property
    def provider_name(self) -> str:
        return "DummyCustomProvider"

    def lookup_ip(self, ip: str):
        if ip == "203.0.113.111":
            return ThreatIndicatorMatch(
                indicator=ip,
                indicator_type="IP",
                risk_score=95,
                risk_label="CRITICAL",
                attack_type="Custom Feed C2",
                provider_name=self.provider_name,
                evidence=f"Custom feed matched {ip}",
            )
        return None

    def lookup_domain(self, domain: str):
        return None

    def lookup_hash(self, file_hash: str):
        return None


class TestThreatIntelligenceAbstraction(unittest.TestCase):
    def setUp(self):
        self.matcher = ThreatIntelMatcher()

    def test_source_ip_match(self):
        """Verify matching malicious source IP increases risk score and attaches evidence"""
        event = {
            "source_ip": "198.51.100.99",
            "destination_ip": "10.0.0.1",
            "risk_score": 50,
            "evidence": "Standard HTTP connection",
        }
        matches, alert = self.matcher.match_event(event)

        self.assertGreater(len(matches), 0)
        self.assertEqual(matches[0].indicator, "198.51.100.99")
        self.assertEqual(matches[0].indicator_type, "IP")
        self.assertTrue(alert["threat_intel_match"])
        self.assertGreater(alert["risk_score"], 50)
        self.assertIn("[THREAT INTEL MATCH]", alert["evidence"])

    def test_domain_match(self):
        """Verify extracting domain from TLS SNI / DNS and matching malicious domain"""
        event = {
            "source_ip": "192.168.1.50",
            "destination_ip": "10.0.0.1",
            "application": "TLS SNI: malicious-c2.example.com",
            "raw_event": {"tls": {"sni": "malicious-c2.example.com"}},
            "risk_score": 40,
        }
        matches, alert = self.matcher.match_event(event)

        self.assertGreater(len(matches), 0)
        domain_matches = [m for m in matches if m.indicator_type == "DOMAIN"]
        self.assertGreater(len(domain_matches), 0)
        self.assertEqual(domain_matches[0].indicator, "malicious-c2.example.com")
        self.assertTrue(alert["threat_intel_match"])
        self.assertGreater(alert["risk_score"], 40)

    def test_payload_hash_match(self):
        """Verify extracting SHA-256 payload hash and matching threat indicator"""
        sha256_payload = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        event = {
            "source_ip": "192.168.1.20",
            "destination_ip": "10.0.0.2",
            "payloadSnippet": f"POST /upload HTTP/1.1 payload_hash={sha256_payload}",
            "risk_score": 30,
        }
        matches, alert = self.matcher.match_event(event)

        self.assertGreater(len(matches), 0)
        hash_matches = [m for m in matches if m.indicator_type == "HASH"]
        self.assertGreater(len(hash_matches), 0)
        self.assertEqual(hash_matches[0].indicator, sha256_payload)
        self.assertEqual(alert["severity"], "CRITICAL")

    def test_custom_provider_extension(self):
        """Verify registering a custom ThreatIntelProvider interface without public API queries"""
        self.matcher.register_provider(DummyCustomProvider())
        event = {
            "source_ip": "203.0.113.111",
            "destination_ip": "10.0.0.1",
            "risk_score": 40,
        }
        matches, alert = self.matcher.match_event(event)

        self.assertGreater(len(matches), 0)
        custom_matches = [m for m in matches if m.provider_name == "DummyCustomProvider"]
        self.assertGreater(len(custom_matches), 0)
        self.assertEqual(custom_matches[0].attack_type, "Custom Feed C2")

    def test_no_match_leaves_normal_score(self):
        """Verify clean events with no threat matches are untouched"""
        event = {
            "source_ip": "10.0.0.5",
            "destination_ip": "10.0.0.1",
            "risk_score": 20,
            "evidence": "Clean internal traffic",
        }
        matches, alert = self.matcher.match_event(event)

        self.assertEqual(len(matches), 0)
        self.assertNotIn("threat_intel_match", alert)
        self.assertEqual(alert["risk_score"], 20)


if __name__ == "__main__":
    unittest.main()
