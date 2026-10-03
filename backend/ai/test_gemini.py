"""
Unit Tests for CyberOrbit Gemini SOC Copilot
-------------------------------------------
Verifies backend API key enforcement, response schema validation, fallback analysis,
mock API execution, and non-executable advisory safety controls.
"""

import json
import unittest
from unittest.mock import patch, MagicMock
from backend.ai.gemini import GeminiSOCCopilot, GeminiValidationError


class TestGeminiSOCCopilot(unittest.TestCase):

    def setUp(self):
        self.sample_alert = {
            "id": "alert-1001",
            "title": "ET EXPLOIT Suspicious SQL Injection Signature",
            "severity": "HIGH",
            "risk_score": 85,
            "source_ip": "192.168.1.100",
            "destination_ip": "10.0.0.5",
            "destination_port": 443,
            "protocol": "TCP",
            "category": "web-application-attack",
            "timestamp": "2026-10-03T18:00:00Z",
            "evidence": {
                "payloadSnippet": "SELECT * FROM users WHERE username='admin' --",
                "ml_anomaly_score": 0.88,
                "threat_intel_matches": ["Malicious Scanner IP"]
            }
        }

    def test_backend_key_initialization(self):
        """Verify Gemini API key is loaded backend-only and VITE_ prefixed envs are ignored."""
        copilot = GeminiSOCCopilot(api_key="backend_secret_key_12345")
        self.assertTrue(copilot.is_configured())
        self.assertEqual(copilot.api_key, "backend_secret_key_12345")

        with patch.dict("os.environ", {"VITE_GEMINI_API_KEY": "leaked_frontend_key"}, clear=True):
            copilot_unconfigured = GeminiSOCCopilot(api_key="")
            self.assertFalse(copilot_unconfigured.is_configured())

    def test_schema_validation_success(self):
        """Verify strict validation succeeds when all required fields are valid."""
        copilot = GeminiSOCCopilot()
        valid_raw = {
            "summary": "High severity SQL injection attack targeted at internal web app.",
            "possible_attack_type": "SQL Injection (SQLi)",
            "evidence_explanation": "Payload contains SQL comment markers '--' and UNION SELECT strings.",
            "recommended_investigation_steps": [
                "Examine web application database query logs around timestamp.",
                "Verify if database user privileges allow schema modification."
            ],
            "recommended_containment_options": [
                "Apply WAF signature rule blocking SQL comment sequences.",
                "Isolate or rate-limit source IP 192.168.1.100 at ingress router."
            ],
            "confidence": 0.95
        }

        validated = copilot.validate_response(valid_raw)
        self.assertEqual(validated["summary"], valid_raw["summary"])
        self.assertEqual(validated["possible_attack_type"], "SQL Injection (SQLi)")
        self.assertEqual(validated["confidence"], 0.95)

    def test_schema_validation_missing_fields_raises_error(self):
        """Verify missing required fields raise GeminiValidationError."""
        copilot = GeminiSOCCopilot()
        incomplete_raw = {
            "summary": "Valid summary",
            "possible_attack_type": "DDoS Attack",
            # Missing evidence_explanation, investigation_steps, containment_options, confidence
        }

        with self.assertRaises(GeminiValidationError):
            copilot.validate_response(incomplete_raw)

    def test_schema_validation_invalid_types_raises_error(self):
        """Verify invalid field types raise GeminiValidationError."""
        copilot = GeminiSOCCopilot()
        invalid_types = {
            "summary": "Valid summary",
            "possible_attack_type": "Brute Force",
            "evidence_explanation": "Valid evidence",
            "recommended_investigation_steps": "Not a list",  # Invalid type
            "recommended_containment_options": ["Option 1"],
            "confidence": 0.8
        }

        with self.assertRaises(GeminiValidationError):
            copilot.validate_response(invalid_types)

    def test_fallback_analysis(self):
        """Verify fallback analysis provides complete schema-compliant analysis when API is unavailable."""
        copilot = GeminiSOCCopilot(api_key="")
        analysis = copilot.analyze_alert(self.sample_alert)

        self.assertIn("summary", analysis)
        self.assertIn("possible_attack_type", analysis)
        self.assertIn("evidence_explanation", analysis)
        self.assertIsInstance(analysis["recommended_investigation_steps"], list)
        self.assertIsInstance(analysis["recommended_containment_options"], list)
        self.assertGreaterEqual(analysis["confidence"], 0.0)
        self.assertLessEqual(analysis["confidence"], 1.0)
        
        # Verify non-executable advisory controls
        self.assertTrue(analysis["is_advisory_only"])
        self.assertTrue(analysis["requires_analyst_approval"])
        self.assertTrue(analysis["execution_prohibited"])

    @patch("urllib.request.urlopen")
    def test_mock_gemini_api_call(self, mock_urlopen):
        """Verify mock API call returning valid JSON parses and validates cleanly."""
        gemini_response_body = json.dumps({
            "candidates": [{
                "content": {
                    "parts": [{
                        "text": json.dumps({
                            "summary": "Detected reconnaissance scan from external host.",
                            "possible_attack_type": "Port Scan / Reconnaissance",
                            "evidence_explanation": "SYN packet bursts sent to multiple destination ports within 1 second.",
                            "recommended_investigation_steps": ["Inspect firewall connection table", "Correlate IP with AbuseIPDB"],
                            "recommended_containment_options": ["Block source IP at gateway"],
                            "confidence": 0.90
                        })
                    }]
                }
            }]
        }).encode("utf-8")

        mock_resp = MagicMock()
        mock_resp.read.return_value = gemini_response_body
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        copilot = GeminiSOCCopilot(api_key="valid_test_api_key")
        result = copilot.analyze_alert(self.sample_alert)

        self.assertEqual(result["summary"], "Detected reconnaissance scan from external host.")
        self.assertEqual(result["possible_attack_type"], "Port Scan / Reconnaissance")
        self.assertEqual(result["confidence"], 0.90)
        self.assertTrue(result["is_advisory_only"])
        self.assertTrue(result["execution_prohibited"])


if __name__ == "__main__":
    unittest.main()
