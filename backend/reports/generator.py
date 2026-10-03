"""
CyberOrbit Security Report Generator
------------------------------------
Provides dedicated report generators for:
- Daily SOC Report
- Incident Report
- Alert Report

Every generated PDF includes all required sections:
1. CyberOrbit
2. Security Operations Report
3. Date
4. Executive Summary
5. Total Events
6. Total Alerts
7. Critical Alerts
8. High Alerts
9. Incidents
10. Top Attack Types
11. Top Source IPs
12. Incident Timeline
13. Detection Evidence
14. AI Analysis
15. Response Actions
16. Resolution
"""

import os
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from backend.reports.pdf_builder import SOCPDFReportBuilder, REPORTLAB_AVAILABLE, BasicPDFReportBuilder


class SecurityReportGenerator:
    """
    Main Security Report Generator API for CyberOrbit.
    """

    def __init__(self):
        if REPORTLAB_AVAILABLE:
            self.builder = SOCPDFReportBuilder()
        else:
            self.builder = BasicPDFReportBuilder()

    def generate_daily_soc_report(
        self,
        data: Optional[Dict[str, Any]] = None,
        output_path: Optional[str] = None
    ) -> bytes:
        """
        Generates a Daily SOC Security Report PDF.
        """
        payload = self._build_daily_soc_payload(data)
        return self.builder.build_pdf(
            report_type="Daily SOC Report",
            data=payload,
            output_path=output_path
        )

    def generate_incident_report(
        self,
        incident_data: Optional[Dict[str, Any]] = None,
        output_path: Optional[str] = None
    ) -> bytes:
        """
        Generates an Incident Security Report PDF for a specific incident or set of incidents.
        """
        payload = self._build_incident_payload(incident_data)
        return self.builder.build_pdf(
            report_type="Incident Report",
            data=payload,
            output_path=output_path
        )

    def generate_alert_report(
        self,
        alert_data: Optional[Dict[str, Any]] = None,
        output_path: Optional[str] = None
    ) -> bytes:
        """
        Generates an Alert Security Report PDF for a specific alert or set of alerts.
        """
        payload = self._build_alert_payload(alert_data)
        return self.builder.build_pdf(
            report_type="Alert Report",
            data=payload,
            output_path=output_path
        )

    def _build_daily_soc_payload(self, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Constructs standardized Daily SOC Report payload."""
        data = data or {}
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        return {
            "date": data.get("date", now),
            "executive_summary": data.get(
                "executive_summary",
                "Daily SOC Command Operations Report: Over the past 24 hours, CyberOrbit automated collectors ingested network telemetry. 38 anomalies were reviewed with 92.4% automated containment rate."
            ),
            "total_events": data.get("total_events", 12480),
            "total_alerts": data.get("total_alerts", 38),
            "critical_alerts": data.get("critical_alerts", 5),
            "high_alerts": data.get("high_alerts", 12),
            "incidents_count": data.get("incidents_count", 4),
            "top_attack_types": data.get("top_attack_types", [
                {"attack_type": "Layer 7 SYN Surge", "count": 14},
                {"attack_type": "SQL Injection Probe", "count": 9},
                {"attack_type": "Credential Stuffing", "count": 7},
                {"attack_type": "Command Execution (RCE)", "count": 5},
            ]),
            "top_source_ips": data.get("top_source_ips", [
                {"ip": "185.220.101.42", "location": "Frankfurt, DE", "threat_count": 18},
                {"ip": "45.155.205.91", "location": "Moscow, RU", "threat_count": 12},
                {"ip": "198.51.100.99", "location": "Singapore, SG", "threat_count": 8},
            ]),
            "incident_timeline": data.get("incident_timeline", [
                {"time": "02:14 UTC", "event": "Volumetric SYN surge spike detected on gateway-01 (1.84 Gbps)"},
                {"time": "02:15 UTC", "event": "Zeek & Suricata normalizer generated CRITICAL alert (INC-5001)"},
                {"time": "02:16 UTC", "event": "Gemini SOC Copilot generated recommended containment options"},
                {"time": "02:17 UTC", "event": "Analyst approved simulated IP block on 198.51.100.99"},
                {"time": "02:20 UTC", "event": "Incident state updated to RESOLVED"},
            ]),
            "detection_evidence": data.get(
                "detection_evidence",
                "POST /v1/auth/login HTTP/2.0\nHost: auth-gateway-01\nPayload Snippet: UNION SELECT null, username, password FROM users --\nTCP SYN Surge [Rate: 14,200 pps]"
            ),
            "ai_analysis": data.get(
                "ai_analysis",
                "Gemini SOC Copilot Analysis: Correlated multi-vector telemetry matching known credential stuffing and SQL injection exploit kits. Risk score: 92/100."
            ),
            "response_actions": data.get("response_actions", [
                "1. BLOCK_IP (198.51.100.99) - Simulated edge firewall drop rule enforced.",
                "2. ISOLATE_HOST (auth-gateway-01) - Quarantined host to isolated VLAN segment.",
                "3. MONITOR_HOST (db-cluster-primary) - Deep PCAP packet capture stream enabled."
            ]),
            "resolution": data.get(
                "resolution",
                "Daily SOC Operations concluded with 0 unhandled critical threats. All identified threat origin IPs mitigated."
            ),
        }

    def _build_incident_payload(self, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Constructs standardized Incident Report payload."""
        data = data or {}
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        inc_id = data.get("id", "inc-5001")
        title = data.get("title", "Credential Stuffing & SYN Surge on Auth Cluster")

        return {
            "date": data.get("date", now),
            "executive_summary": data.get(
                "executive_summary",
                f"Incident Investigation Report for {inc_id} ({title}): Critical multi-stage attack detected on core authentication assets."
            ),
            "total_events": data.get("total_events", 4200),
            "total_alerts": data.get("total_alerts", 8),
            "critical_alerts": data.get("critical_alerts", 3),
            "high_alerts": data.get("high_alerts", 4),
            "incidents_count": data.get("incidents_count", 1),
            "top_attack_types": data.get("top_attack_types", [
                {"attack_type": "Credential Stuffing Surge", "count": 6},
                {"attack_type": "TCP SYN Surge", "count": 2},
            ]),
            "top_source_ips": data.get("top_source_ips", [
                {"ip": data.get("source_ip", "198.51.100.99"), "location": "Singapore, SG", "threat_count": 8},
            ]),
            "incident_timeline": data.get("incident_timeline", [
                {"time": "02:14:00 UTC", "event": "Brute force surge initiated against /v1/auth/login"},
                {"time": "02:14:30 UTC", "event": "Incident INC-5001 auto-correlated by detection engine"},
                {"time": "02:15:00 UTC", "event": "AI Copilot analysis requested by Senior Analyst"},
                {"time": "02:16:00 UTC", "event": "ISOLATE_HOST action executed for auth-gateway-01"},
            ]),
            "detection_evidence": data.get(
                "detection_evidence",
                f"Incident ID: {inc_id}\nAsset: {data.get('target_asset', 'auth-gateway-01')}\nPayload: POST /v1/auth/login X-Forwarded-For: 198.51.100.99"
            ),
            "ai_analysis": data.get(
                "ai_analysis",
                "Gemini SOC Copilot Incident Summary: Attack vector indicates automated credential stuffing campaign originating from botnet proxy nodes."
            ),
            "response_actions": data.get("response_actions", [
                f"1. BLOCK_IP ({data.get('source_ip', '198.51.100.99')}) - Simulated firewall drop rule applied.",
                f"2. ISOLATE_HOST ({data.get('target_asset', 'auth-gateway-01')}) - Quarantined host to isolated VLAN segment."
            ]),
            "resolution": data.get(
                "resolution",
                f"Incident {inc_id} status set to RESOLVED following successful simulated host isolation and firewall blocking."
            ),
        }

    def _build_alert_payload(self, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Constructs standardized Alert Report payload."""
        data = data or {}
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        alert_id = data.get("id", "alert-101")
        event = data.get("event", "SQL Injection Guard Triggered")

        return {
            "date": data.get("date", now),
            "executive_summary": data.get(
                "executive_summary",
                f"Security Alert Investigation Report for {alert_id} ({event}): Ingress web application payload triggered WAF signature matching."
            ),
            "total_events": data.get("total_events", 850),
            "total_alerts": data.get("total_alerts", 1),
            "critical_alerts": data.get("critical_alerts", 1 if data.get("severity") == "CRITICAL" else 0),
            "high_alerts": data.get("high_alerts", 1 if data.get("severity") == "HIGH" else 0),
            "incidents_count": data.get("incidents_count", 0),
            "top_attack_types": data.get("top_attack_types", [
                {"attack_type": event, "count": 1},
            ]),
            "top_source_ips": data.get("top_source_ips", [
                {"ip": data.get("ip", "185.220.101.42"), "location": "Frankfurt, DE", "threat_count": 1},
            ]),
            "incident_timeline": data.get("incident_timeline", [
                {"time": data.get("timestamp", "02:10 UTC"), "event": f"Alert {alert_id} triggered by {event}"},
                {"time": "02:11 UTC", "event": "Analyst reviewed telemetry payload and confidence score"},
                {"time": "02:12 UTC", "event": "WAF signature updated to block payload pattern"},
            ]),
            "detection_evidence": data.get(
                "detection_evidence",
                f"Alert ID: {alert_id}\nSeverity: {data.get('severity', 'HIGH')}\nOrigin IP: {data.get('ip', '185.220.101.42')}\nSnippet: {data.get('payloadSnippet', 'SELECT * FROM users WHERE id = 1 OR 1=1')}"
            ),
            "ai_analysis": data.get(
                "ai_analysis",
                "Gemini SOC Copilot Alert Analysis: Signature matches automated vulnerability scanner probing for SQL injection vulnerabilities."
            ),
            "response_actions": data.get("response_actions", [
                f"1. WAF Signature Rule Updated for {event}.",
                f"2. Rate-limiting enforced on source IP {data.get('ip', '185.220.101.42')}."
            ]),
            "resolution": data.get(
                "resolution",
                f"Alert {alert_id} status updated to MITIGATED. Ingress payload blocked at edge proxy."
            ),
        }


# Global singleton instance
report_generator = SecurityReportGenerator()

# Export helper functions directly
generate_daily_soc_report = report_generator.generate_daily_soc_report
generate_incident_report = report_generator.generate_incident_report
generate_alert_report = report_generator.generate_alert_report
