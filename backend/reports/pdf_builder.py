"""
CyberOrbit PDF Builder Engine
-----------------------------
Generates structured executive PDF reports for SOC operations, incident triage, and alert summaries.

Includes all required Report Sections:
- CyberOrbit Security Operations Report Header
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
import io
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import (
        SimpleDocTemplate,
        Paragraph,
        Spacer,
        Table,
        TableStyle,
        KeepTogether,
        HRFlowable,
    )
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class SOCPDFReportBuilder:
    """
    ReportLab PDF Builder for CyberOrbit Security Reports.
    """

    def __init__(self, report_title: str = "Daily SOC Report"):
        self.report_title = report_title
        self.brand_teal = colors.HexColor("#334d4a")
        self.dark_teal = colors.HexColor("#253835")
        self.accent_gold = colors.HexColor("#d49b28")
        self.alert_red = colors.HexColor("#d94b4b")
        self.alert_orange = colors.HexColor("#b8821a")
        self.soft_green = colors.HexColor("#2d9d78")
        self.bg_light = colors.HexColor("#f0f5f3")
        self.bg_paper = colors.HexColor("#ffffff")
        self.text_dark = colors.HexColor("#253835")
        self.text_muted = colors.HexColor("#6c8582")

    def build_pdf(
        self,
        report_type: str,
        data: Dict[str, Any],
        output_path: Optional[str] = None
    ) -> bytes:
        """
        Builds a complete PDF report document.
        Returns PDF bytes if output_path is None, or writes to output_path.
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            output_path if output_path else buffer,
            pagesize=letter,
            leftMargin=36,
            rightMargin=36,
            topMargin=36,
            bottomMargin=36,
        )

        styles = getSampleStyleSheet()

        # Custom Paragraph Styles
        title_style = ParagraphStyle(
            "DocTitle",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=22,
            leading=26,
            textColor=self.brand_teal,
            spaceAfter=2,
        )
        subtitle_style = ParagraphStyle(
            "DocSubTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=12,
            textColor=self.text_muted,
            spaceAfter=10,
        )
        section_heading_style = ParagraphStyle(
            "SectionHeading",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            leading=15,
            textColor=self.brand_teal,
            spaceBefore=12,
            spaceAfter=6,
        )
        body_style = ParagraphStyle(
            "BodyTextCustom",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=13.5,
            textColor=self.text_dark,
            spaceAfter=6,
        )
        code_style = ParagraphStyle(
            "CodeCustom",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#1b4332"),
            backColor=colors.HexColor("#e8f5e9"),
            borderColor=colors.HexColor("#a5d6a7"),
            borderWidth=0.5,
            borderPadding=5,
            spaceAfter=6,
        )

        story = []

        # Extract Payload Data with Fallbacks
        report_date = data.get("date", datetime.now(timezone.utc).strftime("%B %d, %Y %H:%M UTC"))
        exec_summary = data.get(
            "executive_summary",
            "During the operational window, CyberOrbit Command correlated edge telemetry stream events. Threat detection models identified potential attack signatures and executed simulated mitigation workflows."
        )

        # 1. Header: CyberOrbit Security Operations Report
        story.append(Paragraph("<b>CYBERORBIT</b>", title_style))
        story.append(Paragraph("<b>SECURITY OPERATIONS REPORT</b>", subtitle_style))
        story.append(HRFlowable(width="100%", thickness=2, color=self.brand_teal, spaceAfter=10))

        # 2. Date Section
        date_table = Table(
            [[
                Paragraph("<b>REPORT TYPE:</b> " + report_type.upper().replace("_", " "), body_style),
                Paragraph("<b>DATE:</b> " + str(report_date), ParagraphStyle("RightDate", parent=body_style, alignment=2))
            ]],
            colWidths=[270, 270]
        )
        date_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), self.bg_light),
            ('PADDING', (0, 0), (-1, -1), 6),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(date_table)
        story.append(Spacer(1, 10))

        # 3. Executive Summary
        story.append(Paragraph("Executive Summary", section_heading_style))
        story.append(Paragraph(exec_summary, body_style))
        story.append(Spacer(1, 8))

        # 4. Metrics Grid (Total Events, Total Alerts, Critical Alerts, High Alerts, Incidents)
        story.append(Paragraph("Key SOC Metrics", section_heading_style))
        total_events = data.get("total_events", 12480)
        total_alerts = data.get("total_alerts", 38)
        critical_alerts = data.get("critical_alerts", 5)
        high_alerts = data.get("high_alerts", 12)
        total_incidents = data.get("incidents_count", 4)

        metrics_data = [
            ["Total Events", "Total Alerts", "Critical Alerts", "High Alerts", "Incidents"],
            [
                f"{total_events:,}",
                f"{total_alerts:,}",
                f"{critical_alerts:,}",
                f"{high_alerts:,}",
                f"{total_incidents:,}"
            ]
        ]
        metrics_table = Table(metrics_data, colWidths=[108, 108, 108, 108, 108])
        metrics_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.brand_teal),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 5),
            ('TOPPADDING', (0, 0), (-1, 0), 5),
            ('BACKGROUND', (0, 1), (-1, 1), self.bg_light),
            ('FONTNAME', (0, 1), (-1, 1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 1), (-1, 1), 12),
            ('TEXTCOLOR', (2, 1), (2, 1), self.alert_red),
            ('TEXTCOLOR', (3, 1), (3, 1), self.alert_orange),
            ('TEXTCOLOR', (4, 1), (4, 1), self.brand_teal),
            ('PADDING', (0, 1), (-1, 1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#d4deda")),
        ]))
        story.append(metrics_table)
        story.append(Spacer(1, 10))

        # 5. Top Attack Types & 6. Top Source IPs
        story.append(Paragraph("Threat Intelligence Breakdown", section_heading_style))
        top_attacks = data.get("top_attack_types", [
            {"attack_type": "HTTP Flood / Layer 7 SYN Spike", "count": 14},
            {"attack_type": "SQL Injection Probe", "count": 9},
            {"attack_type": "Credential Stuffing", "count": 7},
            {"attack_type": "Command Injection (RCE)", "count": 5},
        ])
        top_ips = data.get("top_source_ips", [
            {"ip": "185.220.101.42", "location": "Frankfurt, DE", "threat_count": 18},
            {"ip": "45.155.205.91", "location": "Moscow, RU", "threat_count": 12},
            {"ip": "198.51.100.99", "location": "Singapore, SG", "threat_count": 8},
        ])

        attack_rows = [["ATTACK CLASSIFICATION", "OCCURRENCES"]]
        for a in top_attacks:
            attack_rows.append([a.get("attack_type", "Unknown"), str(a.get("count", 0))])

        ip_rows = [["SOURCE IP", "ORIGIN", "THREAT COUNT"]]
        for ip in top_ips:
            ip_rows.append([ip.get("ip", "0.0.0.0"), ip.get("location", "Unknown"), str(ip.get("threat_count", 0))])

        t_attack = Table(attack_rows, colWidths=[180, 80])
        t_attack.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.dark_teal),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#d4deda")),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('FONTSIZE', (0, 1), (-1, -1), 8.5),
        ]))

        t_ip = Table(ip_rows, colWidths=[110, 100, 60])
        t_ip.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.dark_teal),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#d4deda")),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('FONTSIZE', (0, 1), (-1, -1), 8.5),
        ]))

        intel_grid = Table([[t_attack, t_ip]], colWidths=[270, 270])
        intel_grid.setStyle(TableStyle([('VALIGN', (0, 0), (-1, -1), 'TOP')]))
        story.append(intel_grid)
        story.append(Spacer(1, 10))

        # 7. Incident Timeline
        story.append(Paragraph("Incident Timeline", section_heading_style))
        timeline = data.get("incident_timeline", [
            {"time": "02:14:00 UTC", "event": "Volumetric SYN surge detected on gateway-01 (1.84 Gbps)"},
            {"time": "02:14:15 UTC", "event": "Suricata & Zeek normalizer generated CRITICAL alert (INC-5001)"},
            {"time": "02:15:00 UTC", "event": "Gemini SOC Copilot issued BLOCK_IP recommendation for 198.51.100.99"},
            {"time": "02:15:30 UTC", "event": "Analyst Sarah Chen approved simulated firewall drop rule"},
            {"time": "02:18:00 UTC", "event": "Incident status set to CONTAINED / RESOLVED"},
        ])
        tline_rows = [["TIME", "EVENT DESCRIPTION"]]
        for t in timeline:
            tline_rows.append([t.get("time", ""), t.get("event", "")])

        tline_table = Table(tline_rows, colWidths=[110, 430])
        tline_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), self.brand_teal),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#d4deda")),
            ('PADDING', (0, 0), (-1, -1), 5),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 1), (-1, -1), 8.5),
        ]))
        story.append(tline_table)
        story.append(Spacer(1, 10))

        # 8. Detection Evidence
        story.append(Paragraph("Detection Evidence", section_heading_style))
        evidence = data.get(
            "detection_evidence",
            'POST /v1/auth/login HTTP/2.0\nHost: auth-gateway-01\nUser-Agent: Mozilla/5.0 (Hydra-Brute/4.2)\nPayload: {"user": "\' OR 1=1 --", "pass": "admin123"}\nFlags: TCP SYN Surge [Rate: 14,200 pps]'
        )
        story.append(Paragraph(evidence.replace("\n", "<br/>"), code_style))
        story.append(Spacer(1, 6))

        # 9. AI Analysis
        story.append(Paragraph("AI Analysis (Gemini SOC Copilot)", section_heading_style))
        ai_summary = data.get(
            "ai_analysis",
            "Gemini SOC Copilot correlated multi-stage brute force and SQL injection telemetry. Recommended immediate rate-limiting and host isolation."
        )
        story.append(Paragraph(ai_summary, body_style))
        story.append(Spacer(1, 6))

        # 10. Response Actions & 11. Resolution
        story.append(Paragraph("Response Actions & Resolution", section_heading_style))
        response_actions = data.get("response_actions", [
            "1. BLOCK_IP (198.51.100.99) - Simulated edge firewall drop rule applied.",
            "2. ISOLATE_HOST (auth-gateway-01) - Quarantined host to isolated VLAN segment.",
            "3. MONITOR_HOST (db-cluster-primary) - Deep PCAP packet capture stream enabled."
        ])
        resolution = data.get(
            "resolution",
            "Incident status: RESOLVED. Threat actor source IP blocked and target gateway isolated. Uptime SLA maintained at 100%."
        )

        resp_text = "<br/>".join(response_actions)
        story.append(Paragraph(f"<b>Response Actions Executed:</b><br/>{resp_text}", body_style))
        story.append(Spacer(1, 4))
        story.append(Paragraph(f"<b>Final Resolution:</b> {resolution}", body_style))

        doc.build(story)

        if output_path:
            return output_path
        return buffer.getvalue()


# Helper fallback builder in case ReportLab is not available
class BasicPDFReportBuilder:
    """Fallback plain text/PDF generator if ReportLab fails."""
    def build_pdf(self, report_type: str, data: Dict[str, Any], output_path: Optional[str] = None) -> bytes:
        content = f"""CyberOrbit
Security Operations Report
Date: {data.get('date', datetime.now(timezone.utc).isoformat())}

Executive Summary:
{data.get('executive_summary', 'SOC Telemetry Analysis')}

Total Events: {data.get('total_events', 12480)}
Total Alerts: {data.get('total_alerts', 38)}
Critical Alerts: {data.get('critical_alerts', 5)}
High Alerts: {data.get('high_alerts', 12)}
Incidents: {data.get('incidents_count', 4)}

Top Attack Types:
{data.get('top_attack_types', [])}

Top Source IPs:
{data.get('top_source_ips', [])}

Incident Timeline:
{data.get('incident_timeline', [])}

Detection Evidence:
{data.get('detection_evidence', 'N/A')}

AI Analysis:
{data.get('ai_analysis', 'N/A')}

Response Actions:
{data.get('response_actions', [])}

Resolution:
{data.get('resolution', 'RESOLVED')}
"""
        pdf_bytes = content.encode("utf-8")
        if output_path:
            with open(output_path, "wb") as f:
                f.write(pdf_bytes)
            return output_path
        return pdf_bytes
