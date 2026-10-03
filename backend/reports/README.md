# CyberOrbit Security Reporting Engine

Provides structured executive PDF report generation for CyberOrbit SOC Operations, Incident Response, and Security Alert Triage.

## Supported Reports
1. **Daily SOC Report**: Comprehensive 24-hour SOC operational summary.
2. **Incident Report**: Dedicated incident investigation breakdown.
3. **Alert Report**: Granular telemetry anomaly & WAF signature match report.

## Required PDF Sections Included
Every generated PDF contains:
- `CyberOrbit` Header
- `Security Operations Report` Subtitle
- `Date`
- `Executive Summary`
- `Total Events`
- `Total Alerts`
- `Critical Alerts`
- `High Alerts`
- `Incidents`
- `Top Attack Types`
- `Top Source IPs`
- `Incident Timeline`
- `Detection Evidence`
- `AI Analysis`
- `Response Actions`
- `Resolution`

## Python Usage Example

```python
from backend.reports import (
    generate_daily_soc_report,
    generate_incident_report,
    generate_alert_report,
)

# 1. Generate Daily SOC Report
daily_pdf_bytes = generate_daily_soc_report(output_path="daily_soc_report.pdf")

# 2. Generate Incident Report
incident_data = {
    "id": "inc-5001",
    "title": "Credential Stuffing Surge on Auth Cluster",
    "source_ip": "198.51.100.99",
    "target_asset": "auth-gateway-01",
}
incident_pdf_bytes = generate_incident_report(incident_data, output_path="incident_report.pdf")

# 3. Generate Alert Report
alert_data = {
    "id": "alert-101",
    "event": "SQL Injection Guard Triggered",
    "severity": "HIGH",
    "ip": "185.220.101.42",
}
alert_pdf_bytes = generate_alert_report(alert_data, output_path="alert_report.pdf")
```

## Running Unit Tests
```bash
python3 -m unittest backend/reports/test_reports.py
```
