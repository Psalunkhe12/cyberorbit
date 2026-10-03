# CyberOrbit Threat Intelligence Abstraction Layer

The CyberOrbit Threat Intelligence Abstraction Layer ([`backend/threat_intel/`](file:///d:/PROJECTS/final%20year%20project/cyberorbit/backend/threat_intel/)) evaluates network telemetry events against internal threat indicators and provides an extensible provider interface for integrating third-party threat feeds.

---

## 1. Key Principles & Security Policy

1. **Internal Database Matching First**: Matches events against the internal `threat_indicators` database table (and local seed cache).
2. **No Unsolicited Public API Queries**: Does **NOT** automatically transmit customer telemetry or query random public third-party APIs by default.
3. **Extensible Provider Interface**: Exposes a clean abstract base class (`ThreatIntelProvider`) so external threat intelligence services (e.g. VirusTotal, AbuseIPDB, AlienVault OTX) can be added as opt-in plugins later.

---

## 2. Supported Indicator Checks

The `ThreatIntelMatcher` inspects 4 distinct indicator dimensions from canonical and raw telemetry events:

| Indicator Type | Extraction Source | Example Indicators |
| :--- | :--- | :--- |
| **Source IP** | `source_ip`, `ip`, `src_ip` | `198.51.100.99`, `185.220.101.5` |
| **Destination IP** | `destination_ip`, `dest_ip` | `203.0.113.42` |
| **Domains** | HTTP Host, DNS `rrname`, TLS `sni` | `malicious-c2.example.com`, `phishing-login.net` |
| **Hashes** | Payload MD5 (32 hex) / SHA-256 (64 hex) | `e3b0c44298fc1c149afbf4c8996fb92427...` |

---

## 3. Match Actions & Alert Escalation

When an indicator match is identified:
1. **Risk Score Boost**: Increases composite `risk_score` (adds +15 to +25 points, capped at 100).
2. **Evidence Attachment**: Appends threat intel details (provider name, attack type, indicator type, risk label) directly to event evidence.
3. **Alert Creation / Update**: Updates or generates a high-confidence security alert (`threat_intel_match = True`).

---

## 4. Architecture & Extension Interface

```
                       +----------------------------------+
                       |        ThreatIntelMatcher        |
                       +----------------------------------+
                                        |
                 +----------------------+----------------------+
                 |                                             |
  +------------------------------+             +-------------------------------+
  |   InternalDatabaseProvider   |             | (Optional) Third-Party Plugin |
  | (Queries threat_indicators)  |             | (e.g., Custom Provider API)   |
  +------------------------------+             +-------------------------------+
```

### Extending with a Custom Provider:

```python
from backend.threat_intel import ThreatIntelProvider, ThreatIndicatorMatch, ThreatIntelMatcher
from typing import Optional

class CustomThreatProvider(ThreatIntelProvider):
    @property
    def provider_name(self) -> str:
        return "CustomEnterpriseFeed"

    def lookup_ip(self, ip: str) -> Optional[ThreatIndicatorMatch]:
        if ip == "198.51.100.99":
            return ThreatIndicatorMatch(
                indicator=ip,
                indicator_type="IP",
                risk_score=90,
                risk_label="CRITICAL",
                attack_type="Custom C2 Feed Match",
                provider_name=self.provider_name,
                evidence=f"Custom Feed Match on {ip}"
            )
        return None

    def lookup_domain(self, domain: str) -> Optional[ThreatIndicatorMatch]:
        return None

    def lookup_hash(self, file_hash: str) -> Optional[ThreatIndicatorMatch]:
        return None

# Register custom provider
matcher = ThreatIntelMatcher()
matcher.register_provider(CustomThreatProvider())
```

---

## 5. Python API Usage Example

```python
from backend.threat_intel import ThreatIntelMatcher

matcher = ThreatIntelMatcher()

event = {
    "source_ip": "198.51.100.99",
    "destination_ip": "10.0.0.1",
    "destination_port": 443,
    "application": "TLS SNI: malicious-c2.example.com",
    "risk_score": 50,
}

matches, updated_alert = matcher.match_event(event)

print(f"Matched {len(matches)} threat indicators.")
print(f"Updated Risk Score: {updated_alert['risk_score']}")
print(f"Evidence: {updated_alert['evidence']}")
```
