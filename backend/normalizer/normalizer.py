import uuid
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict


CANONICAL_KEYS = [
    "timestamp",
    "source_ip",
    "source_port",
    "destination_ip",
    "destination_port",
    "protocol",
    "event_type",
    "bytes_in",
    "bytes_out",
    "packets_in",
    "packets_out",
    "duration",
    "application",
    "source",
    "raw_event"
]


def normalize_suricata_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes a raw Suricata EVE JSON record into the canonical CyberOrbit security event schema.
    Handles missing fields safely without inventing fictitious data.
    """
    if not isinstance(raw_event, dict):
        raw_event = {}

    timestamp = raw_event.get("timestamp")
    source_ip = raw_event.get("src_ip")
    source_port = raw_event.get("src_port")
    destination_ip = raw_event.get("dest_ip")
    destination_port = raw_event.get("dest_port")
    protocol = raw_event.get("proto")
    event_type = raw_event.get("event_type")

    # Flow metrics
    flow = raw_event.get("flow", {}) if isinstance(raw_event.get("flow"), dict) else {}
    bytes_in = flow.get("bytes_toserver", 0)
    bytes_out = flow.get("bytes_toclient", 0)
    packets_in = flow.get("pkts_toserver", 0)
    packets_out = flow.get("pkts_toclient", 0)
    duration = flow.get("age")

    # Application protocol resolving
    application = None
    if "http" in raw_event and isinstance(raw_event["http"], dict):
        http = raw_event["http"]
        method = http.get("http_method", "")
        host = http.get("hostname", "")
        url = http.get("url", "")
        app_parts = [p for p in [method, host, url] if p]
        application = " ".join(app_parts) if app_parts else None
    elif "dns" in raw_event and isinstance(raw_event["dns"], dict):
        dns = raw_event["dns"]
        rrtype = dns.get("rrtype", "")
        rrname = dns.get("rrname", "")
        application = f"DNS {rrtype} {rrname}".strip()
    elif "tls" in raw_event and isinstance(raw_event["tls"], dict):
        tls = raw_event["tls"]
        sni = tls.get("sni", "")
        application = f"TLS SNI: {sni}".strip() if sni else None
    elif raw_event.get("app_proto"):
        application = str(raw_event.get("app_proto"))

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "protocol": protocol,
        "event_type": event_type,
        "bytes_in": bytes_in if isinstance(bytes_in, (int, float)) else 0,
        "bytes_out": bytes_out if isinstance(bytes_out, (int, float)) else 0,
        "packets_in": packets_in if isinstance(packets_in, (int, float)) else 0,
        "packets_out": packets_out if isinstance(packets_out, (int, float)) else 0,
        "duration": duration if isinstance(duration, (int, float)) else None,
        "application": application,
        "source": "suricata",
        "raw_event": raw_event
    }


def normalize_zeek_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Normalizes a raw Zeek JSON log record into the canonical CyberOrbit security event schema.
    Handles missing fields safely without inventing fictitious data.
    """
    if not isinstance(raw_event, dict):
        raw_event = {}

    # Zeek timestamp resolution (ts is epoch float or string)
    raw_ts = raw_event.get("ts")
    if isinstance(raw_ts, (int, float)):
        timestamp = datetime.fromtimestamp(raw_ts, timezone.utc).isoformat().replace("+00:00", "Z")
    else:
        timestamp = raw_ts

    source_ip = raw_event.get("id.orig_h") or raw_event.get("src_ip")
    source_port = raw_event.get("id.orig_p") or raw_event.get("src_port")
    destination_ip = raw_event.get("id.resp_h") or raw_event.get("dest_ip")
    destination_port = raw_event.get("id.resp_p") or raw_event.get("dest_port")
    protocol = raw_event.get("proto")
    event_type = raw_event.get("event_type") or raw_event.get("_path") or "conn"

    # Flow metrics from Zeek conn.log
    bytes_in = raw_event.get("orig_bytes") or raw_event.get("bytes_in") or 0
    bytes_out = raw_event.get("resp_bytes") or raw_event.get("bytes_out") or 0
    packets_in = raw_event.get("orig_pkts") or raw_event.get("packets_in") or 0
    packets_out = raw_event.get("resp_pkts") or raw_event.get("packets_out") or 0
    duration = raw_event.get("duration")

    # Application protocol resolving
    application = None
    if "host" in raw_event or "uri" in raw_event:
        method = raw_event.get("method", "")
        host = raw_event.get("host", "")
        uri = raw_event.get("uri", "")
        app_parts = [p for p in [method, host, uri] if p]
        application = " ".join(app_parts) if app_parts else None
    elif "query" in raw_event:
        qtype = raw_event.get("qtype_name", "")
        query = raw_event.get("query", "")
        application = f"DNS {qtype} {query}".strip()
    elif "server_name" in raw_event:
        sni = raw_event.get("server_name", "")
        application = f"SSL SNI: {sni}".strip() if sni else None
    elif raw_event.get("service"):
        application = str(raw_event.get("service"))

    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "source_port": source_port,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "protocol": protocol,
        "event_type": event_type,
        "bytes_in": bytes_in if isinstance(bytes_in, (int, float)) else 0,
        "bytes_out": bytes_out if isinstance(bytes_out, (int, float)) else 0,
        "packets_in": packets_in if isinstance(packets_in, (int, float)) else 0,
        "packets_out": packets_out if isinstance(packets_out, (int, float)) else 0,
        "duration": duration if isinstance(duration, (int, float)) else None,
        "application": application,
        "source": "zeek",
        "raw_event": raw_event
    }


@dataclass
class NormalizedEvent:
    id: str
    severity: str  # 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
    event: str
    ip: str
    dest_ip: str
    asset: str
    timestamp: str
    status: str  # 'UNREVIEWED' | 'CONFIRMED' | 'MITIGATED' | 'DISMISSED'
    confidence: int
    payloadSnippet: str
    geoOrigin: str
    attackVector: str
    cveId: Optional[str] = None
    proto: Optional[str] = None
    src_port: Optional[int] = None
    dest_port: Optional[int] = None
    raw_event_type: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EventNormalizer:
    """
    Legacy wrapper for CyberOrbit Event Normalizer.
    Normalizes raw telemetry logs into standard SOC AnomalyEvent & canonical schemas.
    """

    ASSET_MAP = {
        80: "edge-api-01",
        443: "auth-gateway-01",
        3000: "soc-dashboard-web",
        5432: "db-cluster-primary",
        22: "bastion-ssh-01",
        53: "dns-resolver-04",
        8080: "app-server-02"
    }

    GEO_IP_MOCK = {
        "127.0.0.1": "LOCAL / INT",
        "10.0.0.1": "INT / VPN",
        "192.168.1.1": "LAN / INT",
    }

    @staticmethod
    def map_severity(suricata_severity: int) -> str:
        if suricata_severity <= 1:
            return "CRITICAL"
        elif suricata_severity == 2:
            return "HIGH"
        elif suricata_severity == 3:
            return "MEDIUM"
        else:
            return "LOW"

    @classmethod
    def resolve_asset(cls, dest_ip: str, dest_port: Optional[int]) -> str:
        if dest_port and dest_port in cls.ASSET_MAP:
            return cls.ASSET_MAP[dest_port]
        if dest_ip and (dest_ip.startswith("127.") or dest_ip.startswith("10.") or dest_ip.startswith("192.168.")):
            return f"internal-asset-{dest_ip.split('.')[-1]}"
        return f"external-target-{dest_ip}" if dest_ip else "unknown-target"

    @classmethod
    def resolve_geo(cls, ip: str) -> str:
        if not ip:
            return "UNKNOWN"
        if ip in cls.GEO_IP_MOCK:
            return cls.GEO_IP_MOCK[ip]
        hash_val = int(hashlib.md5(ip.encode()).hexdigest(), 16)
        origins = ["FRA / DE", "BOM / IN", "SGP / SG", "IHN / US", "TKY / JP", "LON / UK", "AMS / NL"]
        return origins[hash_val % len(origins)]

    @classmethod
    def normalize_suricata_event(cls, raw: Dict[str, Any]) -> Optional[NormalizedEvent]:
        event_type = raw.get("event_type", "unknown")
        timestamp = raw.get("timestamp", datetime.utcnow().isoformat() + "Z")
        src_ip = raw.get("src_ip", "0.0.0.0")
        dest_ip = raw.get("dest_ip", "0.0.0.0")
        proto = raw.get("proto", "TCP")
        src_port = raw.get("src_port")
        dest_port = raw.get("dest_port")

        event_id = str(uuid.uuid4())

        if event_type == "alert":
            alert_data = raw.get("alert", {})
            signature = alert_data.get("signature", "Unknown Security Alert")
            suricata_sev = alert_data.get("severity", 3)
            category = alert_data.get("category", "Network Intrusion")

            severity = cls.map_severity(suricata_sev)
            asset = cls.resolve_asset(dest_ip, dest_port)
            geo = cls.resolve_geo(src_ip)
            payload = alert_data.get("payload_printable", f"Signature ID: {alert_data.get('signature_id', 'N/A')}")

            return NormalizedEvent(
                id=event_id,
                severity=severity,
                event=signature,
                ip=src_ip,
                dest_ip=dest_ip,
                asset=asset,
                timestamp=timestamp,
                status="UNREVIEWED",
                confidence=85 if severity in ["CRITICAL", "HIGH"] else 70,
                payloadSnippet=payload,
                geoOrigin=geo,
                attackVector=category,
                proto=proto,
                src_port=src_port,
                dest_port=dest_port,
                raw_event_type="alert"
            )

        elif event_type == "flow":
            flow_data = raw.get("flow", {})
            pkts_to_server = flow_data.get("pkts_toserver", 0)
            bytes_to_server = flow_data.get("bytes_toserver", 0)

            if pkts_to_server > 500 or bytes_to_server > 100000:
                severity = "HIGH"
                signature = "High Volume Traffic Spike"
            else:
                severity = "LOW"
                signature = "Standard Network Flow"

            asset = cls.resolve_asset(dest_ip, dest_port)
            geo = cls.resolve_geo(src_ip)
            payload = f"Protocol: {proto}, Packets: {pkts_to_server}, Bytes: {bytes_to_server}"

            return NormalizedEvent(
                id=event_id,
                severity=severity,
                event=signature,
                ip=src_ip,
                dest_ip=dest_ip,
                asset=asset,
                timestamp=timestamp,
                status="UNREVIEWED",
                confidence=60,
                payloadSnippet=payload,
                geoOrigin=geo,
                attackVector="Flow Anomaly",
                proto=proto,
                src_port=src_port,
                dest_port=dest_port,
                raw_event_type="flow"
            )

        asset = cls.resolve_asset(dest_ip, dest_port)
        geo = cls.resolve_geo(src_ip)
        return NormalizedEvent(
            id=event_id,
            severity="LOW",
            event=f"Telemetry Event: {event_type.upper()}",
            ip=src_ip,
            dest_ip=dest_ip,
            asset=asset,
            timestamp=timestamp,
            status="UNREVIEWED",
            confidence=50,
            payloadSnippet=f"Raw Event Type: {event_type}",
            geoOrigin=geo,
            attackVector="Telemetry Monitor",
            proto=proto,
            src_port=src_port,
            dest_port=dest_port,
            raw_event_type=event_type
        )
