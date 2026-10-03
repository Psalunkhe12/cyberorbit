import os
import re
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass


@dataclass
class DetectionAlert:
    rule_id: str
    rule_name: str
    severity: str  # 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
    confidence: int  # 0 to 100
    source_ip: str
    destination_ip: str
    evidence: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "confidence": self.confidence,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "evidence": self.evidence,
        }


class DetectionRules:
    """
    Configurable CyberOrbit Rule-Based Detection Engine.
    Evaluates canonical events against 7 core network security detection rules.
    Only generates security alert dictionaries; does NOT automatically block traffic.
    """

    def __init__(self, config_override: Optional[Dict[str, Any]] = None):
        cfg = config_override or {}
        
        # 1. High packet rate threshold
        self.high_packet_rate_threshold = int(
            cfg.get("high_packet_rate_threshold") or
            os.getenv("RULE_HIGH_PACKET_RATE_THRESHOLD", "500")
        )

        # 2. Possible SYN flood threshold
        self.syn_flood_threshold = int(
            cfg.get("syn_flood_threshold") or
            os.getenv("RULE_SYN_FLOOD_THRESHOLD", "50")
        )

        # 3. Port scanning unique ports threshold
        self.port_scan_port_count = int(
            cfg.get("port_scan_port_count") or
            os.getenv("RULE_PORT_SCAN_PORT_COUNT", "5")
        )

        # 4. Repeated failed connections threshold
        self.failed_conn_threshold = int(
            cfg.get("failed_conn_threshold") or
            os.getenv("RULE_FAILED_CONN_THRESHOLD", "5")
        )

        # 5. Suspicious destination ports
        env_ports = os.getenv("RULE_SUSPICIOUS_PORTS", "4444,6667,31337,23,1433,3389,445,139,5900")
        default_ports = [int(p.strip()) for p in env_ports.split(",") if p.strip().isdigit()]
        self.suspicious_ports: Set[int] = set(cfg.get("suspicious_ports") or default_ports)

        # 6. Repeated connection attempts threshold
        self.repeated_attempts_threshold = int(
            cfg.get("repeated_attempts_threshold") or
            os.getenv("RULE_REPEATED_ATTEMPTS_THRESHOLD", "10")
        )

        # 7. Abnormal outbound traffic threshold (bytes)
        self.abnormal_outbound_bytes = int(
            cfg.get("abnormal_outbound_bytes") or
            os.getenv("RULE_ABNORMAL_OUTBOUND_BYTES", "100000")
        )

    def detect_high_packet_rate(self, event: Dict[str, Any]) -> Optional[DetectionAlert]:
        """Rule 1: High packet rate detection"""
        pkts_in = event.get("packets_in") or 0
        pkts_out = event.get("packets_out") or 0
        total_packets = pkts_in + pkts_out

        if total_packets >= self.high_packet_rate_threshold:
            return DetectionAlert(
                rule_id="RL-2001",
                rule_name="High Packet Rate",
                severity="HIGH",
                confidence=85,
                source_ip=str(event.get("source_ip") or "0.0.0.0"),
                destination_ip=str(event.get("destination_ip") or "0.0.0.0"),
                evidence=f"Observed total packet volume of {total_packets} packets (in: {pkts_in}, out: {pkts_out}), exceeding threshold of {self.high_packet_rate_threshold} packets."
            )
        return None

    def detect_syn_flood(self, event: Dict[str, Any]) -> Optional[DetectionAlert]:
        """Rule 2: Possible SYN flood detection"""
        proto = str(event.get("protocol") or "").upper()
        raw = event.get("raw_event")
        raw_dict = raw if isinstance(raw, dict) else {}
        tcp_info = raw_dict.get("tcp") if isinstance(raw_dict.get("tcp"), dict) else {}
        tcp_flags = str(tcp_info.get("tcp_flags") or "").lower()
        syn_count = tcp_info.get("syn", 0) if isinstance(tcp_info.get("syn"), (int, float)) else 0

        # Check explicit SYN flags, alert signatures, or high SYN count
        is_syn_event = "syn" in tcp_flags or syn_count > 0 or "syn_flood" in str(raw or "").lower()
        if proto == "TCP" and (is_syn_event or syn_count >= self.syn_flood_threshold):
            return DetectionAlert(
                rule_id="RL-2002",
                rule_name="Possible SYN Flood",
                severity="CRITICAL",
                confidence=90,
                source_ip=str(event.get("source_ip") or "0.0.0.0"),
                destination_ip=str(event.get("destination_ip") or "0.0.0.0"),
                evidence=f"TCP SYN flood pattern identified. SYN count: {syn_count}, TCP flags: '{tcp_flags}', exceeding threshold of {self.syn_flood_threshold} SYN packets."
            )
        return None


    def detect_suspicious_destination_port(self, event: Dict[str, Any]) -> Optional[DetectionAlert]:
        """Rule 5: Suspicious destination port detection"""
        dest_port = event.get("destination_port")
        if dest_port and int(dest_port) in self.suspicious_ports:
            return DetectionAlert(
                rule_id="RL-2005",
                rule_name="Suspicious Destination Port",
                severity="HIGH",
                confidence=88,
                source_ip=str(event.get("source_ip") or "0.0.0.0"),
                destination_ip=str(event.get("destination_ip") or "0.0.0.0"),
                evidence=f"Connection attempt targeting known high-risk suspicious port {dest_port}."
            )
        return None

    def detect_abnormal_outbound_traffic(self, event: Dict[str, Any]) -> Optional[DetectionAlert]:
        """Rule 7: Abnormal outbound traffic detection"""
        bytes_out = event.get("bytes_out") or 0
        if bytes_out >= self.abnormal_outbound_bytes:
            return DetectionAlert(
                rule_id="RL-2007",
                rule_name="Abnormal Outbound Traffic",
                severity="HIGH",
                confidence=85,
                source_ip=str(event.get("source_ip") or "0.0.0.0"),
                destination_ip=str(event.get("destination_ip") or "0.0.0.0"),
                evidence=f"Outbound byte transfer of {bytes_out} bytes exceeded normal baseline threshold of {self.abnormal_outbound_bytes} bytes."
            )
        return None

    def evaluate_single_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluates a single canonical event against single-event rules (1, 2, 5, 7).
        Returns list of detection alert dictionaries.
        """
        alerts = []
        for detector in [
            self.detect_high_packet_rate,
            self.detect_syn_flood,
            self.detect_suspicious_destination_port,
            self.detect_abnormal_outbound_traffic,
        ]:
            res = detector(event)
            if res:
                alerts.append(res.to_dict())
        return alerts

    def evaluate_batch_events(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Evaluates a batch/stream of canonical events against both single-event
        and aggregated multi-event rules (3. Port scanning, 4. Failed conns, 6. Repeated attempts).
        """
        alerts = []
        
        # Track aggregations by source IP
        ip_dest_ports: Dict[str, Set[int]] = {}
        ip_failed_conns: Dict[str, int] = {}
        ip_dest_attempts: Dict[str, Dict[str, int]] = {}
        ip_sample_dest: Dict[str, str] = {}

        for ev in events:
            # First run single event checks
            single_alerts = self.evaluate_single_event(ev)
            alerts.extend(single_alerts)

            src_ip = str(ev.get("source_ip") or "0.0.0.0")
            dest_ip = str(ev.get("destination_ip") or "0.0.0.0")
            dest_port = ev.get("destination_port")
            raw_event = ev.get("raw_event") or {}

            ip_sample_dest[src_ip] = dest_ip

            # Track unique destination ports per source IP (for Port Scanning - Rule 3)
            if dest_port is not None:
                if src_ip not in ip_dest_ports:
                    ip_dest_ports[src_ip] = set()
                ip_dest_ports[src_ip].add(int(dest_port))

            # Track failed connection attempts (for Repeated Failed Connections - Rule 4)
            app = str(ev.get("application") or "").lower()
            payload = str(ev.get("raw_event") or "").lower()
            is_failed = (
                "401" in app or "403" in app or "500" in app or
                "unauthorized" in payload or "reset" in payload or
                "failed" in payload or raw_event.get("event_type") == "reject"
            )
            if is_failed:
                ip_failed_conns[src_ip] = ip_failed_conns.get(src_ip, 0) + 1

            # Track repeated connection attempts per source -> dest IP pair (Rule 6)
            if src_ip not in ip_dest_attempts:
                ip_dest_attempts[src_ip] = {}
            ip_dest_attempts[src_ip][dest_ip] = ip_dest_attempts[src_ip].get(dest_ip, 0) + 1

        # Evaluate Rule 3: Port Scanning
        for src_ip, ports in ip_dest_ports.items():
            if len(ports) >= self.port_scan_port_count:
                alerts.append(
                    DetectionAlert(
                        rule_id="RL-2003",
                        rule_name="Port Scanning",
                        severity="HIGH",
                        confidence=88,
                        source_ip=src_ip,
                        destination_ip=ip_sample_dest.get(src_ip, "0.0.0.0"),
                        evidence=f"Source IP probed {len(ports)} distinct destination ports ({sorted(list(ports))[:5]}...), exceeding port scan threshold of {self.port_scan_port_count} ports."
                    ).to_dict()
                )

        # Evaluate Rule 4: Repeated Failed Connections
        for src_ip, fail_count in ip_failed_conns.items():
            if fail_count >= self.failed_conn_threshold:
                alerts.append(
                    DetectionAlert(
                        rule_id="RL-2004",
                        rule_name="Repeated Failed Connections",
                        severity="MEDIUM",
                        confidence=80,
                        source_ip=src_ip,
                        destination_ip=ip_sample_dest.get(src_ip, "0.0.0.0"),
                        evidence=f"Observed {fail_count} failed connection/authentication events, exceeding threshold of {self.failed_conn_threshold} failures."
                    ).to_dict()
                )

        # Evaluate Rule 6: Repeated Connection Attempts
        for src_ip, dest_map in ip_dest_attempts.items():
            for dest_ip, attempts in dest_map.items():
                if attempts >= self.repeated_attempts_threshold:
                    alerts.append(
                        DetectionAlert(
                            rule_id="RL-2006",
                            rule_name="Repeated Connection Attempts",
                            severity="MEDIUM",
                            confidence=82,
                            source_ip=src_ip,
                            destination_ip=dest_ip,
                            evidence=f"Observed {attempts} connection attempts from {src_ip} targeting asset {dest_ip}, exceeding threshold of {self.repeated_attempts_threshold} attempts."
                        ).to_dict()
                    )

        return alerts
