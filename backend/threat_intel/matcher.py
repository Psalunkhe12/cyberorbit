import os
import re
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set, Tuple

from backend.config.settings import settings
from backend.detection.scoring import RiskScorer

try:
    from supabase import create_client, Client
except ImportError:
    create_client = None
    Client = Any


@dataclass
class ThreatIndicatorMatch:
    """
    Represents a threat intelligence match against an indicator (IP, Domain, or Hash).
    """
    indicator: str
    indicator_type: str  # 'IP' | 'DOMAIN' | 'HASH'
    risk_score: int  # 0 to 100
    risk_label: str  # 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
    attack_type: str  # e.g., 'Malware C2', 'Botnet', 'Phishing'
    provider_name: str  # e.g., 'InternalDatabase'
    evidence: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type,
            "risk_score": self.risk_score,
            "risk_label": self.risk_label,
            "attack_type": self.attack_type,
            "provider_name": self.provider_name,
            "evidence": self.evidence,
        }


class ThreatIntelProvider(ABC):
    """
    Abstract Base Class for Threat Intelligence Providers.
    Allows future extension to external APIs (e.g. VirusTotal, AbuseIPDB, AlienVault)
    without querying external public APIs by default.
    """

    @property
    @abstractmethod
    def provider_name(self) -> str:
        pass

    @abstractmethod
    def lookup_ip(self, ip: str) -> Optional[ThreatIndicatorMatch]:
        pass

    @abstractmethod
    def lookup_domain(self, domain: str) -> Optional[ThreatIndicatorMatch]:
        pass

    @abstractmethod
    def lookup_hash(self, file_hash: str) -> Optional[ThreatIndicatorMatch]:
        pass


class InternalDatabaseProvider(ThreatIntelProvider):
    """
    Internal Database Threat Intelligence Provider.
    Queries the internal `threat_indicators` table in Supabase.
    Includes a local seed cache when Supabase is offline.
    """

    DEFAULT_SEED_INDICATORS: Dict[str, Dict[str, Any]] = {
        # Malicious IPs
        "198.51.100.99": {"type": "IP", "risk_score": 92, "risk_label": "CRITICAL", "attack": "Botnet Command & Control (C2)"},
        "185.220.101.5": {"type": "IP", "risk_score": 88, "risk_label": "CRITICAL", "attack": "Tor Exit Node / Anonymizer Proxy"},
        "203.0.113.42": {"type": "IP", "risk_score": 78, "risk_label": "HIGH", "attack": "Known Brute-Force Origin"},

        # Malicious Domains
        "malicious-c2.example.com": {"type": "DOMAIN", "risk_score": 95, "risk_label": "CRITICAL", "attack": "C2 Infrastructure Domain"},
        "phishing-login.net": {"type": "DOMAIN", "risk_score": 85, "risk_label": "HIGH", "attack": "Credential Harvesting Phishing Domain"},

        # Malicious File Hashes (MD5 / SHA-256)
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {"type": "HASH", "risk_score": 99, "risk_label": "CRITICAL", "attack": "Cobalt Strike Beacon Payload"},
        "44d88612fea8a8f36de82e1278abb02f": {"type": "HASH", "risk_score": 90, "risk_label": "CRITICAL", "attack": "Ransomware Dropper Signature"},
    }

    def __init__(self):
        self.supabase_client: Optional[Client] = None
        self.local_cache: Dict[str, Dict[str, Any]] = dict(self.DEFAULT_SEED_INDICATORS)

        if getattr(settings, "SUPABASE_URL", None) and getattr(settings, "SUPABASE_KEY", None) and create_client:
            try:
                self.supabase_client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
                self.sync_from_supabase()
            except Exception as err:
                print(f"[InternalDatabaseProvider Warning] Could not connect to Supabase: {err}")

    @property
    def provider_name(self) -> str:
        return "InternalDatabase"

    def sync_from_supabase(self):
        """Fetches indicators from Supabase threat_indicators table into local cache."""
        if not self.supabase_client:
            return
        try:
            res = self.supabase_client.from_("threat_indicators").select("*").execute()
            if res.data:
                for row in res.data:
                    origin = row.get("origin")
                    if origin:
                        self.local_cache[origin] = {
                            "type": "IP" if "." in origin or ":" in origin else "DOMAIN",
                            "risk_score": row.get("risk_score", 80),
                            "risk_label": row.get("risk_label", "HIGH"),
                            "attack": row.get("attack_type", "Threat Intel Match"),
                        }
        except Exception as err:
            print(f"[InternalDatabaseProvider Warning] Sync error: {err}")

    def add_indicator(
        self,
        indicator: str,
        indicator_type: str,
        risk_score: int = 80,
        risk_label: str = "HIGH",
        attack_type: str = "Threat Intel Match",
    ):
        """Adds a new indicator to the internal database provider."""
        self.local_cache[indicator] = {
            "type": indicator_type.upper(),
            "risk_score": risk_score,
            "risk_label": risk_label.upper(),
            "attack": attack_type,
        }

    def lookup_ip(self, ip: str) -> Optional[ThreatIndicatorMatch]:
        if not ip or ip in ("0.0.0.0", "127.0.0.1"):
            return None
        if ip in self.local_cache and self.local_cache[ip]["type"] == "IP":
            meta = self.local_cache[ip]
            return ThreatIndicatorMatch(
                indicator=ip,
                indicator_type="IP",
                risk_score=meta["risk_score"],
                risk_label=meta["risk_label"],
                attack_type=meta["attack"],
                provider_name=self.provider_name,
                evidence=f"Internal Threat Intel Match on Source/Target IP {ip}: {meta['attack']} (Risk: {meta['risk_score']}/100)",
            )
        return None

    def lookup_domain(self, domain: str) -> Optional[ThreatIndicatorMatch]:
        if not domain:
            return None
        clean_domain = domain.strip().lower()
        if clean_domain in self.local_cache and self.local_cache[clean_domain]["type"] == "DOMAIN":
            meta = self.local_cache[clean_domain]
            return ThreatIndicatorMatch(
                indicator=clean_domain,
                indicator_type="DOMAIN",
                risk_score=meta["risk_score"],
                risk_label=meta["risk_label"],
                attack_type=meta["attack"],
                provider_name=self.provider_name,
                evidence=f"Internal Threat Intel Match on Domain '{clean_domain}': {meta['attack']} (Risk: {meta['risk_score']}/100)",
            )
        return None

    def lookup_hash(self, file_hash: str) -> Optional[ThreatIndicatorMatch]:
        if not file_hash:
            return None
        clean_hash = file_hash.strip().lower()
        if clean_hash in self.local_cache and self.local_cache[clean_hash]["type"] == "HASH":
            meta = self.local_cache[clean_hash]
            return ThreatIndicatorMatch(
                indicator=clean_hash,
                indicator_type="HASH",
                risk_score=meta["risk_score"],
                risk_label=meta["risk_label"],
                attack_type=meta["attack"],
                provider_name=self.provider_name,
                evidence=f"Internal Threat Intel Match on Payload Hash '{clean_hash[:16]}...': {meta['attack']} (Risk: {meta['risk_score']}/100)",
            )
        return None


class ThreatIntelMatcher:
    """
    CyberOrbit Threat Intelligence Matcher & Abstraction Layer.
    Evaluates canonical telemetry events against internal threat indicators
    (Source IP, Destination IP, Domains, and Hashes).

    When a match occurs:
    1. Increases event risk score.
    2. Attaches threat evidence.
    3. Creates or updates security alert.
    """

    def __init__(self, providers: Optional[List[ThreatIntelProvider]] = None):
        self.providers: List[ThreatIntelProvider] = (
            providers if providers is not None else [InternalDatabaseProvider()]
        )
        self.scorer = RiskScorer()

    def register_provider(self, provider: ThreatIntelProvider):
        """Registers an additional threat intelligence provider interface."""
        self.providers.append(provider)

    def extract_domains(self, event: Dict[str, Any]) -> List[str]:
        """Extracts potential domain names from telemetry event fields."""
        domains: Set[str] = set()
        app = str(event.get("application") or "")
        raw = event.get("raw_event") if isinstance(event.get("raw_event"), dict) else {}

        # Look in HTTP host / URL
        if "http" in raw and isinstance(raw["http"], dict):
            h = raw["http"].get("hostname") or raw["http"].get("host")
            if h:
                domains.add(str(h).strip().lower())
        elif raw.get("host"):
            domains.add(str(raw["host"]).strip().lower())

        # Look in DNS query
        if "dns" in raw and isinstance(raw["dns"], dict):
            q = raw["dns"].get("rrname") or raw["dns"].get("query")
            if q:
                domains.add(str(q).strip().lower())
        elif raw.get("query"):
            domains.add(str(raw["query"]).strip().lower())

        # Look in TLS SNI
        if "tls" in raw and isinstance(raw["tls"], dict):
            sni = raw["tls"].get("sni")
            if sni:
                domains.add(str(sni).strip().lower())
        elif raw.get("server_name"):
            domains.add(str(raw["server_name"]).strip().lower())

        # Regex fallback for domains in app string
        domain_matches = re.findall(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b", app)
        for d in domain_matches:
            domains.add(d.lower())

        return list(domains)

    def extract_hashes(self, event: Dict[str, Any]) -> List[str]:
        """Extracts MD5 and SHA-256 hashes from payload or event metadata."""
        hashes: Set[str] = set()
        raw = event.get("raw_event") if isinstance(event.get("raw_event"), dict) else {}
        payload = str(event.get("payloadSnippet") or raw.get("payload_printable") or "")

        # Look for MD5 (32 hex) and SHA-256 (64 hex)
        md5_matches = re.findall(r"\b[a-fA-F0-9]{32}\b", payload)
        sha256_matches = re.findall(r"\b[a-fA-F0-9]{64}\b", payload)

        for m in md5_matches + sha256_matches:
            hashes.add(m.lower())

        return list(hashes)

    def match_event(self, event: Dict[str, Any]) -> Tuple[List[ThreatIndicatorMatch], Dict[str, Any]]:
        """
        Evaluates an event against registered threat intelligence providers.

        Checks:
        - source_ip
        - destination_ip
        - domains
        - hashes

        When matches occur:
        - Increases risk_score
        - Attaches evidence
        - Creates or updates security alert dictionary
        """
        matches: List[ThreatIndicatorMatch] = []

        src_ip = str(event.get("source_ip") or event.get("ip") or "")
        dest_ip = str(event.get("destination_ip") or event.get("dest_ip") or "")
        domains = self.extract_domains(event)
        hashes = self.extract_hashes(event)

        for provider in self.providers:
            # 1. Source IP Lookup
            if src_ip:
                m_src = provider.lookup_ip(src_ip)
                if m_src:
                    matches.append(m_src)

            # 2. Destination IP Lookup
            if dest_ip:
                m_dest = provider.lookup_ip(dest_ip)
                if m_dest:
                    matches.append(m_dest)

            # 3. Domain Lookups
            for domain in domains:
                m_dom = provider.lookup_domain(domain)
                if m_dom:
                    matches.append(m_dom)

            # 4. Hash Lookups
            for h in hashes:
                m_hash = provider.lookup_hash(h)
                if m_hash:
                    matches.append(m_hash)

        # Build / Update Alert Dictionary
        alert = dict(event)

        if matches:
            top_match = max(matches, key=lambda m: m.risk_score)
            evidence_str = "; ".join(m.evidence for m in matches)

            # 1. Increase Risk Score
            initial_score = int(alert.get("risk_score", 50))
            score_boost = 25 if top_match.risk_score >= 85 else 15
            new_risk_score = min(100, max(initial_score, top_match.risk_score) + score_boost)

            # 2. Update Severity based on boosted score
            if new_risk_score >= 80:
                new_severity = "CRITICAL"
            elif new_risk_score >= 60:
                new_severity = "HIGH"
            else:
                new_severity = "MEDIUM"

            # 3. Attach Evidence & Create/Update Alert Fields
            existing_evidence = str(alert.get("evidence") or alert.get("payloadSnippet") or "")
            combined_evidence = f"[THREAT INTEL MATCH] {evidence_str}"
            if existing_evidence:
                combined_evidence = f"{combined_evidence} | Original Evidence: {existing_evidence}"

            alert["rule_id"] = alert.get("rule_id", "RL-TI-4000")
            alert["rule_name"] = f"Threat Intel Match ({top_match.attack_type})"
            alert["severity"] = new_severity
            alert["confidence"] = max(int(alert.get("confidence", 80)), 90)
            alert["risk_score"] = new_risk_score
            alert["threat_intel_match"] = True
            alert["threat_intel_matches"] = [m.to_dict() for m in matches]
            alert["evidence"] = combined_evidence
            alert["payloadSnippet"] = combined_evidence

        return matches, alert
