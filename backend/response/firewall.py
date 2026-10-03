"""
CyberOrbit Firewall Abstraction Layer
-------------------------------------
Provides an abstract base class (FirewallAdapter) and concrete adapters for network security actions:
- BLOCK_IP
- UNBLOCK_IP
- ISOLATE_HOST
- MONITOR_HOST

Safety Guarantee:
Defaults to SimulatedFirewallAdapter.
Does NOT modify the real operating-system firewall unless a real firewall adapter is explicitly registered.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Dict, Any, Optional


class FirewallAdapter(ABC):
    """
    Abstract Base Class / Provider Interface for Firewall Integrations.
    Allows real firewall integration (e.g. iptables, UFW, AWS Security Groups, Cloudflare API)
    to be plugged in without modifying core SOC response orchestrators.
    """

    @property
    @abstractmethod
    def adapter_name(self) -> str:
        pass

    @abstractmethod
    def block_ip(self, ip_address: str, duration_minutes: int = 60) -> Dict[str, Any]:
        pass

    @abstractmethod
    def unblock_ip(self, ip_address: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def isolate_host(self, host_identifier: str) -> Dict[str, Any]:
        pass

    @abstractmethod
    def monitor_host(self, host_identifier: str) -> Dict[str, Any]:
        pass


class SimulatedFirewallAdapter(FirewallAdapter):
    """
    Simulated Firewall Adapter (Default).
    Generates simulated CLI command strings and execution results without touching real OS network interfaces.
    """

    @property
    def adapter_name(self) -> str:
        return "SimulatedFirewallAdapter"

    def block_ip(self, ip_address: str, duration_minutes: int = 60) -> Dict[str, Any]:
        command = f"iptables -A INPUT -s {ip_address} -j DROP"
        timestamp = datetime.now(timezone.utc).isoformat()
        return {
            "action": "BLOCK_IP",
            "target": ip_address,
            "status": "SIMULATED",
            "command_executed": f"[SIMULATED] {command}",
            "timestamp": timestamp,
            "details": f"Simulated blocking of IP {ip_address} for {duration_minutes} minutes via edge firewall rule.",
            "adapter": self.adapter_name,
        }

    def unblock_ip(self, ip_address: str) -> Dict[str, Any]:
        command = f"iptables -D INPUT -s {ip_address} -j DROP"
        timestamp = datetime.now(timezone.utc).isoformat()
        return {
            "action": "UNBLOCK_IP",
            "target": ip_address,
            "status": "SIMULATED",
            "command_executed": f"[SIMULATED] {command}",
            "timestamp": timestamp,
            "details": f"Simulated unblocking of IP {ip_address} from edge firewall rules.",
            "adapter": self.adapter_name,
        }

    def isolate_host(self, host_identifier: str) -> Dict[str, Any]:
        command = f"network-cli host isolate --target={host_identifier} --policy=quarantine-vlan"
        timestamp = datetime.now(timezone.utc).isoformat()
        return {
            "action": "ISOLATE_HOST",
            "target": host_identifier,
            "status": "SIMULATED",
            "command_executed": f"[SIMULATED] {command}",
            "timestamp": timestamp,
            "details": f"Simulated quarantining of host {host_identifier} into isolated VLAN segment.",
            "adapter": self.adapter_name,
        }

    def monitor_host(self, host_identifier: str) -> Dict[str, Any]:
        command = f"tcpdump -i any host {host_identifier} -w /var/log/cyberorbit/monitor-{host_identifier}.pcap"
        timestamp = datetime.now(timezone.utc).isoformat()
        return {
            "action": "MONITOR_HOST",
            "target": host_identifier,
            "status": "SIMULATED",
            "command_executed": f"[SIMULATED] {command}",
            "timestamp": timestamp,
            "details": f"Simulated deep packet capture stream initiated for host {host_identifier}.",
            "adapter": self.adapter_name,
        }
