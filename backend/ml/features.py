import math
from typing import Dict, Any, List, Optional


FEATURE_NAMES = [
    "packets_per_second",
    "bytes_per_second",
    "connection_duration",
    "destination_port",
    "unique_destination_count",
    "failed_connection_count",
    "dns_request_count",
]


class FeatureExtractor:
    """
    CyberOrbit Network Telemetry Feature Extractor.
    Extracts the 7 core numerical features for Isolation Forest Anomaly Detection:
    1. packets_per_second
    2. bytes_per_second
    3. connection_duration
    4. destination_port
    5. unique_destination_count
    6. failed_connection_count
    7. dns_request_count
    """

    @classmethod
    def extract_features(
        cls,
        event: Dict[str, Any],
        context_stats: Optional[Dict[str, Any]] = None,
    ) -> List[float]:
        """
        Extracts a 7-dimensional feature vector from a canonical or raw telemetry event.
        Handles missing or null values safely.
        """
        ctx = context_stats or {}
        raw_event = event.get("raw_event") if isinstance(event.get("raw_event"), dict) else {}
        flow = raw_event.get("flow", {}) if isinstance(raw_event.get("flow"), dict) else {}

        # 1. Connection Duration (seconds)
        duration = float(
            event.get("duration")
            or flow.get("age")
            or raw_event.get("duration")
            or 0.0
        )
        duration = max(0.0, duration)

        # 2. Packets per second & Bytes per second
        pkts_in = float(event.get("packets_in") or flow.get("pkts_toserver") or 0.0)
        pkts_out = float(event.get("packets_out") or flow.get("pkts_toclient") or 0.0)
        total_packets = pkts_in + pkts_out

        bytes_in = float(event.get("bytes_in") or flow.get("bytes_toserver") or 0.0)
        bytes_out = float(event.get("bytes_out") or flow.get("bytes_toclient") or 0.0)
        total_bytes = bytes_in + bytes_out

        time_divisor = duration if duration > 0 else 1.0
        packets_per_second = total_packets / time_divisor
        bytes_per_second = total_bytes / time_divisor

        # 3. Destination Port
        dest_port_val = (
            event.get("destination_port")
            or event.get("dest_port")
            or raw_event.get("dest_port")
            or 0
        )
        try:
            destination_port = float(dest_port_val)
        except (ValueError, TypeError):
            destination_port = 0.0

        # 4. Unique Destination Count (from context or event)
        unique_dest_cnt = float(
            ctx.get("unique_destination_count")
            or event.get("unique_destination_count")
            or 1.0
        )

        # 5. Failed Connection Count (from context or event indicators)
        failed_cnt = float(
            ctx.get("failed_connection_count")
            or event.get("failed_connection_count")
            or 0.0
        )
        if failed_cnt == 0.0:
            app_str = str(event.get("application") or "").lower()
            evt_type = str(event.get("event_type") or "").lower()
            payload = str(raw_event).lower()
            if (
                "401" in app_str
                or "403" in app_str
                or "500" in app_str
                or "failed" in payload
                or "reset" in payload
                or evt_type == "reject"
            ):
                failed_cnt = 1.0

        # 6. DNS Request Count
        dns_cnt = float(
            ctx.get("dns_request_count")
            or event.get("dns_request_count")
            or 0.0
        )
        if dns_cnt == 0.0:
            if "dns" in raw_event or "dns" in str(event.get("application") or "").lower():
                dns_cnt = 1.0

        return [
            packets_per_second,
            bytes_per_second,
            duration,
            destination_port,
            unique_dest_cnt,
            failed_cnt,
            dns_cnt,
        ]

    @classmethod
    def extract_features_dict(
        cls,
        event: Dict[str, Any],
        context_stats: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, float]:
        """
        Returns extracted features as a dictionary mapping feature name -> float.
        """
        vector = cls.extract_features(event, context_stats=context_stats)
        return dict(zip(FEATURE_NAMES, vector))

    @classmethod
    def extract_batch(
        cls,
        events: List[Dict[str, Any]],
        context_stats: Optional[Dict[str, Any]] = None,
    ) -> List[List[float]]:
        """
        Extracts feature vectors for a list of telemetry events.
        """
        return [cls.extract_features(e, context_stats=context_stats) for e in events]
