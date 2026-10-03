import os
import sys
import json
import time
import hashlib
import argparse
from pathlib import Path
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional, Set, Tuple

from backend.normalizer.normalizer import normalize_zeek_event
from backend.config.settings import settings

try:
    from supabase import create_client, Client
except ImportError:
    create_client = None
    Client = Any

SUPPORTED_ZEEK_LOGS = ["conn.log", "dns.log", "http.log", "ssl.log", "notice.log"]


class ZeekCollector:
    """
    CyberOrbit Zeek Log Ingestion Collector.
    Reads, parses, normalizes, deduplicates, and ingests Zeek log files into
    the Supabase `network_events` database table.

    Supports:
    - Log types: conn.log, dns.log, http.log, ssl.log, notice.log
    - Log formats: Tab-Separated Zeek TSV (#fields) and JSON lines
    - Execution modes: --once and --watch
    - Duplicate prevention via event fingerprinting
    """

    def __init__(self, log_dir: Optional[Path] = None):
        self.log_dir = Path(log_dir) if log_dir else settings.SECURITY_DATA_DIR / "zeek-output"
        self.ingested_hashes: Set[str] = set()
        self.file_offsets: Dict[str, int] = {}
        self.supabase_client: Optional[Client] = None

        if getattr(settings, "SUPABASE_URL", None) and getattr(settings, "SUPABASE_KEY", None) and create_client:
            try:
                self.supabase_client = create_client(settings.SUPABASE_URL, settings.SUPABASE_KEY)
                print("[ZeekCollector] Supabase client initialized successfully.")
            except Exception as err:
                print(f"[ZeekCollector Warning] Supabase client initialization failed: {err}")

    def compute_fingerprint(self, norm_event: Dict[str, Any]) -> str:
        """Computes a SHA-256 fingerprint for deduplication."""
        raw = norm_event.get("raw_event") if isinstance(norm_event.get("raw_event"), dict) else {}
        uid = str(raw.get("uid") or "")
        key = (
            f"{norm_event.get('source_ip')}:{norm_event.get('source_port')}->"
            f"{norm_event.get('destination_ip')}:{norm_event.get('destination_port')}:"
            f"{norm_event.get('timestamp')}:{norm_event.get('protocol')}:"
            f"{norm_event.get('event_type')}:{uid}"
        )
        return hashlib.sha256(key.encode()).hexdigest()

    def parse_zeek_line(self, line: str, fields: List[str], log_path_header: str) -> Optional[Dict[str, Any]]:
        """Parses a single line of Zeek log (TSV or JSON format)."""
        line_str = line.strip()
        if not line_str or line_str.startswith("#"):
            return None

        # Format 1: JSON line
        if line_str.startswith("{") and line_str.endswith("}"):
            try:
                data = json.loads(line_str)
                if "_path" not in data:
                    data["_path"] = log_path_header
                return data
            except json.JSONDecodeError:
                return None

        # Format 2: TSV line
        if not fields:
            return None

        parts = line_str.split("\t")
        if len(parts) != len(fields):
            # Mismatch in field count
            return None

        record: Dict[str, Any] = {}
        for name, val in zip(fields, parts):
            if val in ("-", "(empty)"):
                record[name] = None
            else:
                # Try to parse numeric floats/ints
                if val.isdigit():
                    record[name] = int(val)
                else:
                    try:
                        record[name] = float(val) if "." in val else val
                    except ValueError:
                        record[name] = val

        record["_path"] = log_path_header
        return record

    def parse_zeek_file(self, file_path: Path, start_offset: int = 0) -> Tuple[List[Dict[str, Any]], int]:
        """
        Reads a Zeek log file starting from start_offset.
        Handles TSV headers (#separator, #fields, #path) and JSON lines.
        Returns Tuple[list_of_raw_events, new_offset].
        """
        if not file_path.exists():
            return [], start_offset

        fields: List[str] = []
        log_path_header = file_path.stem.replace(".log", "")
        raw_events: List[Dict[str, Any]] = []

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            header_offset = 0
            # Read line by line with readline() to accurately track file offsets
            while True:
                curr_pos = f.tell()
                line = f.readline()
                if not line:
                    break
                line_str = line.strip()
                if line_str.startswith("#path"):
                    parts = line_str.split("\t")
                    if len(parts) >= 2:
                        log_path_header = parts[1]
                elif line_str.startswith("#fields"):
                    fields = line_str.split("\t")[1:]
                elif not line_str.startswith("#"):
                    header_offset = curr_pos
                    break

            # Seek to start_offset or end of headers
            actual_offset = max(start_offset, header_offset if start_offset == 0 else start_offset)
            f.seek(actual_offset)

            while True:
                line = f.readline()
                if not line:
                    break
                parsed = self.parse_zeek_line(line, fields, log_path_header)
                if parsed:
                    raw_events.append(parsed)

            new_offset = f.tell()

        return raw_events, new_offset


    def process_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """
        Processes a single Zeek log file, extracting and normalizing events,
        deduplicating, and updating offsets.
        """
        path_str = str(file_path.resolve())
        start_offset = self.file_offsets.get(path_str, 0)
        raw_events, new_offset = self.parse_zeek_file(file_path, start_offset=start_offset)
        self.file_offsets[path_str] = new_offset

        normalized_list: List[Dict[str, Any]] = []
        for raw in raw_events:
            norm = normalize_zeek_event(raw)
            if not norm or not norm.get("source_ip"):
                continue

            fp = self.compute_fingerprint(norm)
            if fp in self.ingested_hashes:
                continue

            self.ingested_hashes.add(fp)
            normalized_list.append(norm)

        return normalized_list


    def run_once(self) -> List[Dict[str, Any]]:
        """
        --once mode execution: processes all existing supported Zeek log files once.
        Inserts normalized events to Supabase network_events table.
        """
        all_normalized: List[Dict[str, Any]] = []
        if not self.log_dir.exists():
            print(f"[ZeekCollector Warning] Directory {self.log_dir} does not exist.")
            return []

        # Find supported log files + any .log files in log_dir
        log_files = []
        for name in SUPPORTED_ZEEK_LOGS:
            p = self.log_dir / name
            if p.exists():
                log_files.append(p)

        # Include subdirectories or additional .log files
        for p in self.log_dir.rglob("*.log"):
            if p not in log_files:
                log_files.append(p)

        for file_path in log_files:
            norm_events = self.process_file(file_path)
            if norm_events:
                print(f"[ZeekCollector] Processed {len(norm_events)} new normalized events from {file_path.name}")
                all_normalized.extend(norm_events)

        if all_normalized and self.supabase_client:
            self.sync_to_supabase(all_normalized)

        return all_normalized

    def watch(self, interval_seconds: int = 2):
        """
        --watch mode execution: continuously monitors Zeek log files for new appends.
        """
        print(f"[ZeekCollector] Watching directory {self.log_dir} for Zeek logs (interval={interval_seconds}s)...")
        try:
            while True:
                new_events = self.run_once()
                if new_events:
                    print(f"[ZeekCollector] Total {len(new_events)} new events ingested in this cycle.")
                time.sleep(interval_seconds)
        except KeyboardInterrupt:
            print("[ZeekCollector] Watch mode stopped by user.")

    def sync_to_supabase(self, events: List[Dict[str, Any]]) -> bool:
        """
        Inserts normalized Zeek events into Supabase `network_events` table.
        """
        if not self.supabase_client:
            return False
        try:
            db_records = []
            for ev in events:
                db_records.append({
                    "timestamp": ev.get("timestamp") or datetime.now(timezone.utc).isoformat(),
                    "source_ip": ev.get("source_ip"),
                    "source_port": ev.get("source_port"),
                    "destination_ip": ev.get("destination_ip"),
                    "destination_port": ev.get("destination_port"),
                    "protocol": ev.get("protocol"),
                    "event_type": ev.get("event_type"),
                    "bytes_in": ev.get("bytes_in", 0),
                    "bytes_out": ev.get("bytes_out", 0),
                    "packets_in": ev.get("packets_in", 0),
                    "packets_out": ev.get("packets_out", 0),
                    "duration": ev.get("duration"),
                    "application": ev.get("application"),
                    "source": "zeek",
                    "raw_event": ev.get("raw_event", {}),
                })

            self.supabase_client.from_("network_events").insert(db_records).execute()
            print(f"[ZeekCollector] Inserted {len(db_records)} normalized records into Supabase 'network_events' table.")
            return True
        except Exception as err:
            print(f"[ZeekCollector Error] Supabase insert failed: {err}")
            return False


def main():
    parser = argparse.ArgumentParser(description="CyberOrbit Zeek Log Collector & Ingestion Tool")
    parser.add_argument("--dir", type=str, help="Directory containing Zeek log files")
    mode_group = parser.add_mutually_exclusive_group(required=False)
    mode_group.add_argument("--once", action="store_true", help="Process existing Zeek logs once and exit")
    mode_group.add_argument("--watch", action="store_true", help="Continuously watch directory for new Zeek events")
    args = parser.parse_args()

    target_dir = Path(args.dir) if args.dir else settings.SECURITY_DATA_DIR / "zeek-output"
    collector = ZeekCollector(log_dir=target_dir)

    if args.watch:
        collector.watch()
    else:
        # Default to --once execution
        collector.run_once()


if __name__ == "__main__":
    main()
