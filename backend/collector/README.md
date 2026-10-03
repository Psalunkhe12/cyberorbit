# CyberOrbit Log Collectors & Telemetry Ingestion Pipeline

CyberOrbit includes high-performance collectors for **Zeek Log Ingestion** (`backend/collector/zeek_collector.py`) and **Suricata EVE Ingestion** (`backend/collector/suricata_collector.py`). They parse, normalize, deduplicate, and ingest network security events into Supabase database tables (`network_events`, `alerts`, `traffic_metrics`).

---

## 1. Zeek Log Collector (`backend/collector/zeek_collector.py`)

### 🌟 Key Features
- **Supported Zeek Logs**: `conn.log`, `dns.log`, `http.log`, `ssl.log`, `notice.log`.
- **Dual Log Format Support**: Automatically parses both standard Zeek Tab-Separated Values (TSV `#fields`) and modern Zeek JSON line files.
- **Normalizer Integration**: Passes all raw Zeek events through `backend/normalizer/normalizer.py` to produce standardized CyberOrbit `network_events`.
- **Deduplication Engine**: Uses SHA-256 event fingerprinting to prevent inserting duplicate log entries into Supabase.
- **Execution Modes**: `--once` (single pass batch process) and `--watch` (continuous directory monitoring).

### 🚀 Zeek Ingestion Commands

#### Single Test / Batch Run (`--once`)
Processes all existing Zeek log files in the target directory once and inserts normalized events into Supabase `network_events`:
```bash
# Default directory (security-data/zeek-output)
python -m backend.collector.zeek_collector --once

# Specify custom Zeek log directory
python -m backend.collector.zeek_collector --dir security-data/zeek-output --once
```

#### Live Continuous Monitoring (`--watch`)
Monitors the Zeek output directory for newly appended log entries:
```bash
python -m backend.collector.zeek_collector --watch

# Custom directory watch mode
python -m backend.collector.zeek_collector --dir /var/log/zeek/current --watch
```

#### Run inside WSL / Ubuntu
```bash
wsl python3 -m backend.collector.zeek_collector --once
wsl python3 -m backend.collector.zeek_collector --watch
```

---

## 2. Suricata Collector (`backend/collector/suricata_collector.py`)

### 🌟 Key Features
- **Supported Events**: `alert`, `flow`, `dns`, `http`, `tls`, and `stats`.
- **Deduplication Engine**: Generates deterministic SHA256 event UUIDs to prevent inserting duplicate records.
- **Target Tables**: Ingests into `alerts`, `network_events`, and `traffic_metrics`.

### 🚀 Suricata Ingestion Commands

```bash
# Single pass run
python -m backend.collector.suricata_collector --once

# Live continuous tailing
python -m backend.collector.suricata_collector --watch

# WSL execution
wsl python3 -m backend.collector.suricata_collector --watch
```

---

## ⚙️ Environment Configuration

Set the following environment variables in `.env`:

```env
# Supabase Database Connection
SUPABASE_URL="https://your-supabase-project.supabase.co"
SUPABASE_KEY="your-supabase-service-role-key-or-anon-key"

# Optional Custom Data Paths
EVE_JSON_PATH="security-data/suricata-output/eve.json"
```

---

## 📊 Zeek Data Field Mapping (`public.network_events`)

| Zeek Log Type | Event Type | Application Mapping | Key Fields Mapped |
| :--- | :--- | :--- | :--- |
| `conn.log` | `connection` | Protocol / Service name | `source_ip`, `source_port`, `destination_ip`, `destination_port`, `bytes_in`, `bytes_out`, `packets_in`, `packets_out`, `duration` |
| `dns.log` | `dns` | `DNS <qtype> <query>` | Query name, Record type, Answers, Response codes |
| `http.log` | `http` | `<method> <host> <uri>` | User agent, Status code, Request/Response body bytes |
| `ssl.log` | `ssl` / `tls` | `TLS SNI: <server_name>` | Cipher, Version, Issuer, Subject, SNI |
| `notice.log` | `alert` / `notice` | `Zeek Notice: <note>` | Action, Msg, Sub-note, Peer ID |
