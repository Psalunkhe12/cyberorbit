# CyberOrbit Zeek Log Ingestion & Normalization

This document details the Zeek security telemetry ingestion pipeline, log format specifications, schema normalization, deduplication mechanism, and exact runnable CLI commands.

---

## 1. Supported Zeek Log Types & Formats

The `ZeekCollector` ([`backend/collector/zeek_collector.py`](file:///d:/PROJECTS/final%20year%20project/cyberorbit/backend/collector/zeek_collector.py)) reads and parses both **Tab-Separated Zeek TSV logs** (`#fields`) and **Zeek JSON logs** (`Log::writer_json`).

### Supported Log Files:
- `conn.log`: Network connection state, IP endpoints, protocol, flow bytes/packets, duration.
- `dns.log`: DNS query names, query types (`A`, `AAAA`, `PTR`), response codes.
- `http.log`: Web traffic requests, HTTP method (`GET`, `POST`), host, URIs, user agents.
- `ssl.log`: TLS handshake SNI server names, SSL versions, certificates.
- `notice.log` (when available): Zeek detection notices and policy alerts.

---

## 2. Ingestion Pipeline & Normalization

```
+------------------+     +-------------------+     +---------------------+     +--------------------+
| Zeek Log Files   | --> | ZeekCollector     | --> | EventNormalizer     | --> | Supabase DB        |
| (conn, dns,      |     | (TSV/JSON Parser &|     | (normalize_zeek_    |     | (network_events    |
|  http, ssl, etc.)|     |  Deduplication)   |     |  event -> Schema)   |     |  Table Insertion)  |
+------------------+     +-------------------+     +---------------------+     +--------------------+
```

1. **Parser**: Dynamically parses header rows (`#fields`, `#path`) or structured JSON objects.
2. **Normalizer**: Transforms raw telemetry through [`backend/normalizer/normalizer.py`](file:///d:/PROJECTS/final%20year%20project/cyberorbit/backend/normalizer/normalizer.py) (`normalize_zeek_event`) into the canonical CyberOrbit schema (`source_ip`, `destination_ip`, `bytes_in`, `packets_out`, `application`, `raw_event`).
3. **Deduplication**: Computes SHA-256 event fingerprints to guarantee zero duplicate record insertions.
4. **Database Sync**: Inserts normalized events into Supabase `public.network_events` table.

---

## 3. Exact Execution Commands

### A. One-Time Ingestion Mode (`--once`)
Processes all existing Zeek log files in the target directory once and exits immediately.

```bash
# Process default directory (security-data/zeek-output/)
python -m backend.collector.zeek_collector --once
```

With a custom directory path:
```bash
python -m backend.collector.zeek_collector --once --dir security-data/zeek-output
```

Via WSL / Linux environment:
```bash
wsl python3 -m backend.collector.zeek_collector --once --dir security-data/zeek-output
```

---

### B. Continuous Directory Watch Mode (`--watch`)
Monitors the Zeek log directory continuously, tailing new appended log lines in real time using byte-offset tracking.

```bash
# Watch default directory
python -m backend.collector.zeek_collector --watch
```

With a custom log directory path:
```bash
python -m backend.collector.zeek_collector --watch --dir /var/log/zeek/current
```

Via WSL:
```bash
wsl python3 -m backend.collector.zeek_collector --watch --dir security-data/zeek-output
```

---

## 4. Running Unit Tests

Run the complete Zeek collector unit test suite:

```bash
# Run Zeek collector unit tests
wsl python3 -m unittest backend/collector/test_zeek_collector.py
```

Run the entire backend test suite (Collectors, Detection Engine, Normalizer, ML Module, Scoring):

```bash
wsl python3 -m unittest backend/collector/test_zeek_collector.py backend/ml/test_ml.py backend/detection/test_correlation.py backend/detection/test_scoring.py backend/detection/test_detection.py backend/normalizer/test_normalizer.py
```
