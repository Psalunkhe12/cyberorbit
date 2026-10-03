# CyberOrbit AI-Powered Mini-SOC Engine Backend

CyberOrbit backend is a modular, high-performance Security Operations Center (SOC) telemetry processing and threat detection engine designed to integrate Suricata IDS/IPS, Machine Learning zero-day anomaly detection, rule matching, risk scoring, correlation, and Google Gemini AI incident triage.

---

## 🏗️ Architecture & Module Directory

```
backend/
├── collector/          # Suricata EVE log collector & PCAP ingestion engine
│   ├── __init__.py
│   └── suricata_collector.py
├── normalizer/         # Telemetry parser & SOC AnomalyEvent standardizer
│   ├── __init__.py
│   └── normalizer.py
├── detection/          # Multi-layer detection suite
│   ├── __init__.py
│   ├── engine.py       # Core orchestration & Supabase sync engine
│   ├── rules.py        # WAF & Network signature rules engine
│   ├── scoring.py      # Composite CVSS/Asset risk scoring algorithm
│   └── correlation.py  # Multi-stage attack campaign correlation
├── ml/                 # Machine Learning pipeline
│   ├── __init__.py
│   ├── features.py     # Flow telemetry feature engineering & entropy calculator
│   ├── train.py        # IsolationForest model training pipeline
│   └── detector.py     # Zero-day network anomaly detector
├── ai/                 # AI Copilot & Triage
│   ├── __init__.py
│   └── gemini.py       # Google Gemini 3.6 Flash Orbit AI integration
├── response/           # Automated Incident Response
│   ├── __init__.py
│   └── actions.py      # Containment policies, iptables bans & Suricata drop rules
├── config/             # Environment & path configuration
│   └── settings.py
├── requirements.txt    # Python dependencies
└── README.md           # Backend documentation
```

---

## 🚀 Key Modules & Capabilities

### 1. Collector (`collector/suricata_collector.py`)
- Reads and streams Suricata `eve.json` events in real-time or tail mode.
- Supports PCAP file execution via WSL Suricata engine (`suricata -r <pcap> -l <out>`).

### 2. Normalizer (`normalizer/normalizer.py`)
- Standardizes raw Suricata alerts, flows, HTTP requests, and DNS events into `NormalizedEvent` structures matching CyberOrbit frontend TypeScript interfaces.
- Resolves asset names (`auth-gateway-01`, `db-cluster-primary`) and GeoIP origins.

### 3. Detection Suite (`detection/`)
- **Signature Rules (`rules.py`)**: Checks payloads against SQL Injection, XSS, RCE, SYN Flood, and scanner signatures.
- **Risk Scoring (`scoring.py`)**: Computes composite risk score (0-100) based on severity, asset criticality multiplier, confidence, and rule hits.
- **Event Correlation (`correlation.py`)**: Correlates events by source IP or target asset to detect multi-stage attack campaigns.
- **Master Engine (`engine.py`)**: Orchestrates detection pipeline and syncs alerts to Supabase `alerts` table.

### 4. Machine Learning Engine (`ml/`)
- Extracts 8-dimensional flow feature vectors (packet rates, byte sizes, port codes, payload entropy).
- Fits `IsolationForest` to detect zero-day anomalies and traffic spikes.

### 5. Orbit AI Copilot (`ai/gemini.py`)
- Powered by `google-genai` and Gemini 3.6 Flash.
- Produces executive incident briefings, deep packet payload triage, and containment action plans.

### 6. Automated Response (`response/actions.py`)
- Simulates or executes system containment policies: IP blocking via `iptables`, Suricata drop rule generation, and Supabase alert status updates (`MITIGATED`, `CONFIRMED`).

---

## ⚙️ Installation & Usage

### 1. Install Dependencies
```bash
pip install -r backend/requirements.txt
```

### 2. Set Up Environment Variables
Ensure `.env` in the root directory contains:
```env
VITE_SUPABASE_URL="https://your-supabase-project.supabase.co"
VITE_SUPABASE_ANON_KEY="your-supabase-anon-key"
GEMINI_API_KEY="your-gemini-api-key"
```

### 3. Run Detection Engine
```bash
python -m backend.detection.engine
```

### 4. Train ML Model
```bash
python -m backend.ml.train
```

---

## 🔒 Security & Standards Compliance
- Adheres to standard SOC incident response protocols (NIST SP 800-61).
- Non-destructive execution: Default firewall actions run in SIMULATED mode.
