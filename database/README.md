# CyberOrbit Supabase Database Setup & Migration Guide

This directory contains the database schema migrations for the **CyberOrbit AI-Powered Mini-SOC** platform.

---

## 📋 Database Tables Overview

| Table Name | Description | Key Indexes & Features |
| :--- | :--- | :--- |
| `alerts` | Stores normalized security anomalies and triage status | Severity, Status, DetectedAt DESC |
| `network_events` | Raw & processed Suricata flow/packet telemetry | SrcIP, DestIP, Timestamp DESC |
| `traffic_metrics` | Aggregate throughput & connection stats | Timestamp DESC |
| `security_rules` | Dynamic WAF and SOC mitigation rules | Category, Status, Rule Code UNIQUE |
| `incidents` | Correlated security incident tickets | FK to `alerts`, Severity, Status |
| `ai_analyses` | Orbit AI Copilot analysis results & briefings | FK to `incidents` & `alerts` |
| `threat_indicators` | Geolocation attack vectors & risk scores | Risk Score DESC, Origin |
| `response_actions` | Automated mitigation audit trail (iptables/WAF) | Action Type, Target |
| `audit_logs` | System audit trail for operator actions | CreatedAt DESC |
| `notifications` | Live SOC alert notifications | IsRead status |

---

## 🛠️ Step-by-Step Instructions: Apply Migration in Supabase

1. **Log in to Supabase Console**:
   Go to [https://supabase.com/dashboard](https://supabase.com/dashboard) and select your CyberOrbit project.

2. **Open SQL Editor**:
   In the left sidebar menu, click on **SQL Editor** (the `>_` icon).

3. **Create a New Query**:
   Click **+ New Query** at the top.

4. **Paste Migration Script**:
   Copy the entire contents of [`database/migrations/001_security_monitoring.sql`](file:///d:/PROJECTS/final%20year%20project/cyberorbit/database/migrations/001_security_monitoring.sql) and paste it into the query editor.

5. **Execute Script**:
   Click the green **Run** button (or press `Ctrl + Enter` / `Cmd + Enter`).

6. **Verify Table Creation**:
   Go to **Table Editor** in the left sidebar to confirm that all 10 tables (`alerts`, `network_events`, `traffic_metrics`, `security_rules`, `incidents`, `ai_analyses`, `threat_indicators`, `response_actions`, `audit_logs`, `notifications`) are visible with RLS enabled.

---

## 🔒 Security Best Practices & RLS Guidance

- **Frontend Client Key Safety**: Only expose `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` to the browser (`.env`). **NEVER** expose `SUPABASE_SERVICE_ROLE_KEY` in frontend code or commit it to version control.
- **Row Level Security (RLS)**: RLS is enabled on all 10 tables by default in `001_security_monitoring.sql`.
- **Backend Admin Access**: High-privilege writes or automated system response logging from `backend/` should use `SUPABASE_SERVICE_ROLE_KEY` via server-side environment variables.
