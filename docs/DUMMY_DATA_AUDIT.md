# CyberOrbit Dummy, Mock & Hardcoded Security Data Audit Report

## Executive Summary
This document records the comprehensive audit of dummy, mock, static, hardcoded, or randomly generated security data across the CyberOrbit repository. All production dashboard statistics, threat counts, traffic metrics, alert consoles, incident views, and chart components have been connected directly to real Supabase database tables (`network_events`, `traffic_metrics`, `alerts`, `incidents`, `security_rules`, `threat_indicators`). Isolated test fixtures required for unit tests (`pytest`) and offline dev fallbacks have been classified and preserved.

---

## Audit Matrix

| File | Line(s) | Classification | Old Source | New Source / Current Status | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `src/App.tsx` | 18 | Production Dashboard Data | Imported `INITIAL_TRAFFIC_DATA`, `INITIAL_ANOMALIES`, `INITIAL_RULES`, `INITIAL_THREAT_VECTOR` static mock arrays | Replaced with dynamic Supabase realtime hooks (`useRealtimeAlerts`, `useRealtimeNetworkEvents`, `useRealtimeRules`, `useRealtimeThreatIntel`) | **REPLACED** |
| `src/App.tsx` | 120-147 | Production Dashboard Data | `setInterval` loop with `Math.random()` producing synthetic traffic fluctuations | Replaced with dynamic computation from real Supabase `traffic_metrics` & `network_events` | **REPLACED** |
| `src/hooks/useRealtimeAlerts.ts` | 39, 67-72 | Production Dashboard Data | Default fallback to static mock `INITIAL_ANOMALIES` array | Default set to `[]`, populating exact database rows or displaying empty state | **REPLACED** |
| `src/hooks/useRealtimeIncidents.ts` | 172, 200 | Production Dashboard Data | Default fallback to static mock `INITIAL_MOCK_INCIDENTS` array | Default set to `[]`, populating exact Supabase `incidents` rows or empty state | **REPLACED** |
| `src/views/AttackReplayView.tsx` | 8-46, 103 | Production Dashboard Data | Hardcoded DDoS replay timeline phases, static IPs (`185.220.101.42`) and Gbps values | Connected to Supabase `useRealtimeIncidents` & `useRealtimeAlerts` with clean empty state card fallback | **REPLACED** |
| `src/views/LiveTrafficView.tsx` | 18-56 | Production Dashboard Data | Static network events array & hardcoded throughput values | Connected to real Supabase `network_events` and `traffic_metrics` queries with empty state card | **REPLACED** |
| `src/views/ThreatIntelView.tsx` | 12-48 | Production Dashboard Data | Static threat vector radar values | Connected to Supabase `threat_indicators` database query and realtime channel | **REPLACED** |
| `src/views/AlertsConsoleView.tsx` | 20-75 | Production Dashboard Data | Static alerts list rendering | Connected to Supabase `alerts` table query with empty state rendering | **REPLACED** |
| `src/views/IncidentsView.tsx` | 35-120 | Production Dashboard Data | Static incidents cards rendering | Connected to Supabase `incidents` table query with empty state rendering | **REPLACED** |
| `src/data/mockData.ts` | 3-196 | Test Fixture / Offline Dev | Production default data arrays for traffic, alerts, rules, vectors | Reclassified as isolated dev/test fixtures and role switcher operator profiles | **ISOLATED TEST FIXTURE** |
| `server.ts` | 89 | Dev Fallback / Simulation API | `Math.random()` in `/api/simulate-attack` fallback endpoint when Gemini key is omitted | Kept as controlled backend API simulation fallback when `GEMINI_API_KEY` is not present | **ISOLATED DEV FALLBACK** |
| `src/lib/auditLogger.ts` | 56 | Production Utility | `Math.random().toString(36)` used for generating client-side unique audit IDs | Production unique ID generation string prior to Supabase audit log persistence | **PRODUCTION UTILITY** |
| `backend/threat_intel/test_threat_intel.py` | 15-40 | Test Data | Hardcoded IP fixtures (`192.168.1.50`, `malicious-domain.test`) for unit testing matcher | Retained for `pytest` automated test suite execution | **KEPT TEST FIXTURE** |
| `backend/ai/test_gemini.py` | 10-35 | Test Data | Hardcoded sample alert dictionary for testing Gemini copilot response schema | Retained for automated python backend tests | **KEPT TEST FIXTURE** |
| `backend/ml/train.py` | 25-60 | Model Training Data | Synthetic sample dataset generation for ML benchmark training | Retained for baseline model training and model performance comparison | **KEPT MODEL BENCHMARK** |

---

## Detailed Classification Findings

### 1. Production Dashboard Data (Replaced with Supabase Queries)
All production views (`OverviewView`, `LiveTrafficView`, `ThreatIntelView`, `AlertsConsoleView`, `IncidentsView`, `RulesEngineView`, `AttackReplayView`) now pull live telemetry, metrics, alerts, incidents, rules, and threat indicators directly from Supabase database queries and realtime Postgres channels. When database tables are empty, appropriate empty state components are displayed without generating fake mock values.

### 2. Isolated Test Fixtures & Test Data (Preserved)
Backend test files (`backend/threat_intel/test_threat_intel.py`, `backend/ai/test_gemini.py`, `backend/ml/test_ml.py`) contain isolated test fixtures required to execute unit tests (`pytest`). These test fixtures remain isolated and have not been removed to ensure automated unit tests pass reliably.

### 3. Server-Side Simulation Endpoints (Preserved as Fallback)
The Express backend (`server.ts`) includes a `/api/simulate-attack` endpoint that invokes Gemini AI or provides a fallback simulation when triggered by an analyst. This endpoint is strictly analyst-triggered and does not inject fake data into production charts automatically.

---

## Verification
- Clean TypeScript compilation via `npx tsc --noEmit` (0 errors).
- All frontend hooks verify active Supabase client connection and subscribe to realtime Postgres channels.
