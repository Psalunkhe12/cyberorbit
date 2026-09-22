# 🛡️ CyberOrbit SOC Command

<div align="center">

[![React](https://img.shields.io/badge/React-19.0-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-3178C6?logo=typescript&logoColor=white)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-6.2-646CFF?logo=vite&logoColor=white)](https://vitejs.dev/)
[![TailwindCSS](https://img.shields.io/badge/TailwindCSS-v4-06B6D4?logo=tailwindcss&logoColor=white)](https://tailwindcss.com/)
[![Google Gemini](https://img.shields.io/badge/Google%20Gemini-3.6%20Flash-4285F4?logo=google&logoColor=white)](https://ai.google.dev/)
[![Express](https://img.shields.io/badge/Express-4.21-000000?logo=express&logoColor=white)](https://expressjs.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Next-Gen Autonomous Security Operations Center (SOC) Command & AI Incident Response Platform**

</div>

---

## 📌 Overview

**CyberOrbit SOC Command** is a modern, high-performance Security Operations Center dashboard engineered for security engineers, incident responders, and SecOps teams. 

Integrating real-time network telemetry, autonomous attack simulation, and the **Google Gemini AI (3.6 Flash)** model, CyberOrbit transforms raw packet streams into actionable security intelligence, automated firewall rules, and interactive attack replays.

---

## 🚀 Key Features

- **🤖 Orbit AI Copilot (`/api/copilot`)**: Embedded SecOps AI copilot capable of triaging active incidents, analyzing network payloads, recommending containment playbooks, and drafting firewall ACL rules in real-time.
- **⚡ Synthetic Attack Simulation (`/api/simulate-attack`)**: Generates realistic, multi-stage cyber attack scenarios (DDoS SYN floods, credential stuffing, NTP amplification, SQLi probes) with live vector telemetry and risk scoring.
- **🔍 Deep Anomaly Packet Analyzer (`/api/analyze-packet`)**: Automated payload inspection and threat correlation engine providing instant risk assessments and step-by-step mitigation paths.
- **🛰️ Live Traffic & Velocity Monitoring**: Real-time bandwidth telemetry, protocol distribution, and anomaly detection across edge proxies and security gateways.
- **🔄 Interactive Attack Replay**: Step-by-step forensic reconstruction of detected security events with chronological progression and remediation tracking.
- **🛡️ Dynamic Rules & WAF Engine**: Active management of firewall rules, rate limits, IP blocklists, and BGP Flowspec filters with single-click activation.
- **📊 Threat Vector Radar & Metrics**: Real-time visual metrics for system security posture, MTTR, MTTD, and cross-border threat trajectories.

---

## 🏗️ Architecture & Tech Stack

### Frontend
- **React 19** + **TypeScript** — Component architecture and type safety
- **Tailwind CSS v4** — High-performance styling and dark-mode aesthetic
- **Motion (Framer Motion)** — Micro-interactions, animated telemetry, and transitions
- **Recharts** — Network velocity charts and threat distribution visualizations
- **Lucide React** — Crisp security and system iconography

### Backend
- **Express.js** — Lightweight API server for AI endpoints and asset serving
- **Vite (Middleware Mode)** — Lightning-fast HMR in development and optimized production bundling
- **Google GenAI SDK (`@google/genai`)** — Integration with Gemini 3.6 Flash for intelligent threat reasoning

---

## 📂 Project Structure

```text
cyberorbit-soc-command/
├── assets/                  # Static assets and media
├── src/
│   ├── components/          # Reusable UI components
│   │   ├── MetricsBar.tsx          # Key SOC metrics & posture KPIs
│   │   ├── OrbitCopilotCard.tsx    # Floating Gemini AI copilot interface
│   │   ├── PriorityTriageStream.tsx# Live alert triage stream
│   │   ├── RoleSwitcherModal.tsx   # Tier-1 / Tier-2 / Lead analyst switcher
│   │   ├── Sidebar.tsx             # Primary navigation dock
│   │   ├── ThreatVectorRadar.tsx   # Visual threat radar
│   │   ├── TopHeader.tsx           # Global header with status indicators
│   │   └── TrafficVelocityCard.tsx # Ingress/Egress throughput monitor
│   ├── data/
│   │   └── mockData.ts      # Default telemetry fixtures & mock streams
│   ├── views/               # Primary application modules
│   │   ├── AlertsConsoleView.tsx   # Full-screen alert management
│   │   ├── AttackReplayView.tsx    # Forensic event timeline & replay
│   │   ├── LiveTrafficView.tsx     # Deep packet & gateway traffic inspector
│   │   ├── OverviewView.tsx        # Command center master dashboard
│   │   ├── ReportsView.tsx         # Executive security summary reports
│   │   ├── RulesEngineView.tsx     # Firewall & WAF policy manager
│   │   └── ThreatIntelView.tsx     # IOC & threat feed intelligence
│   ├── types.ts             # Global TypeScript interface definitions
│   ├── index.css            # Global CSS styles and Tailwind imports
│   ├── App.tsx              # Main dashboard view container & state coordinator
│   └── main.tsx             # React entry point
├── server.ts                # Express backend & Gemini AI API routes
├── vite.config.ts           # Vite configuration
├── tsconfig.json            # TypeScript compiler configuration
├── .env.example             # Template for required environment variables
├── .gitignore               # Ignored files (node_modules, dist, secrets)
└── package.json             # Dependencies and build scripts
```

---

## ⚡ Getting Started

### 1. Prerequisites
- **Node.js**: `v18.0.0` or higher
- **npm** (or **bun** / **yarn** / **pnpm**)
- **Gemini API Key**: Obtainable from [Google AI Studio](https://aistudio.google.com/) *(optional; demo fallback mode is supported if no key is provided)*

### 2. Clone Repository
```bash
git clone https://github.com/<your-username>/cyberorbit-soc-command.git
cd cyberorbit-soc-command
```

### 3. Install Dependencies
```bash
npm install
```

### 4. Configure Environment Variables
Create a `.env` or `.env.local` file by copying the example:
```bash
cp .env.example .env.local
```
Add your Gemini API key:
```env
GEMINI_API_KEY="your-gemini-api-key-here"
```

### 5. Start the Development Server
```bash
npm run dev
```
Open your browser at `http://localhost:3000` to interact with the command center.

---

## 🛠️ Available Scripts

| Command | Action |
| :--- | :--- |
| `npm run dev` | Starts the Express server with Vite middleware in development mode |
| `npm run build` | Compiles client assets (`vite build`) and bundles server (`esbuild`) into `dist/` |
| `npm start` | Runs the compiled production server from `dist/server.cjs` |
| `npm run lint` | Runs `tsc --noEmit` to validate all TypeScript types |

---

## 🔌 API Endpoints

| Route | Method | Description |
| :--- | :--- | :--- |
| `/api/copilot` | `POST` | Interacts with Orbit AI (Gemini 3.6 Flash) with context-aware SOC system prompts |
| `/api/simulate-attack` | `POST` | Synthesizes complex multi-vector cyber attack scenarios and telemetry |
| `/api/analyze-packet` | `POST` | Deep payload and IOC analysis for detected anomaly events |

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
