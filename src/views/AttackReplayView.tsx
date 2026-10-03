import React, { useState } from 'react';
import { RotateCcw, ShieldCheck, Zap, Server, Globe, ShieldAlert, AlertTriangle } from 'lucide-react';
import { useRealtimeIncidents } from '../hooks/useRealtimeIncidents';
import { useRealtimeAlerts } from '../hooks/useRealtimeAlerts';

export const AttackReplayView: React.FC = () => {
  const { incidents, loading: incidentsLoading } = useRealtimeIncidents();
  const { alerts, loading: alertsLoading } = useRealtimeAlerts();
  
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [timelineSec, setTimelineSec] = useState(30);

  const activeIncident = incidents.find((i) => i.id === selectedIncidentId) || incidents[0];

  // If loading
  if (incidentsLoading || alertsLoading) {
    return (
      <div className="bg-white rounded-[32px] p-12 border border-[#d4deda] text-center text-[#6c8582]">
        <RotateCcw className="w-8 h-8 animate-spin mx-auto mb-3 text-[#2d9d78]" />
        <p className="text-sm font-bold">Loading incident forensics & telemetry sequence...</p>
      </div>
    );
  }

  // Empty state when no incidents or alerts exist
  if (!activeIncident && alerts.length === 0) {
    return (
      <div className="flex flex-col gap-5">
        <div className="bg-white rounded-[32px] p-6 border border-[#d4deda] shadow-sm">
          <h2 className="font-display text-lg font-extrabold text-[#253835] mb-1 flex items-center gap-2 m-0">
            <RotateCcw className="w-5 h-5 text-[#d49b28]" />
            <span>Incident Forensics & Attack Sequence Replay</span>
          </h2>
          <p className="text-xs text-[#6c8582] m-0 mt-1">
            Scrub through historical attack telemetry to analyze vector propagation and response timelines.
          </p>
        </div>

        <div className="bg-white rounded-[32px] p-12 border border-[#d4deda] shadow-sm text-center">
          <ShieldCheck className="w-12 h-12 text-[#2d9d78] mx-auto mb-3 opacity-80" />
          <h3 className="font-display text-lg font-bold text-[#253835] mb-1">
            No Security Incidents Available for Replay
          </h3>
          <p className="text-xs text-[#6c8582] max-w-md mx-auto m-0">
            The database currently contains no active or recorded security incidents.
            Attack sequence replay will become available automatically when network telemetry triggers an incident.
          </p>
        </div>
      </div>
    );
  }

  // Derive replay phases based on the selected real database incident / alerts
  const incidentTitle = activeIncident?.title || 'Realtime Telemetry Sequence';
  const sourceIp = activeIncident?.source_ip || alerts[0]?.ip || '0.0.0.0';
  const targetAsset = activeIncident?.target_asset || alerts[0]?.asset || 'internal-network';
  const vector = activeIncident?.attack_vector || alerts[0]?.attackVector || 'Network Spike';
  const severity = activeIncident?.severity || alerts[0]?.severity || 'MEDIUM';

  const getPhaseInfo = (sec: number) => {
    if (sec < 15) {
      return {
        phase: `Phase 1: Initial Reconnaissance & ${vector} Signal`,
        status: 'INITIAL TELEMETRY',
        gbps: '0.45 Gbps',
        desc: `Observed initial traffic anomaly targeting asset ${targetAsset} from IP ${sourceIp}.`,
        mitigation: 'Ingestion scrubber logging incoming packet header flags.',
      };
    } else if (sec < 35) {
      return {
        phase: `Phase 2: Active ${vector} Escalation`,
        status: `${severity} SURGE DETECTED`,
        gbps: '2.80 Gbps',
        desc: `Surge in events from ${sourceIp}. Risk score reached ${activeIncident?.risk_score || 75}/100.`,
        mitigation: 'Automated firewall rule evaluation & rate limiter active.',
      };
    } else if (sec < 50) {
      return {
        phase: 'Phase 3: Automated Mitigation & Rule Execution',
        status: 'CONTAINMENT IN PROGRESS',
        gbps: '1.10 Gbps',
        desc: `Mitigation rule applied for target ${targetAsset}. Dropping malicious payload flows.`,
        mitigation: 'Quarantine state applied to suspicious source subnet.',
      };
    } else {
      return {
        phase: 'Phase 4: Post-Mitigation Telemetry Normalization',
        status: 'STABILIZED / REVIEWED',
        gbps: '0.20 Gbps',
        desc: `Threat vector neutralized. Asset ${targetAsset} returning to baseline throughput.`,
        mitigation: 'Audit log entry generated and analyst review pending.',
      };
    }
  };

  const currentPhase = getPhaseInfo(timelineSec);

  return (
    <div className="flex flex-col gap-5">
      {/* Top Banner */}
      <div className="bg-white rounded-[32px] p-6 border border-[#d4deda] shadow-sm flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h2 className="font-display text-lg font-extrabold text-[#253835] mb-1 flex items-center gap-2 m-0">
            <RotateCcw className="w-5 h-5 text-[#d49b28]" />
            <span>Incident Forensics & Attack Sequence Replay</span>
          </h2>
          <p className="text-xs text-[#6c8582] m-0 mt-1">
            Scrub through historical DDoS & intrusion telemetry to analyze vector propagation and mitigation response times.
          </p>
        </div>

        {incidents.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold text-[#6c8582]">Select Incident:</span>
            <select
              value={activeIncident?.id}
              onChange={(e) => setSelectedIncidentId(e.target.value)}
              className="bg-[#e8eceb] text-[#253835] font-mono-code text-xs font-bold px-3 py-1.5 rounded-xl border border-[#d4deda] focus:outline-none"
            >
              {incidents.map((inc) => (
                <option key={inc.id} value={inc.id}>
                  {inc.id} - {inc.title.slice(0, 30)}...
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Interactive Scrub Control */}
      <div className="bg-[#334d4a] text-white rounded-[32px] p-6 border border-white/10 shadow-xl">
        <div className="flex justify-between items-center mb-4">
          <div>
            <span className="text-[10px] font-bold text-[#d49b28] uppercase tracking-wider block">
              REPLAY TARGET: {activeIncident ? activeIncident.id : 'TELEMETRY STREAM'}
            </span>
            <h3 className="font-display text-xl font-bold text-white m-0">
              {currentPhase.phase}
            </h3>
          </div>
          <span className="text-xs font-mono-code bg-white/10 px-3 py-1 rounded-full text-[#d49b28] font-bold">
            T + {timelineSec} SECONDS
          </span>
        </div>

        {/* Timeline Slider */}
        <div className="my-6">
          <input
            type="range"
            min={0}
            max={60}
            value={timelineSec}
            onChange={(e) => setTimelineSec(Number(e.target.value))}
            className="w-full accent-[#d49b28] h-2 bg-white/20 rounded-lg cursor-pointer"
          />
          <div className="flex justify-between text-[10px] font-mono-code text-white/60 mt-2">
            <span>T+0s (Recon)</span>
            <span>T+15s (Surge)</span>
            <span>T+30s (Peak Threat)</span>
            <span>T+45s (Mitigation)</span>
            <span>T+60s (Stabilized)</span>
          </div>
        </div>

        {/* Topology Flow Graph */}
        <div className="bg-white/5 rounded-2xl p-6 border border-white/10 my-4 grid grid-cols-1 md:grid-cols-3 gap-6 text-center">
          <div className="p-4 bg-white/5 rounded-xl border border-white/10 flex flex-col items-center justify-center">
            <Globe className="w-8 h-8 text-[#d94b4b] mb-2 animate-pulse" />
            <b className="text-xs font-bold text-white block">Threat Source IP</b>
            <span className="text-[10px] text-white/60 font-mono-code">{sourceIp}</span>
          </div>

          <div className="p-4 bg-white/5 rounded-xl border border-white/10 flex flex-col items-center justify-center relative">
            <div className="text-xs font-bold text-[#d49b28] mb-1">
              Estimated Rate: {currentPhase.gbps}
            </div>
            <Zap className="w-8 h-8 text-[#d49b28] mb-2" />
            <b className="text-xs font-bold text-white block">Perimeter Edge Scrubber</b>
            <span className="text-[10px] text-white/60 font-mono-code">{vector}</span>
          </div>

          <div className="p-4 bg-white/5 rounded-xl border border-white/10 flex flex-col items-center justify-center">
            <Server className="w-8 h-8 text-[#2d9d78] mb-2" />
            <b className="text-xs font-bold text-white block">Target Asset</b>
            <span className="text-[10px] text-white/60 font-mono-code">{targetAsset}</span>
          </div>
        </div>

        {/* Phase Details Box */}
        <div className="bg-white/10 p-4 rounded-xl border border-white/10 text-xs flex justify-between items-center">
          <div>
            <b className="text-[#d49b28] block mb-0.5">Mitigation Action:</b>
            <span className="text-white/90">{currentPhase.mitigation}</span>
          </div>
          <span className="font-extrabold text-[#d49b28] text-sm font-display">
            {currentPhase.status}
          </span>
        </div>
      </div>
    </div>
  );
};
