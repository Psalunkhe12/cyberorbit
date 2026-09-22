import React, { useState } from 'react';
import { RotateCcw, Play, Pause, ShieldCheck, Zap, Server, Globe } from 'lucide-react';

export const AttackReplayView: React.FC = () => {
  const [timelineSec, setTimelineSec] = useState(30);
  const [isPlaying, setIsPlaying] = useState(false);

  const getPhaseInfo = (sec: number) => {
    if (sec < 15) {
      return {
        phase: 'Phase 1: Initial Reconnaissance & SYN Probing',
        status: 'NORMAL / ELEVATING',
        gbps: '0.85 Gbps',
        desc: 'Botnet nodes in Frankfurt and Moscow initiate SYN packet bursts on port 443.',
        activeNodes: ['Botnet Pool A'],
        mitigation: 'SYN Cookie Challenge initiated by Edge Gateway.',
      };
    } else if (sec < 35) {
      return {
        phase: 'Phase 2: Layer 7 Volumetric HTTP Flood Surge',
        status: 'CRITICAL ATTACK SURGE',
        gbps: '4.20 Gbps',
        desc: '18,000 requests/sec flooding /api/v2/products. Target CPU load at 88%.',
        activeNodes: ['Botnet Pool A', 'Botnet Pool B'],
        mitigation: 'Auto-rate-limiting triggered. WAF SQLi filter active.',
      };
    } else if (sec < 50) {
      return {
        phase: 'Phase 3: BGP Flowspec & Edge Quarantine',
        status: 'CONTAINMENT IN PROGRESS',
        gbps: '2.10 Gbps',
        desc: 'Malicious AS202425 IP range rerouted to blackhole scrubbers.',
        activeNodes: ['Edge Scrubber Node'],
        mitigation: '92.4% traffic dropped before reaching internal cluster.',
      };
    } else {
      return {
        phase: 'Phase 4: Post-Mitigation Baseline Restoration',
        status: 'STABILIZED',
        gbps: '1.20 Gbps',
        desc: 'Normal user connections restored. System throughput within SLA boundaries.',
        activeNodes: ['Legitimate Edge Proxy'],
        mitigation: 'All threat vectors quarantined.',
      };
    }
  };

  const currentPhase = getPhaseInfo(timelineSec);

  return (
    <div className="flex flex-col gap-5">
      {/* Top Banner */}
      <div className="bg-white rounded-[32px] p-6 border border-[#d4deda] shadow-sm">
        <h2 className="font-display text-lg font-extrabold text-[#253835] mb-1 flex items-center gap-2 m-0">
          <RotateCcw className="w-5 h-5 text-[#d49b28]" />
          <span>Incident Forensics & Attack Sequence Replay</span>
        </h2>
        <p className="text-xs text-[#6c8582] m-0 mt-1">
          Scrub through historical DDoS attack telemetry to analyze vector propagation and mitigation response times.
        </p>
      </div>

      {/* Interactive Scrub Control */}
      <div className="bg-[#334d4a] text-white rounded-[32px] p-6 border border-white/10 shadow-xl">
        <div className="flex justify-between items-center mb-4">
          <div>
            <span className="text-[10px] font-bold text-[#d49b28] uppercase tracking-wider block">
              TIMELINE TIME-SCRUBBER
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
            <span>T+30s (Peak DDoS)</span>
            <span>T+45s (BGP Reroute)</span>
            <span>T+60s (Restored)</span>
          </div>
        </div>

        {/* Topology Flow Graph */}
        <div className="bg-white/5 rounded-2xl p-6 border border-white/10 my-4 grid grid-cols-1 md:grid-cols-3 gap-6 text-center">
          <div className="p-4 bg-white/5 rounded-xl border border-white/10 flex flex-col items-center justify-center">
            <Globe className="w-8 h-8 text-[#d94b4b] mb-2 animate-pulse" />
            <b className="text-xs font-bold text-white block">Botnet Sources (Frankfurt)</b>
            <span className="text-[10px] text-white/60 font-mono-code">185.220.101.42</span>
          </div>

          <div className="p-4 bg-white/5 rounded-xl border border-white/10 flex flex-col items-center justify-center relative">
            <div className="text-xs font-bold text-[#d49b28] mb-1">
              Volume: {currentPhase.gbps}
            </div>
            <Zap className="w-8 h-8 text-[#d49b28] mb-2" />
            <b className="text-xs font-bold text-white block">Edge Proxy Scrubber</b>
            <span className="text-[10px] text-white/60 font-mono-code">edge-api-02</span>
          </div>

          <div className="p-4 bg-white/5 rounded-xl border border-white/10 flex flex-col items-center justify-center">
            <Server className="w-8 h-8 text-[#2d9d78] mb-2" />
            <b className="text-xs font-bold text-white block">Internal Microservices</b>
            <span className="text-[10px] text-white/60 font-mono-code">auth-service</span>
          </div>
        </div>

        {/* Phase Details Box */}
        <div className="bg-white/10 p-4 rounded-xl border border-white/10 text-xs flex justify-between items-center">
          <div>
            <b className="text-[#d49b28] block mb-0.5">Mitigation Protocol Executed:</b>
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
