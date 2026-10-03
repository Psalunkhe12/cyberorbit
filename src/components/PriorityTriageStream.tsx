import React, { useState } from 'react';
import { AnomalyEvent } from '../types';
import { ShieldCheck, Eye, Sparkles, X, Terminal, Cpu, MapPin } from 'lucide-react';
import { AlertDetailDrawer } from './AlertDetailDrawer';

interface PriorityTriageStreamProps {
  anomalies: AnomalyEvent[];
  onReviewAnomaly: (id: string) => void;
  onAnalyzePayload: (anomaly: AnomalyEvent) => void;
}

export const PriorityTriageStream: React.FC<PriorityTriageStreamProps> = ({
  anomalies,
  onReviewAnomaly,
  onAnalyzePayload,
}) => {
  const [selectedAnomaly, setSelectedAnomaly] = useState<AnomalyEvent | null>(null);

  const getSeverityStyle = (severity: AnomalyEvent['severity']) => {
    switch (severity) {
      case 'CRITICAL':
        return 'bg-[#fde8e8] text-[#d94b4b]';
      case 'HIGH':
        return 'bg-[#fdf3e1] text-[#b8821a]';
      case 'MEDIUM':
        return 'bg-[#e3f2fd] text-[#1976d2]';
      case 'LOW':
        return 'bg-[#e8f5e9] text-[#2d9d78]';
    }
  };

  return (
    <div className="bg-white rounded-[32px] p-6 border border-[#d4deda] shadow-sm">
      <div className="flex justify-between items-center mb-4">
        <div>
          <div className="font-display text-base font-extrabold text-[#253835]">
            Priority Triage Stream
          </div>
          <div className="text-xs text-[#6c8582] mt-0.5">
            Recent detected anomalies needing review
          </div>
        </div>
        <span className="text-[11px] font-bold px-3 py-1 rounded-full bg-[#dce3e0] text-[#253835]">
          FILTERED ({anomalies.length})
        </span>
      </div>

      <div className="overflow-x-auto">
        {anomalies.length === 0 ? (
          <div className="py-12 px-4 text-center bg-[#f8faf9] rounded-2xl border border-dashed border-[#c2d1cc]">
            <ShieldCheck className="w-8 h-8 text-[#2d9d78] mx-auto mb-2 opacity-70" />
            <p className="text-xs font-bold text-[#334d4a] m-0">No Telemetry Anomalies Detected</p>
            <p className="text-[11px] text-[#6c8582] mt-1 m-0">
              No active alerts or security events in triage queue. All edge proxies operating normally.
            </p>
          </div>
        ) : (
          <table className="w-full border-collapse text-xs">
            <thead>
              <tr className="border-b border-[#d4deda]">
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase tracking-wider">
                  SEVERITY
                </th>
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase tracking-wider">
                  EVENT
                </th>
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase tracking-wider">
                  SOURCE IP
                </th>
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase tracking-wider">
                  ASSET
                </th>
                <th className="text-right py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase tracking-wider">
                  ACTION
                </th>
              </tr>
            </thead>
            <tbody>
              {anomalies.map((item) => (
                <tr
                  key={item.id}
                  className="border-b border-[#edf2f0] hover:bg-[#f0f5f3] transition-colors cursor-pointer group"
                  onClick={() => setSelectedAnomaly(item)}
                >
                  <td className="py-3.5 px-3">
                    <span
                      className={`text-[10px] font-extrabold px-2.5 py-1 rounded-full uppercase inline-block ${getSeverityStyle(
                        item.severity
                      )}`}
                    >
                      {item.severity}
                    </span>
                  </td>
                  <td className="py-3.5 px-3 font-semibold text-[#253835]">
                    <div className="flex items-center gap-1.5">
                      <span>{item.event}</span>
                      {item.cveId && (
                        <span className="bg-[#334d4a]/10 text-[#334d4a] text-[9px] font-mono-code px-1.5 py-0.5 rounded">
                          {item.cveId}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="py-3.5 px-3 font-mono-code text-xs text-[#334d4a] font-semibold">
                    {item.ip}
                  </td>
                  <td className="py-3.5 px-3 text-[#6c8582] font-mono-code text-xs">
                    {item.asset}
                  </td>
                  <td className="py-3.5 px-3 text-right" onClick={(e) => e.stopPropagation()}>
                    <button
                      onClick={() => onReviewAnomaly(item.id)}
                      className={`review-btn text-xs font-bold py-1.5 px-4 rounded-full border-none cursor-pointer transition-all ${
                        item.status === 'CONFIRMED' || item.status === 'MITIGATED'
                          ? 'bg-[#2d9d78] text-white'
                          : 'bg-[#d49b28] hover:bg-[#b8821a] text-white'
                      }`}
                    >
                      {item.status === 'CONFIRMED' || item.status === 'MITIGATED'
                        ? 'Confirmed'
                        : 'Review'}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Alert Detail Drawer with AI Security Analysis */}
      <AlertDetailDrawer
        alert={selectedAnomaly}
        onClose={() => setSelectedAnomaly(null)}
        onReviewAlert={onReviewAnomaly}
        onTriggerToast={(msg) => console.log(msg)}
      />
    </div>
  );
};
