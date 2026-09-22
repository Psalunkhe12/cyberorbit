import React, { useState } from 'react';
import { AnomalyEvent } from '../types';
import { ShieldCheck, Eye, Sparkles, X, Terminal, Cpu, MapPin } from 'lucide-react';

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
      </div>

      {/* Deep Inspection Drawer / Modal */}
      {selectedAnomaly && (
        <div className="fixed inset-0 z-50 bg-black/40 backdrop-blur-xs grid place-items-center p-4">
          <div className="bg-white rounded-2xl max-w-2xl w-full p-6 shadow-2xl border border-[#d4deda] relative animate-in fade-in zoom-in-95 duration-200">
            <button
              onClick={() => setSelectedAnomaly(null)}
              className="absolute top-4 right-4 text-[#6c8582] hover:text-[#253835] bg-[#dce3e0] p-1.5 rounded-full border-none cursor-pointer"
            >
              <X className="w-4 h-4" />
            </button>

            <div className="flex items-center gap-3 mb-4">
              <span
                className={`text-[10px] font-extrabold px-3 py-1 rounded-full uppercase ${getSeverityStyle(
                  selectedAnomaly.severity
                )}`}
              >
                {selectedAnomaly.severity}
              </span>
              <h2 className="font-display text-xl font-bold text-[#253835]">
                {selectedAnomaly.event}
              </h2>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-4 bg-[#f0f5f3] p-3.5 rounded-xl text-xs">
              <div>
                <span className="text-[#6c8582] block text-[10px] uppercase font-bold">
                  Source IP
                </span>
                <span className="font-mono-code font-bold text-[#334d4a]">
                  {selectedAnomaly.ip}
                </span>
              </div>
              <div>
                <span className="text-[#6c8582] block text-[10px] uppercase font-bold">
                  Target Asset
                </span>
                <span className="font-mono-code font-bold text-[#253835]">
                  {selectedAnomaly.asset}
                </span>
              </div>
              <div>
                <span className="text-[#6c8582] block text-[10px] uppercase font-bold">
                  Confidence
                </span>
                <span className="font-bold text-[#2d9d78]">
                  {selectedAnomaly.confidence}%
                </span>
              </div>
              <div>
                <span className="text-[#6c8582] block text-[10px] uppercase font-bold">
                  Geo Origin
                </span>
                <span className="font-medium text-[#253835] flex items-center gap-1">
                  <MapPin className="w-3 h-3 text-[#d49b28]" />
                  {selectedAnomaly.geoOrigin}
                </span>
              </div>
              <div>
                <span className="text-[#6c8582] block text-[10px] uppercase font-bold">
                  Vector
                </span>
                <span className="font-medium text-[#253835]">
                  {selectedAnomaly.attackVector || 'Network Spike'}
                </span>
              </div>
              <div>
                <span className="text-[#6c8582] block text-[10px] uppercase font-bold">
                  Timestamp
                </span>
                <span className="font-mono-code text-[#253835]">
                  {selectedAnomaly.timestamp}
                </span>
              </div>
            </div>

            <div className="mb-4">
              <label className="text-[11px] font-bold text-[#6c8582] uppercase block mb-1.5 flex items-center gap-1.5">
                <Terminal className="w-3.5 h-3.5 text-[#334d4a]" />
                <span>Captured Packet Payload Snippet</span>
              </label>
              <pre className="bg-[#334d4a] text-[#d49b28] p-3.5 rounded-xl font-mono-code text-xs overflow-x-auto whitespace-pre-wrap border border-white/10">
                {selectedAnomaly.payloadSnippet}
              </pre>
            </div>

            <div className="flex justify-end gap-3 pt-2 border-t border-[#d4deda]">
              <button
                onClick={() => {
                  onAnalyzePayload(selectedAnomaly);
                  setSelectedAnomaly(null);
                }}
                className="bg-[#334d4a] hover:bg-[#253835] text-white font-bold py-2 px-4 rounded-full text-xs border-none cursor-pointer flex items-center gap-2"
              >
                <Sparkles className="w-3.5 h-3.5 text-[#d49b28]" />
                <span>Analyze with Orbit AI</span>
              </button>
              <button
                onClick={() => {
                  onReviewAnomaly(selectedAnomaly.id);
                  setSelectedAnomaly(null);
                }}
                className="bg-[#d49b28] hover:bg-[#b8821a] text-white font-bold py-2 px-5 rounded-full text-xs border-none cursor-pointer flex items-center gap-2"
              >
                <ShieldCheck className="w-4 h-4" />
                <span>Confirm & Mitigate</span>
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
