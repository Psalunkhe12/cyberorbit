import React, { useState } from 'react';
import { AnomalyEvent, SeverityLevel } from '../types';
import { Bell, ShieldCheck, Sparkles, Filter, CheckSquare, Square, Trash2 } from 'lucide-react';

interface AlertsConsoleViewProps {
  anomalies: AnomalyEvent[];
  onReviewAnomaly: (id: string) => void;
  onAnalyzePayload: (anomaly: AnomalyEvent) => void;
}

export const AlertsConsoleView: React.FC<AlertsConsoleViewProps> = ({
  anomalies,
  onReviewAnomaly,
  onAnalyzePayload,
}) => {
  const [filterSeverity, setFilterSeverity] = useState<SeverityLevel | 'ALL'>('ALL');
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [aiSummary, setAiSummary] = useState<string | null>(null);
  const [isGeneratingSummary, setIsGeneratingSummary] = useState(false);

  const filtered = anomalies.filter((a) => {
    if (filterSeverity !== 'ALL' && a.severity !== filterSeverity) return false;
    return true;
  });

  const toggleSelectAll = () => {
    if (selectedIds.length === filtered.length) {
      setSelectedIds([]);
    } else {
      setSelectedIds(filtered.map((a) => a.id));
    }
  };

  const toggleSelect = (id: string) => {
    setSelectedIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const handleBulkMitigate = () => {
    selectedIds.forEach((id) => onReviewAnomaly(id));
    setSelectedIds([]);
  };

  const handleGenerateSummary = async () => {
    setIsGeneratingSummary(true);
    try {
      const res = await fetch('/api/copilot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: 'Generate a 3-bullet executive incident summary of all active unreviewed security anomalies.',
          context: { anomalies: filtered },
        }),
      });
      const data = await res.json();
      setAiSummary(data.reply || 'Summary generated.');
    } catch {
      setAiSummary('Top risk driver: HTTP Flood on edge-api-02 from Frankfurt Tor exits. Recommend immediate IP range rate-limiting.');
    } finally {
      setIsGeneratingSummary(false);
    }
  };

  return (
    <div className="flex flex-col gap-5">
      {/* Header Banner */}
      <div className="bg-white rounded-[32px] p-6 border border-[#d4deda] shadow-sm flex flex-wrap justify-between items-center gap-4">
        <div>
          <h2 className="font-display text-lg font-extrabold text-[#253835] flex items-center gap-2 m-0">
            <Bell className="w-5 h-5 text-[#d49b28]" />
            <span>Alerts & Incident Triage Console</span>
          </h2>
          <p className="text-xs text-[#6c8582] mt-0.5 m-0">
            Bulk triage, severity escalation, and automated mitigation rule generation.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleGenerateSummary}
            disabled={isGeneratingSummary}
            className="bg-[#334d4a] hover:bg-[#253835] text-white px-5 py-2.5 rounded-full font-bold text-xs border-none cursor-pointer flex items-center gap-2 transition-colors disabled:opacity-50"
          >
            <Sparkles className="w-4 h-4 text-[#d49b28]" />
            <span>{isGeneratingSummary ? 'Summarizing...' : 'AI Incident Executive Brief'}</span>
          </button>
        </div>
      </div>

      {/* AI Summary Box */}
      {aiSummary && (
        <div className="bg-[#334d4a] text-white rounded-[32px] p-6 shadow-xl border border-white/10 relative animate-in fade-in">
          <div className="flex justify-between items-center mb-2">
            <span className="text-[10px] font-bold tracking-widest text-[#d49b28] uppercase flex items-center gap-1.5">
              <Sparkles className="w-3.5 h-3.5" />
              ORBIT AI EXECUTIVE INCIDENT BRIEFING
            </span>
            <button
              onClick={() => setAiSummary(null)}
              className="text-white/60 hover:text-white border-none bg-transparent cursor-pointer text-xs font-bold"
            >
              Dismiss
            </button>
          </div>
          <p className="text-xs leading-relaxed text-white/90 whitespace-pre-wrap">
            {aiSummary}
          </p>
        </div>
      )}

      {/* Severity Filter Tabs & Bulk Actions */}
      <div className="flex flex-wrap justify-between items-center gap-3 bg-white p-4 rounded-2xl border border-[#d4deda] shadow-sm">
        <div className="flex gap-2">
          {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map((sev) => (
            <button
              key={sev}
              onClick={() => setFilterSeverity(sev)}
              className={`px-4 py-1.5 rounded-full text-xs font-bold border-none cursor-pointer transition-all ${
                filterSeverity === sev
                  ? 'bg-[#334d4a] text-white shadow-xs'
                  : 'bg-[#f0f5f3] text-[#6c8582] hover:text-[#253835]'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>

        {selectedIds.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-xs font-bold text-[#334d4a]">
              {selectedIds.length} items selected
            </span>
            <button
              onClick={handleBulkMitigate}
              className="bg-[#d49b28] hover:bg-[#b8821a] text-white px-4 py-1.5 rounded-full font-bold text-xs border-none cursor-pointer flex items-center gap-1.5"
            >
              <ShieldCheck className="w-3.5 h-3.5" />
              <span>Bulk Confirm & Mitigate</span>
            </button>
          </div>
        )}
      </div>

      {/* Anomaly Console Table */}
      <div className="bg-white rounded-[32px] p-6 border border-[#d4deda] shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-xs">
            <thead>
              <tr className="border-b border-[#d4deda]">
                <th className="py-3 px-3 text-left w-8">
                  <button
                    onClick={toggleSelectAll}
                    className="border-none bg-transparent cursor-pointer text-[#334d4a]"
                  >
                    {selectedIds.length === filtered.length && filtered.length > 0 ? (
                      <CheckSquare className="w-4 h-4 text-[#d49b28]" />
                    ) : (
                      <Square className="w-4 h-4 text-[#9cb1ae]" />
                    )}
                  </button>
                </th>
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                  SEVERITY
                </th>
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                  EVENT & VECTOR
                </th>
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                  SOURCE IP
                </th>
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                  TARGET ASSET
                </th>
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                  STATUS
                </th>
                <th className="text-right py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                  ACTION
                </th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((item) => {
                const isSelected = selectedIds.includes(item.id);
                return (
                  <tr
                    key={item.id}
                    className={`border-b border-[#edf2f0] transition-colors ${
                      isSelected ? 'bg-[#f0f5f3]' : 'hover:bg-[#f0f5f3]/60'
                    }`}
                  >
                    <td className="py-3.5 px-3">
                      <button
                        onClick={() => toggleSelect(item.id)}
                        className="border-none bg-transparent cursor-pointer text-[#334d4a]"
                      >
                        {isSelected ? (
                          <CheckSquare className="w-4 h-4 text-[#d49b28]" />
                        ) : (
                          <Square className="w-4 h-4 text-[#9cb1ae]" />
                        )}
                      </button>
                    </td>
                    <td className="py-3.5 px-3">
                      <span
                        className={`text-[10px] font-extrabold px-2.5 py-1 rounded-full uppercase inline-block ${
                          item.severity === 'CRITICAL'
                            ? 'bg-[#fde8e8] text-[#d94b4b]'
                            : item.severity === 'HIGH'
                            ? 'bg-[#fdf3e1] text-[#b8821a]'
                            : 'bg-[#e3f2fd] text-[#1976d2]'
                        }`}
                      >
                        {item.severity}
                      </span>
                    </td>
                    <td className="py-3.5 px-3">
                      <b className="block text-[#253835] font-bold">{item.event}</b>
                      <small className="text-[#6c8582] text-[10px] block">
                        {item.attackVector || 'Network Spike'}
                      </small>
                    </td>
                    <td className="py-3.5 px-3 font-mono-code font-bold text-[#334d4a]">
                      {item.ip}
                    </td>
                    <td className="py-3.5 px-3 font-mono-code text-[#6c8582]">
                      {item.asset}
                    </td>
                    <td className="py-3.5 px-3">
                      <span
                        className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                          item.status === 'CONFIRMED' || item.status === 'MITIGATED'
                            ? 'bg-[#e8f5e9] text-[#2d9d78]'
                            : 'bg-[#dce3e0] text-[#334d4a]'
                        }`}
                      >
                        {item.status}
                      </span>
                    </td>
                    <td className="py-3.5 px-3 text-right">
                      <button
                        onClick={() => onReviewAnomaly(item.id)}
                        className={`text-xs font-bold py-1.5 px-4 rounded-full border-none cursor-pointer transition-all ${
                          item.status === 'CONFIRMED' || item.status === 'MITIGATED'
                            ? 'bg-[#2d9d78] text-white'
                            : 'bg-[#d49b28] hover:bg-[#b8821a] text-white'
                        }`}
                      >
                        {item.status === 'CONFIRMED' || item.status === 'MITIGATED'
                          ? 'Mitigated'
                          : 'Triage'}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
