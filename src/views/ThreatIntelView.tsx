import React, { useState } from 'react';
import { Search, ShieldAlert, Globe, Database, Download, AlertTriangle, CheckCircle, ShieldCheck } from 'lucide-react';
import { useRealtimeThreatIntel } from '../hooks/useRealtimeThreatIntel';

export const ThreatIntelView: React.FC = () => {
  const { indicators, primaryVector, loading, isolateThreatVector } = useRealtimeThreatIntel();
  const [searchIp, setSearchIp] = useState('');
  const [selectedRecord, setSelectedRecord] = useState<any>(null);

  const activeRecord = selectedRecord || (indicators.length > 0 ? indicators[0] : null);

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    if (!searchIp.trim()) return;
    const found = indicators.find((t) => t.origin.includes(searchIp.trim()) || t.target.includes(searchIp.trim()));
    if (found) {
      setSelectedRecord(found);
    }
  };

  return (
    <div className="flex flex-col gap-5">
      {/* Search Input Banner */}
      <div className="bg-white rounded-[32px] p-6 border border-[#d4deda] shadow-sm">
        <h2 className="font-display text-lg font-extrabold text-[#253835] mb-1 flex items-center gap-2 m-0">
          <ShieldAlert className="w-5 h-5 text-[#d49b28]" />
          <span>Threat Intelligence & IP Reputation Vault</span>
        </h2>
        <p className="text-xs text-[#6c8582] mb-4 mt-1">
          Query internal threat_indicators database table for high-risk IPs, domains, and attack vectors.
        </p>

        <form onSubmit={handleSearch} className="flex gap-3">
          <div className="flex-1 flex items-center gap-2 bg-[#f0f5f3] px-4 py-2.5 rounded-full border border-[#d4deda]">
            <Search className="w-4 h-4 text-[#6c8582]" />
            <input
              type="text"
              value={searchIp}
              onChange={(e) => setSearchIp(e.target.value)}
              placeholder="Search threat indicators by IP or origin host..."
              className="w-full bg-transparent border-none outline-none text-xs text-[#253835] font-mono-code"
            />
          </div>
          <button
            type="submit"
            className="bg-[#d49b28] hover:bg-[#b8821a] text-white px-6 py-2.5 rounded-full font-bold text-xs border-none cursor-pointer transition-colors"
          >
            Lookup IP
          </button>
        </form>
      </div>

      {/* Lookup Detail Card */}
      {activeRecord ? (
        <div className="bg-[#334d4a] text-white rounded-[32px] p-6 border border-white/10 shadow-xl">
          <div className="flex flex-wrap justify-between items-start gap-4 mb-6">
            <div>
              <span className="text-[10px] font-bold tracking-widest text-[#d49b28] uppercase block mb-1">
                INDICATOR DETAIL
              </span>
              <h3 className="font-mono-code text-3xl font-extrabold text-white m-0">
                {activeRecord.origin || activeRecord.ip || 'Threat Indicator'}
              </h3>
              <span className="text-xs text-white/70 block mt-1">
                Target: {activeRecord.target} ({activeRecord.originCode || 'INT'})
              </span>
            </div>

            <div className="bg-white/10 px-5 py-3 rounded-2xl border border-white/10 text-right">
              <span className="text-[10px] font-bold text-[#d49b28] uppercase block">
                RISK SCORE
              </span>
              <span className="font-display text-3xl font-extrabold text-[#d94b4b]">
                {activeRecord.riskScore}/100
              </span>
              <small className="text-[10px] text-white/60 block">{activeRecord.riskLabel}</small>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 bg-white/5 p-4 rounded-xl border border-white/10 text-xs">
            <div>
              <span className="text-white/50 block text-[10px] uppercase font-bold">Attack Classification</span>
              <span className="font-bold text-[#d49b28]">{activeRecord.attackType}</span>
            </div>
            <div>
              <span className="text-white/50 block text-[10px] uppercase font-bold">Quarantine Status</span>
              <span className="font-medium text-white">{activeRecord.isIsolated ? 'ISOLATED' : 'ACTIVE THREAT'}</span>
            </div>
            <div>
              <span className="text-white/50 block text-[10px] uppercase font-bold">Last Updated</span>
              <span className="font-mono-code text-white">{new Date(activeRecord.lastUpdated).toLocaleString()}</span>
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-[#334d4a] text-white rounded-[32px] p-6 border border-white/10 text-center py-8">
          <ShieldCheck className="w-8 h-8 text-[#2d9d78] mx-auto mb-2 opacity-80" />
          <p className="text-sm font-bold text-white m-0">No Active Threat Indicator Selected</p>
          <p className="text-xs text-white/60 mt-1 m-0">
            Select a threat indicator below or insert IOCs into public.threat_indicators.
          </p>
        </div>
      )}

      {/* Global IOC Threat Database Table */}
      <div className="bg-white rounded-[32px] p-6 border border-[#d4deda] shadow-sm">
        <div className="flex justify-between items-center mb-4">
          <div className="font-display text-base font-extrabold text-[#253835] flex items-center gap-2">
            <Database className="w-4 h-4 text-[#d49b28]" />
            <span>Active Indicators of Compromise ({indicators.length})</span>
          </div>
          <button
            onClick={() => alert('Exporting IOC database...')}
            className="bg-[#dce3e0] hover:bg-[#c2ceca] text-[#253835] px-4 py-2 rounded-full font-bold text-xs border-none cursor-pointer flex items-center gap-1.5 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export STIX 2.1</span>
          </button>
        </div>

        <div className="overflow-x-auto">
          {loading && indicators.length === 0 ? (
            <div className="py-12 text-center text-xs font-bold text-[#6c8582]">
              Loading threat indicators from database...
            </div>
          ) : indicators.length === 0 ? (
            <div className="py-12 px-4 text-center bg-[#f8faf9] rounded-2xl border border-dashed border-[#c2d1cc]">
              <ShieldCheck className="w-8 h-8 text-[#2d9d78] mx-auto mb-2 opacity-70" />
              <p className="text-xs font-bold text-[#334d4a] m-0">No Threat Indicators Found</p>
              <p className="text-[11px] text-[#6c8582] mt-1 m-0">
                The threat_indicators database table contains no records. Threat intelligence matcher is active.
              </p>
            </div>
          ) : (
            <table className="w-full border-collapse text-xs">
              <thead>
                <tr className="border-b border-[#d4deda]">
                  <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                    ORIGIN / THREAT IP
                  </th>
                  <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                    RISK SCORE
                  </th>
                  <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                    TARGET ASSET
                  </th>
                  <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                    ATTACK TYPE
                  </th>
                  <th className="text-right py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                    ACTION
                  </th>
                </tr>
              </thead>
              <tbody>
                {indicators.map((item) => (
                  <tr
                    key={item.id}
                    onClick={() => setSelectedRecord(item)}
                    className="border-b border-[#edf2f0] hover:bg-[#f0f5f3] cursor-pointer"
                  >
                    <td className="py-3 px-3 font-mono-code font-bold text-[#334d4a]">{item.origin}</td>
                    <td className="py-3 px-3 font-extrabold text-[#d94b4b]">{item.riskScore}/100</td>
                    <td className="py-3 px-3 text-[#6c8582]">{item.target}</td>
                    <td className="py-3 px-3 font-semibold text-[#253835]">{item.attackType}</td>
                    <td className="py-3 px-3 text-right">
                      <button className="bg-[#d49b28] hover:bg-[#b8821a] text-white px-3 py-1 rounded-full text-[11px] font-bold border-none cursor-pointer">
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
};
