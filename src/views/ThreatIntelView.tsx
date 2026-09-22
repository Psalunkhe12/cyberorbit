import React, { useState } from 'react';
import { Search, ShieldAlert, Globe, Database, Download, AlertTriangle, CheckCircle } from 'lucide-react';

interface ThreatRecord {
  ip: string;
  riskScore: number;
  country: string;
  asn: string;
  org: string;
  category: string;
  reportsCount: number;
  lastSeen: string;
  botnetFamily: string;
}

export const ThreatIntelView: React.FC = () => {
  const [searchIp, setSearchIp] = useState('185.220.101.42');
  const [activeRecord, setActiveRecord] = useState<ThreatRecord>({
    ip: '185.220.101.42',
    riskScore: 96,
    country: 'Germany (DE)',
    asn: 'AS202425',
    org: 'Tor Exit Infrastructure Services',
    category: 'Known Botnet Command & Control',
    reportsCount: 1420,
    lastSeen: '1 minute ago',
    botnetFamily: 'Mirai.v3 / HTTP Flood Variant',
  });

  const sampleThreats: ThreatRecord[] = [
    {
      ip: '185.220.101.42',
      riskScore: 96,
      country: 'Germany (DE)',
      asn: 'AS202425',
      org: 'Tor Exit Infrastructure Services',
      category: 'Known Botnet Command & Control',
      reportsCount: 1420,
      lastSeen: '1 minute ago',
      botnetFamily: 'Mirai.v3 / HTTP Flood Variant',
    },
    {
      ip: '45.155.205.91',
      riskScore: 89,
      country: 'Russia (RU)',
      asn: 'AS48282',
      org: 'VDSina Hosting Proxy',
      category: 'SYN Flood / Transport Exhaustion',
      reportsCount: 840,
      lastSeen: '5 minutes ago',
      botnetFamily: 'Satori DDoS Bot',
    },
    {
      ip: '91.199.118.17',
      riskScore: 91,
      country: 'Romania (RO)',
      asn: 'AS12302',
      org: 'VPS Provider Network',
      category: 'Credential Stuffing Node',
      reportsCount: 1120,
      lastSeen: '12 minutes ago',
      botnetFamily: 'BruteX Scanner',
    },
    {
      ip: '194.26.29.114',
      riskScore: 99,
      country: 'Ukraine (UA)',
      asn: 'AS3214',
      org: 'Datacenter Transit LLC',
      category: 'SQLi & Zero-Day Exploiter',
      reportsCount: 2310,
      lastSeen: '20 minutes ago',
      botnetFamily: 'Cobalt Strike Beacon Probe',
    },
  ];

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    const found = sampleThreats.find((t) => t.ip.includes(searchIp.trim()));
    if (found) {
      setActiveRecord(found);
    } else {
      setActiveRecord({
        ip: searchIp,
        riskScore: Math.floor(Math.random() * 40 + 50),
        country: 'United States (US)',
        asn: 'AS13335',
        org: 'Cloudflare Proxy Network',
        category: 'Suspicious Rate Spike',
        reportsCount: Math.floor(Math.random() * 200 + 10),
        lastSeen: 'Just now',
        botnetFamily: 'Generic Crawler Probe',
      });
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
          Query global threat intelligence feeds, ASN reputations, and active botnet signatures.
        </p>

        <form onSubmit={handleSearch} className="flex gap-3">
          <div className="flex-1 flex items-center gap-2 bg-[#f0f5f3] px-4 py-2.5 rounded-full border border-[#d4deda]">
            <Search className="w-4 h-4 text-[#6c8582]" />
            <input
              type="text"
              value={searchIp}
              onChange={(e) => setSearchIp(e.target.value)}
              placeholder="Enter IP address (e.g. 185.220.101.42 or 45.155.205.91)..."
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
      <div className="bg-[#334d4a] text-white rounded-[32px] p-6 border border-white/10 shadow-xl">
        <div className="flex flex-wrap justify-between items-start gap-4 mb-6">
          <div>
            <span className="text-[10px] font-bold tracking-widest text-[#d49b28] uppercase block mb-1">
              LOOKUP RESULT
            </span>
            <h3 className="font-mono-code text-3xl font-extrabold text-white m-0">
              {activeRecord.ip}
            </h3>
            <span className="text-xs text-white/70 block mt-1">
              {activeRecord.org} ({activeRecord.asn})
            </span>
          </div>

          <div className="bg-white/10 px-5 py-3 rounded-2xl border border-white/10 text-right">
            <span className="text-[10px] font-bold text-[#d49b28] uppercase block">
              REPUTATION RISK SCORE
            </span>
            <span className="font-display text-3xl font-extrabold text-[#d94b4b]">
              {activeRecord.riskScore}/100
            </span>
            <small className="text-[10px] text-white/60 block">CRITICAL MALICIOUS</small>
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 bg-white/5 p-4 rounded-xl border border-white/10 text-xs">
          <div>
            <span className="text-white/50 block text-[10px] uppercase font-bold">Category</span>
            <span className="font-bold text-[#d49b28]">{activeRecord.category}</span>
          </div>
          <div>
            <span className="text-white/50 block text-[10px] uppercase font-bold">Country</span>
            <span className="font-medium text-white">{activeRecord.country}</span>
          </div>
          <div>
            <span className="text-white/50 block text-[10px] uppercase font-bold">Botnet Family</span>
            <span className="font-mono-code text-white">{activeRecord.botnetFamily}</span>
          </div>
          <div>
            <span className="text-white/50 block text-[10px] uppercase font-bold">Total Abuse Reports</span>
            <span className="font-bold text-white">{activeRecord.reportsCount.toLocaleString()}</span>
          </div>
        </div>
      </div>

      {/* Global IOC Threat Database Table */}
      <div className="bg-white rounded-[32px] p-6 border border-[#d4deda] shadow-sm">
        <div className="flex justify-between items-center mb-4">
          <div className="font-display text-base font-extrabold text-[#253835] flex items-center gap-2">
            <Database className="w-4 h-4 text-[#d49b28]" />
            <span>Active Indicators of Compromise (IOC Vault)</span>
          </div>
          <button
            onClick={() => alert('Exporting IOC database as STIX / JSON feed...')}
            className="bg-[#dce3e0] hover:bg-[#c2ceca] text-[#253835] px-4 py-2 rounded-full font-bold text-xs border-none cursor-pointer flex items-center gap-1.5 transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Export STIX 2.1</span>
          </button>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-xs">
            <thead>
              <tr className="border-b border-[#d4deda]">
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                  INDICATOR (IP)
                </th>
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                  RISK SCORE
                </th>
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                  ASN / ORG
                </th>
                <th className="text-left py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                  THREAT CLASSIFICATION
                </th>
                <th className="text-right py-3 px-3 text-[10px] font-bold text-[#6c8582] uppercase">
                  ACTION
                </th>
              </tr>
            </thead>
            <tbody>
              {sampleThreats.map((item) => (
                <tr
                  key={item.ip}
                  onClick={() => setActiveRecord(item)}
                  className="border-b border-[#edf2f0] hover:bg-[#f0f5f3] cursor-pointer"
                >
                  <td className="py-3 px-3 font-mono-code font-bold text-[#334d4a]">{item.ip}</td>
                  <td className="py-3 px-3 font-extrabold text-[#d94b4b]">{item.riskScore}/100</td>
                  <td className="py-3 px-3 text-[#6c8582]">{item.asn} - {item.org}</td>
                  <td className="py-3 px-3 font-semibold text-[#253835]">{item.category}</td>
                  <td className="py-3 px-3 text-right">
                    <button className="bg-[#d49b28] hover:bg-[#b8821a] text-white px-3 py-1 rounded-full text-[11px] font-bold border-none cursor-pointer">
                      Inspect
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
