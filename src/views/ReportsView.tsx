import React, { useState } from 'react';
import { FileText, Download, Printer, Sparkles, ShieldCheck, CheckCircle } from 'lucide-react';

export const ReportsView: React.FC = () => {
  const [reportDate] = useState('August 12, 2026');
  const [isGenerating, setIsGenerating] = useState(false);
  const [reportSummary, setReportSummary] = useState<string>(
    'During the reporting period, CyberOrbit SOC Command successfully mitigated 24 threat vectors with a 92.4% automated containment rate. Peak throughput reached 1.84 Gbps with zero SLA downtime on critical edge API proxies.'
  );

  const handleGenerateReport = async () => {
    setIsGenerating(true);
    try {
      const res = await fetch('/api/copilot', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: 'Generate a executive summary paragraph for the CISO security report covering traffic throughput, mitigated SYN floods, and WAF rules.',
        }),
      });
      const data = await res.json();
      setReportSummary(data.reply || reportSummary);
    } catch {
      // keep current
    } finally {
      setIsGenerating(false);
    }
  };

  const handlePrint = () => {
    window.print();
  };

  return (
    <div className="flex flex-col gap-5">
      {/* Top Controls Banner */}
      <div className="bg-white rounded-[32px] p-6 border border-[#d4deda] shadow-sm flex flex-wrap justify-between items-center gap-4">
        <div>
          <h2 className="font-display text-lg font-extrabold text-[#253835] flex items-center gap-2 m-0">
            <FileText className="w-5 h-5 text-[#d49b28]" />
            <span>Executive Security Reports Suite</span>
          </h2>
          <p className="text-xs text-[#6c8582] mt-0.5 m-0">
            Generate formal CISO compliance, threat summary, and SLA uptime reports.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleGenerateReport}
            disabled={isGenerating}
            className="bg-[#334d4a] hover:bg-[#253835] text-white px-5 py-2.5 rounded-full font-bold text-xs border-none cursor-pointer flex items-center gap-2 transition-colors disabled:opacity-50"
          >
            <Sparkles className="w-4 h-4 text-[#d49b28]" />
            <span>{isGenerating ? 'Generating...' : 'Refresh Executive Insights'}</span>
          </button>
          <button
            onClick={handlePrint}
            className="bg-[#d49b28] hover:bg-[#b8821a] text-white px-5 py-2.5 rounded-full font-bold text-xs border-none cursor-pointer flex items-center gap-2 transition-colors shadow-md"
          >
            <Printer className="w-4 h-4" />
            <span>Export Report / Print</span>
          </button>
        </div>
      </div>

      {/* Printable Report Paper Layout */}
      <div className="bg-white rounded-[32px] p-8 sm:p-12 border border-[#d4deda] shadow-sm max-w-4xl mx-auto w-full text-[#253835]">
        {/* Report Header */}
        <div className="flex justify-between items-start border-b-2 border-[#334d4a] pb-6 mb-6">
          <div>
            <div className="font-display text-2xl font-extrabold text-[#334d4a] tracking-wider">
              CYBERORBIT
            </div>
            <small className="text-xs text-[#6c8582] font-semibold">
              SECURITY OPERATIONS CENTER · COMMAND REPORT
            </small>
          </div>
          <div className="text-right">
            <span className="text-xs font-bold text-[#6c8582] block">DATE GENERATED</span>
            <span className="font-mono-code text-sm font-bold text-[#253835]">{reportDate}</span>
          </div>
        </div>

        {/* Executive Summary Section */}
        <div className="mb-8">
          <h3 className="font-display text-base font-bold text-[#334d4a] uppercase tracking-wide border-b border-[#d4deda] pb-2 mb-3">
            1. Executive Summary & CISO Overview
          </h3>
          <p className="text-xs leading-relaxed text-[#253835] bg-[#f0f5f3] p-4 rounded-xl border border-[#d4deda]">
            {reportSummary}
          </p>
        </div>

        {/* SLA Key Performance Indicators */}
        <div className="mb-8">
          <h3 className="font-display text-base font-bold text-[#334d4a] uppercase tracking-wide border-b border-[#d4deda] pb-2 mb-4">
            2. SLA & Operational Performance Metrics
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="p-4 bg-[#edf2f0] rounded-xl text-center">
              <span className="text-[10px] text-[#6c8582] font-bold uppercase block">
                Peak Throughput
              </span>
              <b className="font-display text-2xl text-[#334d4a]">1.84 Gbps</b>
            </div>
            <div className="p-4 bg-[#edf2f0] rounded-xl text-center">
              <span className="text-[10px] text-[#6c8582] font-bold uppercase block">
                Total Mitigated IPs
              </span>
              <b className="font-display text-2xl text-[#2d9d78]">24 IPs</b>
            </div>
            <div className="p-4 bg-[#edf2f0] rounded-xl text-center">
              <span className="text-[10px] text-[#6c8582] font-bold uppercase block">
                Automation Rate
              </span>
              <b className="font-display text-2xl text-[#d49b28]">92.4%</b>
            </div>
            <div className="p-4 bg-[#edf2f0] rounded-xl text-center">
              <span className="text-[10px] text-[#6c8582] font-bold uppercase block">
                Uptime SLA
              </span>
              <b className="font-display text-2xl text-[#2d9d78]">100.0%</b>
            </div>
          </div>
        </div>

        {/* Incident Summary Audit Table */}
        <div>
          <h3 className="font-display text-base font-bold text-[#334d4a] uppercase tracking-wide border-b border-[#d4deda] pb-2 mb-3">
            3. Key Resolved Threat Events
          </h3>
          <table className="w-full text-xs border-collapse">
            <thead>
              <tr className="border-b border-[#d4deda]">
                <th className="text-left py-2 text-[#6c8582] font-bold">EVENT</th>
                <th className="text-left py-2 text-[#6c8582] font-bold">SOURCE IP</th>
                <th className="text-left py-2 text-[#6c8582] font-bold">ASSET</th>
                <th className="text-right py-2 text-[#6c8582] font-bold">OUTCOME</th>
              </tr>
            </thead>
            <tbody>
              <tr className="border-b border-[#edf2f0]">
                <td className="py-2.5 font-bold">HTTP Flood Anomaly</td>
                <td className="py-2.5 font-mono-code">185.220.101.42</td>
                <td className="py-2.5 font-mono-code">edge-api-02</td>
                <td className="py-2.5 text-right font-bold text-[#2d9d78]">Mitigated / WAF Blocked</td>
              </tr>
              <tr className="border-b border-[#edf2f0]">
                <td className="py-2.5 font-bold">SYN Rate Threshold</td>
                <td className="py-2.5 font-mono-code">45.155.205.91</td>
                <td className="py-2.5 font-mono-code">gateway-01</td>
                <td className="py-2.5 text-right font-bold text-[#2d9d78]">Rate Limited</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
