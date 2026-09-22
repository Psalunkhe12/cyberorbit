import React from 'react';
import { Zap, Radio, AlertTriangle, ShieldCheck, TrendingUp, TrendingDown } from 'lucide-react';

interface MetricsBarProps {
  throughput: string;
  activeFlows: number;
  threatsCount: number;
  mitigatedCount: number;
}

export const MetricsBar: React.FC<MetricsBarProps> = ({
  throughput,
  activeFlows,
  threatsCount,
  mitigatedCount,
}) => {
  return (
    <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-5">
      {/* Card 1: Throughput */}
      <div className="bg-white p-5 rounded-3xl border border-[#d4deda] shadow-sm hover:shadow-md transition-all">
        <div className="flex justify-between items-start mb-4">
          <div className="text-[10px] font-bold text-[#6c8582] uppercase tracking-wider">
            Throughput
          </div>
          <div className="text-[#d49b28] text-lg font-bold">
            <Zap className="w-5 h-5 text-[#d49b28]" />
          </div>
        </div>
        <div className="text-2xl lg:text-3xl font-black text-[#253835]">
          {throughput}<span className="text-sm font-medium text-[#6c8582] ml-1">Gbps</span>
        </div>
        <div className="text-[10px] text-[#2d9d78] font-bold mt-1.5 flex items-center gap-1">
          <TrendingUp className="w-3 h-3" />
          <span>↑ 8.3%</span>
          <span className="text-[#6c8582] font-normal italic">vs baseline</span>
        </div>
      </div>

      {/* Card 2: Active Flows */}
      <div className="bg-white p-5 rounded-3xl border border-[#d4deda] shadow-sm hover:shadow-md transition-all">
        <div className="flex justify-between items-start mb-4">
          <div className="text-[10px] font-bold text-[#6c8582] uppercase tracking-wider">
            Active Flows
          </div>
          <div className="text-[#d49b28] text-lg font-bold">
            <Radio className="w-5 h-5 text-[#d49b28]" />
          </div>
        </div>
        <div className="text-2xl lg:text-3xl font-black text-[#253835]">
          {activeFlows.toLocaleString()}
        </div>
        <div className="text-[10px] text-[#2d9d78] font-bold mt-1.5 flex items-center gap-1">
          <TrendingUp className="w-3 h-3" />
          <span>↑ 4.1%</span>
          <span className="text-[#6c8582] font-normal italic">last 10m</span>
        </div>
      </div>

      {/* Card 3: Threats */}
      <div className="bg-white p-5 rounded-3xl border border-[#d4deda] shadow-sm hover:shadow-md transition-all">
        <div className="flex justify-between items-start mb-4">
          <div className="text-[10px] font-bold text-[#6c8582] uppercase tracking-wider">
            Detected Threats
          </div>
          <div className="text-[#d94b4b] text-lg font-bold">
            <AlertTriangle className="w-5 h-5 text-[#d94b4b]" />
          </div>
        </div>
        <div className="text-2xl lg:text-3xl font-black text-[#253835]">
          {threatsCount < 10 ? `0${threatsCount}` : threatsCount}
        </div>
        <div className="text-[10px] text-[#d94b4b] font-bold mt-1.5 flex items-center gap-1">
          <TrendingUp className="w-3 h-3" />
          <span>↑ 3 new</span>
          <span className="text-[#6c8582] font-normal italic">incidents</span>
        </div>
      </div>

      {/* Card 4: Health / Mitigated */}
      <div className="bg-white p-5 rounded-3xl border border-[#d4deda] shadow-sm hover:shadow-md transition-all">
        <div className="flex justify-between items-start mb-4">
          <div className="text-[10px] font-bold text-[#6c8582] uppercase tracking-wider">
            Health Index
          </div>
          <div className="text-[#2d9d78] text-lg font-bold">
            <ShieldCheck className="w-5 h-5 text-[#2d9d78]" />
          </div>
        </div>
        <div className="text-2xl lg:text-3xl font-black text-[#253835]">
          98.2<span className="text-sm font-medium text-[#6c8582] ml-1">%</span>
        </div>
        <div className="text-[10px] text-[#2d9d78] font-bold mt-1.5 flex items-center gap-1">
          <span>STABLE</span>
          <span className="text-[#6c8582] font-normal italic">({mitigatedCount} mitigated)</span>
        </div>
      </div>
    </section>
  );
};
