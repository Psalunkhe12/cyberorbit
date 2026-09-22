import React from 'react';
import { Search, Radio, ChevronDown, Play } from 'lucide-react';
import { Operator, NavigationTab } from '../types';

interface TopHeaderProps {
  activeTab: NavigationTab;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  onRunSimulation: () => void;
  isSimulating: boolean;
  operator: Operator;
  onOpenRoleModal: () => void;
}

export const TopHeader: React.FC<TopHeaderProps> = ({
  activeTab,
  searchQuery,
  onSearchChange,
  onRunSimulation,
  isSimulating,
  operator,
  onOpenRoleModal,
}) => {
  const titles: Record<NavigationTab, { breadcrumb: string; main: string }> = {
    overview: { breadcrumb: 'SOC COMMAND / PRODUCTION', main: 'Security Dashboard' },
    traffic: { breadcrumb: 'SOC COMMAND / NETWORK', main: 'Live Traffic Monitor' },
    threats: { breadcrumb: 'SOC COMMAND / INTEL', main: 'Threat Intelligence Vault' },
    alerts: { breadcrumb: 'SOC COMMAND / TRIAGE', main: 'Alerts & Incidents Console' },
    rules: { breadcrumb: 'OPERATIONS / FIREWALL', main: 'WAF & Rules Engine' },
    replay: { breadcrumb: 'OPERATIONS / FORENSICS', main: 'Attack Sequence Replay' },
    reports: { breadcrumb: 'OPERATIONS / INTELLIGENCE', main: 'Security Executive Reports' },
  };

  const currentInfo = titles[activeTab] || titles.overview;

  return (
    <header className="flex flex-wrap items-center justify-between gap-4 mb-7">
      <div>
        <div className="text-[11px] font-bold tracking-[1px] text-[#6c8582] uppercase mb-1">
          {currentInfo.breadcrumb}
        </div>
        <h1 className="font-display text-3xl font-extrabold text-[#253835] tracking-tight">
          {currentInfo.main}
        </h1>
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        {/* Search Bar */}
        <div className="flex items-center gap-2.5 bg-white rounded-full px-4 py-1.5 shadow-[0_10px_30px_rgba(40,60,57,0.06)] border border-[#d4deda]/60">
          <Search className="w-4 h-4 text-[#6c8582]" />
          <input
            id="searchInput"
            type="text"
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            placeholder="Search IP, node, or rule..."
            className="border-none bg-transparent outline-none text-xs text-[#253835] w-52 placeholder-[#9cb1ae] font-sans"
          />
          <button
            id="simBtn"
            onClick={onRunSimulation}
            disabled={isSimulating}
            className="bg-[#d49b28] hover:bg-[#b8821a] text-white border-none rounded-full px-4 py-2 font-bold text-xs cursor-pointer transition-colors flex items-center gap-1.5 shrink-0 disabled:opacity-50"
          >
            {isSimulating ? (
              <Radio className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Play className="w-3.5 h-3.5 fill-current" />
            )}
            <span>{isSimulating ? 'Simulating...' : 'Run Simulation'}</span>
          </button>
        </div>

        {/* Live Systems Status */}
        <div className="bg-white px-4.5 py-2.5 rounded-full text-xs font-bold text-[#253835] shadow-[0_10px_30px_rgba(40,60,57,0.06)] flex items-center gap-2 border border-[#d4deda]/60 select-none">
          <span className="w-2 h-2 rounded-full bg-[#2d9d78] pulse-glow" />
          <span className="tracking-wide uppercase text-[11px]">ALL SYSTEMS LIVE</span>
        </div>

        {/* Role Button Dropdown */}
        <button
          id="roleBtn"
          onClick={onOpenRoleModal}
          className="bg-white px-4.5 py-2.5 rounded-full text-xs font-bold text-[#253835] shadow-[0_10px_30px_rgba(40,60,57,0.06)] flex items-center gap-1.5 border border-[#d4deda]/60 cursor-pointer hover:bg-[#e3e9e6]/50 transition-colors"
        >
          <span>{operator.role}</span>
          <ChevronDown className="w-3.5 h-3.5 text-[#6c8582]" />
        </button>
      </div>
    </header>
  );
};
