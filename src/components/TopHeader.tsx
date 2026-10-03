import React from 'react';
import { Search, Radio, ChevronDown, Play, UserCheck, ShieldCheck, User } from 'lucide-react';
import { NavigationTab } from '../types';
import { useAuth } from '../context/AuthContext';

interface TopHeaderProps {
  activeTab: NavigationTab;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  onRunSimulation: () => void;
  isSimulating: boolean;
}

export const TopHeader: React.FC<TopHeaderProps> = ({
  activeTab,
  searchQuery,
  onSearchChange,
  onRunSimulation,
  isSimulating,
}) => {
  const { profile, role, setIsLoginModalOpen, setIsProfileModalOpen, user } = useAuth();

  const titles: Record<NavigationTab, { breadcrumb: string; main: string }> = {
    overview: { breadcrumb: 'SOC COMMAND / PRODUCTION', main: 'Security Dashboard' },
    incidents: { breadcrumb: 'SOC COMMAND / INCIDENTS', main: 'Correlated Incidents Center' },
    traffic: { breadcrumb: 'SOC COMMAND / NETWORK', main: 'Live Traffic Monitor' },
    threats: { breadcrumb: 'SOC COMMAND / INTEL', main: 'Threat Intelligence Vault' },
    alerts: { breadcrumb: 'SOC COMMAND / TRIAGE', main: 'Alerts & Incidents Console' },
    rules: { breadcrumb: 'OPERATIONS / FIREWALL', main: 'WAF & Rules Engine' },
    replay: { breadcrumb: 'OPERATIONS / FORENSICS', main: 'Attack Sequence Replay' },
    reports: { breadcrumb: 'OPERATIONS / INTELLIGENCE', main: 'Security Executive Reports' },
  };

  const currentInfo = titles[activeTab] || titles.overview;

  const getRoleBadgeStyle = (r: typeof role) => {
    switch (r) {
      case 'ADMIN':
        return 'bg-[#fde8e8] text-[#d94b4b] border-[#f8b4b4]';
      case 'SOC_LEAD':
        return 'bg-[#334d4a] text-white border-[#334d4a]';
      case 'ANALYST':
        return 'bg-[#fdf3e1] text-[#b8821a] border-[#f6d79b]';
      case 'VIEWER':
      default:
        return 'bg-[#e8f5e9] text-[#2d9d78] border-[#a5d6a7]';
    }
  };

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
            className="border-none bg-transparent outline-none text-xs text-[#253835] w-48 placeholder-[#9cb1ae] font-sans"
          />
          <button
            id="simBtn"
            onClick={onRunSimulation}
            disabled={isSimulating}
            className="bg-[#d49b28] hover:bg-[#b8821a] text-white border-none rounded-full px-3.5 py-1.5 font-bold text-xs cursor-pointer transition-colors flex items-center gap-1.5 shrink-0 disabled:opacity-50"
          >
            {isSimulating ? (
              <Radio className="w-3.5 h-3.5 animate-spin" />
            ) : (
              <Play className="w-3.5 h-3.5 fill-current" />
            )}
            <span>{isSimulating ? 'Simulating...' : 'Run Simulation'}</span>
          </button>
        </div>

        {/* Live System Indicator */}
        <div className="bg-white px-3.5 py-2 rounded-full text-xs font-bold text-[#253835] shadow-xs flex items-center gap-2 border border-[#d4deda]/60 select-none">
          <span className="w-2 h-2 rounded-full bg-[#2d9d78] pulse-glow" />
          <span className="tracking-wide uppercase text-[10px]">ALL SYSTEMS LIVE</span>
        </div>

        {/* Profile / Auth Button */}
        <button
          id="profileBtn"
          onClick={() => setIsProfileModalOpen(true)}
          className="bg-white px-3.5 py-1.5 rounded-full text-xs font-bold text-[#253835] shadow-xs flex items-center gap-2 border border-[#d4deda]/60 cursor-pointer hover:bg-[#e3e9e6]/50 transition-colors"
        >
          <div
            className="w-6 h-6 rounded-full grid place-items-center text-white text-[10px] font-extrabold"
            style={{ backgroundColor: profile.avatarColor }}
          >
            {profile.initials}
          </div>
          <span className="truncate max-w-[110px]">{profile.name.split(' ')[0]}</span>
          <span
            className={`text-[9px] font-extrabold px-2 py-0.5 rounded-full border uppercase ${getRoleBadgeStyle(
              role
            )}`}
          >
            {role}
          </span>
          <ChevronDown className="w-3.5 h-3.5 text-[#6c8582]" />
        </button>

        {!user && (
          <button
            onClick={() => setIsLoginModalOpen(true)}
            className="bg-[#334d4a] hover:bg-[#253835] text-white px-4 py-2 rounded-full text-xs font-bold border-none cursor-pointer flex items-center gap-1.5 shadow-xs"
          >
            <UserCheck className="w-3.5 h-3.5 text-[#d49b28]" />
            <span>Sign In</span>
          </button>
        )}
      </div>
    </header>
  );
};
