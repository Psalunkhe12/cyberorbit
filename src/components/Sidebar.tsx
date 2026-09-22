import React from 'react';
import { NavigationTab, Operator } from '../types';
import {
  LayoutDashboard,
  Activity,
  ShieldAlert,
  Bell,
  SlidersHorizontal,
  RotateCcw,
  FileText,
  Sparkles,
  ChevronUp
} from 'lucide-react';

interface SidebarProps {
  activeTab: NavigationTab;
  onTabChange: (tab: NavigationTab) => void;
  operator: Operator;
  onOpenRoleModal: () => void;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onTabChange,
  operator,
  onOpenRoleModal,
}) => {
  const mainMenuNav = [
    { id: 'overview', label: 'Overview', icon: LayoutDashboard },
    { id: 'traffic', label: 'Live Traffic', icon: Activity },
    { id: 'threats', label: 'Threat Intel', icon: ShieldAlert },
    { id: 'alerts', label: 'Alerts Console', icon: Bell },
  ] as const;

  const opsNav = [
    { id: 'rules', label: 'Rules Engine', icon: SlidersHorizontal },
    { id: 'replay', label: 'Attack Replay', icon: RotateCcw },
    { id: 'reports', label: 'Reports', icon: FileText },
  ] as const;

  return (
    <aside className="bg-[#334d4a] p-8 text-white min-h-screen flex flex-col justify-between w-[260px] shrink-0 sticky top-0 h-screen select-none border-r border-[#d4deda]/10">
      <div>
        {/* Brand Header */}
        <div className="flex items-center gap-3 pb-9 font-display font-extrabold text-2xl tracking-tight text-white">
          <div className="w-9 h-9 border-2 border-[#d49b28] rounded-full grid place-items-center text-[#d49b28] shadow-[0_0_12px_rgba(212,155,40,0.3)] bg-[#d49b28]/10">
            <Sparkles className="w-5 h-5 text-[#d49b28]" />
          </div>
          <span className="tracking-wide">CyberOrbit</span>
        </div>

        {/* Main Menu */}
        <div className="text-[10px] font-bold text-white/40 uppercase tracking-widest mb-4 px-1">
          Command Center
        </div>
        <nav className="flex flex-col gap-2 mb-8">
          {mainMenuNav.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                id={`nav-${item.id}`}
                onClick={() => onTabChange(item.id)}
                className={`w-full border-none rounded-xl text-left px-4 py-3 flex items-center gap-3 text-sm font-bold cursor-pointer transition-all duration-200 ${
                  isActive
                    ? 'bg-white text-[#334d4a] shadow-lg font-extrabold'
                    : 'text-white/80 hover:bg-white/10'
                }`}
              >
                <Icon
                  className={`w-4 h-4 ${
                    isActive ? 'text-[#d49b28]' : 'opacity-60'
                  }`}
                />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>

        {/* Operations */}
        <div className="text-[10px] font-bold text-white/40 uppercase tracking-widest mb-4 px-1">
          Security Operations
        </div>
        <nav className="flex flex-col gap-2">
          {opsNav.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                id={`nav-${item.id}`}
                onClick={() => onTabChange(item.id)}
                className={`w-full border-none rounded-xl text-left px-4 py-3 flex items-center gap-3 text-sm font-bold cursor-pointer transition-all duration-200 ${
                  isActive
                    ? 'bg-white text-[#334d4a] shadow-lg font-extrabold'
                    : 'text-white/80 hover:bg-white/10'
                }`}
              >
                <Icon
                  className={`w-4 h-4 ${
                    isActive ? 'text-[#d49b28]' : 'opacity-60'
                  }`}
                />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Operator Footer */}
      <div className="pt-5 border-t border-white/12 mt-auto">
        <button
          id="operatorProfileBtn"
          onClick={onOpenRoleModal}
          className="w-full flex items-center justify-between p-1.5 rounded-xl hover:bg-white/5 transition-colors cursor-pointer text-left border border-transparent hover:border-white/10"
        >
          <div className="flex items-center gap-3">
            <div
              className="w-10 h-10 rounded-full border-2 border-[#d49b28] bg-[#d49b28]/15 grid place-items-center font-bold text-sm text-[#d49b28] shrink-0"
              style={{ borderColor: operator.avatarColor, color: operator.avatarColor }}
            >
              {operator.initials}
            </div>
            <div className="overflow-hidden">
              <b className="block text-[13.5px] text-white font-semibold truncate">
                {operator.name}
              </b>
              <small className="text-white/60 text-[11px] block truncate">
                {operator.role}
              </small>
            </div>
          </div>
          <ChevronUp className="w-4 h-4 text-white/40 shrink-0" />
        </button>
      </div>
    </aside>
  );
};
