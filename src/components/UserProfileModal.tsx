import React from 'react';
import { useAuth, UserRole } from '../context/AuthContext';
import {
  X,
  User,
  ShieldCheck,
  LogOut,
  CheckCircle2,
  XCircle,
  Key,
  Lock,
  Sparkles,
  ShieldAlert,
} from 'lucide-react';

interface UserProfileModalProps {
  onClose: () => void;
  onTriggerToast: (msg: string) => void;
}

export const UserProfileModal: React.FC<UserProfileModalProps> = ({ onClose, onTriggerToast }) => {
  const { profile, role, permissions, logout, switchRole, user } = useAuth();

  const handleLogout = async () => {
    await logout();
    onTriggerToast('Logged out successfully. Session reset to VIEWER (Read-Only).');
    onClose();
  };

  const handleRoleSwitch = (newRole: UserRole) => {
    switchRole(newRole);
    onTriggerToast(`Switched active role to ${newRole}`);
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4 animate-in fade-in duration-200">
      <div className="bg-white rounded-[32px] max-w-md w-full p-8 shadow-2xl border border-[#d4deda] relative overflow-hidden">
        {/* Header */}
        <div className="flex justify-between items-start mb-6">
          <div className="flex items-center gap-3">
            <div
              className="w-12 h-12 rounded-2xl grid place-items-center text-white font-extrabold text-base shadow-xs"
              style={{ backgroundColor: profile.avatarColor }}
            >
              {profile.initials}
            </div>
            <div>
              <h2 className="font-display text-lg font-bold text-[#253835] m-0">
                {profile.name}
              </h2>
              <p className="text-xs text-[#6c8582] m-0 font-mono-code mt-0.5">
                {profile.email}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="text-[#6c8582] hover:text-[#253835] bg-[#f0f5f3] hover:bg-[#e3eae7] p-2 rounded-full border-none cursor-pointer transition-all"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Current Active Role Badge */}
        <div className="bg-[#f8faf9] p-4 rounded-2xl border border-[#d4deda] mb-6">
          <div className="flex justify-between items-center mb-2">
            <span className="text-[10px] font-extrabold text-[#6c8582] uppercase tracking-wider">
              AUTHENTICATED SOC ROLE
            </span>
            <span
              className={`text-[10px] font-extrabold px-3 py-1 rounded-full uppercase border ${
                role === 'ADMIN'
                  ? 'bg-[#fde8e8] text-[#d94b4b] border-[#f8b4b4]'
                  : role === 'SOC_LEAD'
                  ? 'bg-[#334d4a] text-white border-[#334d4a]'
                  : role === 'ANALYST'
                  ? 'bg-[#fdf3e1] text-[#b8821a] border-[#f6d79b]'
                  : 'bg-[#e8f5e9] text-[#2d9d78] border-[#a5d6a7]'
              }`}
            >
              {role}
            </span>
          </div>

          {/* Quick Role Switcher for Testing */}
          <span className="text-[10px] font-bold text-[#334d4a] block mb-1">
            Switch Active Role (RBAC Simulation):
          </span>
          <div className="grid grid-cols-4 gap-1.5">
            {(['ADMIN', 'SOC_LEAD', 'ANALYST', 'VIEWER'] as const).map((r) => (
              <button
                key={r}
                onClick={() => handleRoleSwitch(r)}
                className={`py-1.5 px-2 rounded-xl text-[10px] font-bold border cursor-pointer transition-all ${
                  role === r
                    ? 'bg-[#334d4a] text-white border-[#334d4a]'
                    : 'bg-white text-[#6c8582] border-[#d4deda] hover:text-[#253835]'
                }`}
              >
                {r === 'SOC_LEAD' ? 'LEAD' : r}
              </button>
            ))}
          </div>
        </div>

        {/* Permissions Matrix */}
        <div className="space-y-3 mb-6">
          <span className="text-[10px] font-extrabold text-[#334d4a] uppercase tracking-wider block">
            Role Authorization Checklist:
          </span>

          <div className="space-y-2 text-xs">
            <div className="flex justify-between items-center bg-[#f0f5f3] p-2.5 rounded-xl">
              <span className="font-semibold text-[#253835]">Alert & Incident Triage:</span>
              {permissions.canTriageAlerts ? (
                <span className="text-[#2d9d78] font-bold flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" /> Allowed
                </span>
              ) : (
                <span className="text-[#d94b4b] font-bold flex items-center gap-1">
                  <XCircle className="w-3.5 h-3.5" /> Blocked (Read-Only)
                </span>
              )}
            </div>

            <div className="flex justify-between items-center bg-[#f0f5f3] p-2.5 rounded-xl">
              <span className="font-semibold text-[#253835]">Approve Response Actions:</span>
              {permissions.canApproveResponseActions ? (
                <span className="text-[#2d9d78] font-bold flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" /> Allowed
                </span>
              ) : (
                <span className="text-[#d94b4b] font-bold flex items-center gap-1">
                  <XCircle className="w-3.5 h-3.5" /> Blocked
                </span>
              )}
            </div>

            <div className="flex justify-between items-center bg-[#f0f5f3] p-2.5 rounded-xl">
              <span className="font-semibold text-[#253835]">Manage Security Rules:</span>
              {permissions.canManageSecurityRules ? (
                <span className="text-[#2d9d78] font-bold flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" /> Allowed
                </span>
              ) : (
                <span className="text-[#d94b4b] font-bold flex items-center gap-1">
                  <XCircle className="w-3.5 h-3.5" /> Blocked
                </span>
              )}
            </div>

            <div className="flex justify-between items-center bg-[#f0f5f3] p-2.5 rounded-xl">
              <span className="font-semibold text-[#253835]">AI Gemini Analysis:</span>
              {permissions.canTriggerAIAnalysis ? (
                <span className="text-[#2d9d78] font-bold flex items-center gap-1">
                  <CheckCircle2 className="w-3.5 h-3.5" /> Allowed
                </span>
              ) : (
                <span className="text-[#d94b4b] font-bold flex items-center gap-1">
                  <XCircle className="w-3.5 h-3.5" /> Blocked
                </span>
              )}
            </div>
          </div>
        </div>

        {/* Footer Actions */}
        <div className="pt-4 border-t border-[#d4deda] flex justify-between items-center">
          <span className="text-[10px] text-[#6c8582] font-mono-code">
            Supabase Auth: {user ? 'Connected' : 'Demo Mode'}
          </span>

          <button
            onClick={handleLogout}
            className="bg-[#fde8e8] hover:bg-[#fbd5d5] text-[#d94b4b] border border-[#f8b4b4] px-5 py-2.5 rounded-full font-bold text-xs cursor-pointer flex items-center gap-2 transition-all"
          >
            <LogOut className="w-4 h-4" />
            <span>Sign Out / Reset</span>
          </button>
        </div>
      </div>
    </div>
  );
};
