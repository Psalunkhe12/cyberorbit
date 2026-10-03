import React, { useState } from 'react';
import { useAuth, UserRole, DEMO_PROFILES } from '../context/AuthContext';
import {
  X,
  Lock,
  Mail,
  ShieldCheck,
  User,
  Sparkles,
  ArrowRight,
  Shield,
  Eye,
  KeyRound,
} from 'lucide-react';

interface LoginFormModalProps {
  onClose: () => void;
  onTriggerToast: (msg: string) => void;
}

export const LoginFormModal: React.FC<LoginFormModalProps> = ({ onClose, onTriggerToast }) => {
  const { login, signup } = useAuth();
  const [isSignUpMode, setIsSignUpMode] = useState(false);
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [name, setName] = useState('');
  const [role, setRole] = useState<UserRole>('ANALYST');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim()) return;

    setLoading(true);
    setError(null);

    try {
      if (isSignUpMode) {
        const success = await signup(email, password || 'cyberorbit123', name || email.split('@')[0], role);
        if (success) {
          onTriggerToast(`Account created successfully with role ${role}`);
          onClose();
        }
      } else {
        const success = await login(email, password);
        if (success) {
          onTriggerToast(`Authenticated successfully as ${email}`);
          onClose();
        }
      }
    } catch (err: any) {
      setError(err.message || 'Authentication failed. Please check credentials.');
    } finally {
      setLoading(false);
    }
  };

  const handleQuickDemoLogin = async (demoRole: UserRole) => {
    setLoading(true);
    const demo = DEMO_PROFILES[demoRole];
    await login(demo.email);
    onTriggerToast(`Signed in as ${demo.name} (${demoRole})`);
    setLoading(false);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 bg-black/60 backdrop-blur-xs flex items-center justify-center p-4 animate-in fade-in duration-200">
      <div className="bg-white rounded-[32px] max-w-lg w-full p-8 shadow-2xl border border-[#d4deda] relative overflow-hidden">
        {/* Top Header */}
        <div className="flex justify-between items-start mb-6">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-[#334d4a] text-white rounded-2xl shadow-xs">
              <ShieldCheck className="w-6 h-6 text-[#d49b28]" />
            </div>
            <div>
              <h2 className="font-display text-xl font-bold text-[#253835] m-0">
                CyberOrbit SOC Authentication
              </h2>
              <p className="text-xs text-[#6c8582] m-0 mt-0.5">
                Role-Based Access Control (RBAC) & RLS Security
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

        {/* Quick Demo Shortcuts */}
        <div className="mb-6 bg-[#f8faf9] p-4 rounded-2xl border border-[#d4deda]">
          <span className="text-[10px] font-extrabold text-[#334d4a] uppercase tracking-wider block mb-2 flex items-center gap-1.5">
            <Sparkles className="w-3.5 h-3.5 text-[#d49b28]" />
            Quick Demo Role Shortcuts
          </span>
          <div className="grid grid-cols-2 gap-2">
            {(['ADMIN', 'SOC_LEAD', 'ANALYST', 'VIEWER'] as const).map((r) => (
              <button
                key={r}
                type="button"
                onClick={() => handleQuickDemoLogin(r)}
                className={`px-3 py-2 rounded-xl text-xs font-bold border cursor-pointer transition-all flex items-center justify-between ${
                  r === 'ADMIN'
                    ? 'bg-[#fde8e8] text-[#d94b4b] border-[#f8b4b4] hover:bg-[#fbd5d5]'
                    : r === 'SOC_LEAD'
                    ? 'bg-[#334d4a] text-white border-[#334d4a] hover:bg-[#253835]'
                    : r === 'ANALYST'
                    ? 'bg-[#fdf3e1] text-[#b8821a] border-[#f6d79b] hover:bg-[#fbe9c5]'
                    : 'bg-[#e8f5e9] text-[#2d9d78] border-[#a5d6a7] hover:bg-[#d4edd9]'
                }`}
              >
                <span>{r === 'VIEWER' ? 'VIEWER (Read-Only)' : r}</span>
                <ArrowRight className="w-3 h-3 opacity-60" />
              </button>
            ))}
          </div>
        </div>

        {/* Form Mode Toggle */}
        <div className="flex bg-[#f0f5f3] p-1 rounded-full mb-6 border border-[#d4deda]">
          <button
            type="button"
            onClick={() => setIsSignUpMode(false)}
            className={`flex-1 py-2 text-xs font-bold rounded-full border-none cursor-pointer transition-all ${
              !isSignUpMode ? 'bg-[#334d4a] text-white shadow-xs' : 'text-[#6c8582]'
            }`}
          >
            Log In
          </button>
          <button
            type="button"
            onClick={() => setIsSignUpMode(true)}
            className={`flex-1 py-2 text-xs font-bold rounded-full border-none cursor-pointer transition-all ${
              isSignUpMode ? 'bg-[#334d4a] text-white shadow-xs' : 'text-[#6c8582]'
            }`}
          >
            Create Account
          </button>
        </div>

        {error && (
          <div className="mb-4 bg-[#fde8e8] text-[#d94b4b] p-3 rounded-xl text-xs font-semibold border border-[#f8b4b4]">
            {error}
          </div>
        )}

        {/* Form Fields */}
        <form onSubmit={handleSubmit} className="space-y-4">
          {isSignUpMode && (
            <div>
              <label className="text-[11px] font-bold text-[#6c8582] uppercase block mb-1">
                Full Name
              </label>
              <div className="relative">
                <User className="w-4 h-4 text-[#6c8582] absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  required
                  placeholder="e.g. Sarah Chen"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full pl-10 pr-4 py-2.5 bg-[#f0f5f3] rounded-xl text-xs font-semibold text-[#253835] outline-none border border-[#d4deda] focus:border-[#334d4a]"
                />
              </div>
            </div>
          )}

          <div>
            <label className="text-[11px] font-bold text-[#6c8582] uppercase block mb-1">
              Work Email Address
            </label>
            <div className="relative">
              <Mail className="w-4 h-4 text-[#6c8582] absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="email"
                required
                placeholder="analyst@cyberorbit.sec"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 bg-[#f0f5f3] rounded-xl text-xs font-semibold text-[#253835] outline-none border border-[#d4deda] focus:border-[#334d4a]"
              />
            </div>
          </div>

          <div>
            <label className="text-[11px] font-bold text-[#6c8582] uppercase block mb-1">
              Password
            </label>
            <div className="relative">
              <KeyRound className="w-4 h-4 text-[#6c8582] absolute left-3.5 top-1/2 -translate-y-1/2" />
              <input
                type="password"
                placeholder="••••••••••••"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="w-full pl-10 pr-4 py-2.5 bg-[#f0f5f3] rounded-xl text-xs font-semibold text-[#253835] outline-none border border-[#d4deda] focus:border-[#334d4a]"
              />
            </div>
          </div>

          {isSignUpMode && (
            <div>
              <label className="text-[11px] font-bold text-[#6c8582] uppercase block mb-1">
                Assign Role & Permissions
              </label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value as UserRole)}
                className="w-full px-4 py-2.5 bg-[#f0f5f3] rounded-xl text-xs font-bold text-[#253835] outline-none border border-[#d4deda] focus:border-[#334d4a] cursor-pointer"
              >
                <option value="ADMIN">ADMIN — Full System Access & User Management</option>
                <option value="SOC_LEAD">SOC_LEAD — Full Triage, Response Approval & Rule Editing</option>
                <option value="ANALYST">ANALYST — Triage Alerts, Incidents & AI Analysis</option>
                <option value="VIEWER">VIEWER — Read-Only Dashboard & Metrics (Write Blocked)</option>
              </select>
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="w-full py-3 bg-[#334d4a] hover:bg-[#253835] text-white font-extrabold text-xs rounded-full border-none cursor-pointer shadow-md hover:shadow-lg transition-all disabled:opacity-50 mt-2"
          >
            {loading ? 'Processing...' : isSignUpMode ? 'Create Account & Assign Role' : 'Authenticate & Sign In'}
          </button>
        </form>
      </div>
    </div>
  );
};
