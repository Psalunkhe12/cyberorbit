import React from 'react';
import { useAuth, UserRole } from '../context/AuthContext';
import { Lock, ShieldAlert, ArrowRight, UserCheck } from 'lucide-react';

interface ProtectedRouteProps {
  children: React.ReactNode;
  allowedRoles?: UserRole[];
  requiredPermission?: 'canTriageAlerts' | 'canApproveResponseActions' | 'canManageSecurityRules' | 'canTriggerAIAnalysis' | 'canManageUserRoles';
}

export const ProtectedRoute: React.FC<ProtectedRouteProps> = ({
  children,
  allowedRoles,
  requiredPermission,
}) => {
  const { role, permissions, setIsLoginModalOpen, setIsProfileModalOpen } = useAuth();

  let isAuthorized = true;

  if (allowedRoles && !allowedRoles.includes(role)) {
    isAuthorized = false;
  }

  if (requiredPermission && !permissions[requiredPermission]) {
    isAuthorized = false;
  }

  if (!isAuthorized) {
    return (
      <div className="bg-white rounded-[32px] p-8 border border-[#d4deda] shadow-sm text-center my-6 animate-in fade-in">
        <div className="w-12 h-12 rounded-2xl bg-[#fde8e8] text-[#d94b4b] grid place-items-center mx-auto mb-3 border border-[#f8b4b4]">
          <Lock className="w-6 h-6" />
        </div>
        <h3 className="font-display font-bold text-lg text-[#253835] m-0">
          Authorization Restricted (Role: <span className="text-[#d94b4b]">{role}</span>)
        </h3>
        <p className="text-xs text-[#6c8582] mt-1 max-w-md mx-auto">
          Your current SOC role <span className="font-bold text-[#253835]">{role}</span> does not have write or management authorization for this view.
          Database Row Level Security (RLS) policies enforce read-only access.
        </p>

        <div className="flex justify-center items-center gap-3 mt-4">
          <button
            onClick={() => setIsLoginModalOpen(true)}
            className="bg-[#334d4a] hover:bg-[#253835] text-white px-5 py-2.5 rounded-full font-bold text-xs border-none cursor-pointer flex items-center gap-2"
          >
            <UserCheck className="w-4 h-4 text-[#d49b28]" />
            <span>Sign In / Change Role</span>
          </button>
          <button
            onClick={() => setIsProfileModalOpen(true)}
            className="bg-[#f0f5f3] hover:bg-[#e3eae7] text-[#334d4a] px-5 py-2.5 rounded-full font-bold text-xs border border-[#d4deda] cursor-pointer"
          >
            View Permissions
          </button>
        </div>
      </div>
    );
  }

  return <>{children}</>;
};
