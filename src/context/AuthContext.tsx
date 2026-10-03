import React, { createContext, useContext, useState, useEffect } from 'react';
import { supabase } from '../lib/supabase';
import { User, Session } from '@supabase/supabase-js';
import { logAuditAction } from '../lib/auditLogger';

export type UserRole = 'ADMIN' | 'SOC_LEAD' | 'ANALYST' | 'VIEWER';

export interface UserProfile {
  id: string;
  email: string;
  name: string;
  role: UserRole;
  avatarColor: string;
  initials: string;
}

export const ROLE_PERMISSIONS: Record<
  UserRole,
  {
    canTriageAlerts: boolean;
    canApproveResponseActions: boolean;
    canManageSecurityRules: boolean;
    canTriggerAIAnalysis: boolean;
    canManageUserRoles: boolean;
    isReadOnly: boolean;
  }
> = {
  ADMIN: {
    canTriageAlerts: true,
    canApproveResponseActions: true,
    canManageSecurityRules: true,
    canTriggerAIAnalysis: true,
    canManageUserRoles: true,
    isReadOnly: false,
  },
  SOC_LEAD: {
    canTriageAlerts: true,
    canApproveResponseActions: true,
    canManageSecurityRules: true,
    canTriggerAIAnalysis: true,
    canManageUserRoles: false,
    isReadOnly: false,
  },
  ANALYST: {
    canTriageAlerts: true,
    canApproveResponseActions: false,
    canManageSecurityRules: false,
    canTriggerAIAnalysis: true,
    canManageUserRoles: false,
    isReadOnly: false,
  },
  VIEWER: {
    canTriageAlerts: false,
    canApproveResponseActions: false,
    canManageSecurityRules: false,
    canTriggerAIAnalysis: false,
    canManageUserRoles: false,
    isReadOnly: true,
  },
};

export const DEMO_PROFILES: Record<UserRole, UserProfile> = {
  ADMIN: {
    id: 'usr-admin-01',
    email: 'admin@cyberorbit.sec',
    name: 'Elena Vance (Administrator)',
    role: 'ADMIN',
    avatarColor: '#d94b4b',
    initials: 'EV',
  },
  SOC_LEAD: {
    id: 'usr-soclead-01',
    email: 'sarah.chen@cyberorbit.sec',
    name: 'Sarah Chen (SOC Lead)',
    role: 'SOC_LEAD',
    avatarColor: '#334d4a',
    initials: 'SC',
  },
  ANALYST: {
    id: 'usr-analyst-01',
    email: 'alex.mercer@cyberorbit.sec',
    name: 'Alex Mercer (Senior Analyst)',
    role: 'ANALYST',
    avatarColor: '#d49b28',
    initials: 'AM',
  },
  VIEWER: {
    id: 'usr-viewer-01',
    email: 'auditor@cyberorbit.sec',
    name: 'Marcus Vance (Security Auditor)',
    role: 'VIEWER',
    avatarColor: '#6c8582',
    initials: 'MV',
  },
};

interface AuthContextType {
  user: User | null;
  session: Session | null;
  profile: UserProfile;
  role: UserRole;
  permissions: (typeof ROLE_PERMISSIONS)[UserRole];
  isAuthenticated: boolean;
  login: (email: string, password?: string) => Promise<boolean>;
  signup: (email: string, password: string, name: string, role: UserRole) => Promise<boolean>;
  logout: () => Promise<void>;
  switchRole: (newRole: UserRole) => void;
  isLoginModalOpen: boolean;
  setIsLoginModalOpen: (open: boolean) => void;
  isProfileModalOpen: boolean;
  setIsProfileModalOpen: (open: boolean) => void;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [session, setSession] = useState<Session | null>(null);
  const [user, setUser] = useState<User | null>(null);
  const [profile, setProfile] = useState<UserProfile>(DEMO_PROFILES.SOC_LEAD);
  const [isLoginModalOpen, setIsLoginModalOpen] = useState(false);
  const [isProfileModalOpen, setIsProfileModalOpen] = useState(false);

  useEffect(() => {
    if (!supabase) return;

    // Get current session
    supabase.auth.getSession().then(({ data: { session } }) => {
      setSession(session);
      setUser(session?.user ?? null);
      if (session?.user) {
        fetchUserProfile(session.user.id, session.user.email ?? '');
      }
    });

    // Listen for auth state changes
    const { data: { subscription } } = supabase.auth.onAuthStateChange(async (_event, session) => {
      setSession(session);
      setUser(session?.user ?? null);
      if (session?.user) {
        fetchUserProfile(session.user.id, session.user.email ?? '');
      }
    });

    return () => subscription.unsubscribe();
  }, []);

  const fetchUserProfile = async (userId: string, email: string) => {
    if (!supabase) return;

    try {
      const { data, error } = await supabase
        .from('user_profiles')
        .select('*')
        .eq('user_id', userId)
        .single();

      if (data && !error) {
        const userRole = (data.role as UserRole) || 'ANALYST';
        setProfile({
          id: data.id,
          email: data.email || email,
          name: data.name || email.split('@')[0],
          role: userRole,
          avatarColor: DEMO_PROFILES[userRole]?.avatarColor || '#334d4a',
          initials: (data.name || email).slice(0, 2).toUpperCase(),
        });
      }
    } catch (err) {
      console.warn('Failed to fetch user_profile from Supabase, using local fallback:', err);
    }
  };

  const login = async (email: string, password?: string): Promise<boolean> => {
    let loggedProfile = DEMO_PROFILES.ANALYST;

    if (supabase && password) {
      try {
        const { data, error } = await supabase.auth.signInWithPassword({
          email,
          password,
        });

        if (error) {
          throw error;
        }

        if (data.user) {
          setUser(data.user);
          setSession(data.session);
          await fetchUserProfile(data.user.id, data.user.email ?? '');
          logAuditAction({
            user: data.user.email || email,
            action: 'LOGIN',
            entity: data.user.id,
            old_value: null,
            new_value: { status: 'AUTHENTICATED' },
          });
          return true;
        }
      } catch (err) {
        console.error('Supabase login error:', err);
      }
    }

    // Demo Mode Sign-in Matching
    const matchedRole = (Object.keys(DEMO_PROFILES) as UserRole[]).find(
      (r) => DEMO_PROFILES[r].email.toLowerCase() === email.toLowerCase()
    );

    if (matchedRole) {
      loggedProfile = DEMO_PROFILES[matchedRole];
      setProfile(loggedProfile);
    } else {
      loggedProfile = {
        id: `usr-${Date.now()}`,
        email,
        name: email.split('@')[0],
        role: 'ANALYST',
        avatarColor: '#334d4a',
        initials: email.slice(0, 2).toUpperCase(),
      };
      setProfile(loggedProfile);
    }

    logAuditAction({
      user: loggedProfile.email || email,
      action: 'LOGIN',
      entity: loggedProfile.id,
      old_value: null,
      new_value: { status: 'AUTHENTICATED', role: loggedProfile.role },
    });

    return true;
  };

  const signup = async (
    email: string,
    password: string,
    name: string,
    role: UserRole
  ): Promise<boolean> => {
    if (supabase) {
      try {
        const { data, error } = await supabase.auth.signUp({
          email,
          password,
          options: {
            data: { name, role },
          },
        });

        if (error) throw error;

        if (data.user) {
          // Insert profile into database
          await supabase.from('user_profiles').insert([
            {
              user_id: data.user.id,
              email,
              name,
              role,
            },
          ]);
        }
        return true;
      } catch (err) {
        console.error('Supabase signup error:', err);
      }
    }

    // Local profile setup
    setProfile({
      id: `usr-${Date.now()}`,
      email,
      name,
      role,
      avatarColor: DEMO_PROFILES[role]?.avatarColor || '#334d4a',
      initials: name.slice(0, 2).toUpperCase(),
    });
    return true;
  };

  const logout = async () => {
    if (supabase) {
      try {
        await supabase.auth.signOut();
      } catch (err) {
        console.error('Logout error:', err);
      }
    }
    setUser(null);
    setSession(null);
    setProfile(DEMO_PROFILES.VIEWER); // Reset to read-only viewer profile on logout
  };

  const switchRole = (newRole: UserRole) => {
    setProfile((prev) => ({
      ...DEMO_PROFILES[newRole],
      email: prev.email.includes('@') ? prev.email : DEMO_PROFILES[newRole].email,
    }));
  };

  const permissions = ROLE_PERMISSIONS[profile.role] || ROLE_PERMISSIONS.VIEWER;

  return (
    <AuthContext.Provider
      value={{
        user,
        session,
        profile,
        role: profile.role,
        permissions,
        isAuthenticated: !!user || !!profile.email,
        login,
        signup,
        logout,
        switchRole,
        isLoginModalOpen,
        setIsLoginModalOpen,
        isProfileModalOpen,
        setIsProfileModalOpen,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};
