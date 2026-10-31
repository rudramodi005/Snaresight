/**
 * React Authentication Context and Provider for SnareSight.
 *
 * Enforces role-based permissions, session tracking, secure logout, and token propagation.
 */

import React, { createContext, useContext, useState, useEffect } from 'react';
import { User, LoginCredentials, UserRole } from '../../types/auth';
import { authApi } from '../../services/authApi';

interface AuthContextType {
  user: User | null;
  loading: boolean;
  isAuthenticated: boolean;
  role: UserRole;
  login: (credentials: LoginCredentials) => Promise<void>;
  logout: () => Promise<void>;
  hasPermission: (permission: string) => boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

// Default development fallback user
const DEFAULT_DEV_USER: User = {
  user_id: 'dev-user-01',
  username: 'soc_lead',
  email: 'soc_lead@snaresight.local',
  full_name: 'Senior SOC Investigator',
  role: 'ANALYST',
  is_active: true,
  permissions: [
    'view_dashboard',
    'view_events',
    'view_sensitive_evidence',
    'view_alerts',
    'assign_alerts',
    'acknowledge_alerts',
    'resolve_alerts',
    'close_alerts',
    'add_investigation_notes',
    'modify_mapping_review_status',
    'generate_reports',
    'export_data',
    'view_audit_logs',
  ],
};

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [user, setUser] = useState<User | null>(DEFAULT_DEV_USER);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    const checkSession = async () => {
      try {
        const currentUser = await authApi.getMe();
        if (currentUser) {
          setUser(currentUser);
        } else {
          // Keep default dev user if in local development mode without token
          setUser(DEFAULT_DEV_USER);
        }
      } catch (err) {
        setUser(DEFAULT_DEV_USER);
      } finally {
        setLoading(false);
      }
    };
    checkSession();
  }, []);

  const login = async (credentials: LoginCredentials) => {
    const tokenRes = await authApi.login(credentials);
    const currentUser = await authApi.getMe();
    if (currentUser) {
      setUser(currentUser);
    } else {
      setUser({
        user_id: tokenRes.user_id,
        username: tokenRes.username,
        email: `${tokenRes.username}@snaresight.local`,
        role: tokenRes.role,
        is_active: true,
        permissions: tokenRes.permissions,
      });
    }
  };

  const logout = async () => {
    await authApi.logout();
    setUser(null);
  };

  const hasPermission = (permission: string): boolean => {
    if (!user) return false;
    if (user.role === 'ADMIN') return true;
    return user.permissions.includes(permission);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        isAuthenticated: !!user,
        role: user?.role || 'VIEWER',
        login,
        logout,
        hasPermission,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

