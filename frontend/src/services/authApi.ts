/**
 * API client for SnareSight authentication, password management, and security audit logs.
 */

import {
  LoginCredentials,
  TokenResponse,
  User,
  ChangePasswordPayload,
  AuditLogListResponse,
} from '../types/auth';

const BASE_URL = '/api/v1';

export const authApi = {
  /**
   * Authenticate with username and password.
   */
  async login(credentials: LoginCredentials): Promise<TokenResponse> {
    const res = await fetch(`${BASE_URL}/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(credentials),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Authentication failed' }));
      throw new Error(err.detail || 'Authentication failed');
    }
    const data: TokenResponse = await res.json();
    // Cache token in memory / sessionStorage for cross-tab sessions
    sessionStorage.setItem('snaresight_token', data.access_token);
    return data;
  },

  /**
   * Terminate active session and invalidate JWT token.
   */
  async logout(): Promise<void> {
    const token = sessionStorage.getItem('snaresight_token');
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    try {
      await fetch(`${BASE_URL}/auth/logout`, {
        method: 'POST',
        headers,
      });
    } finally {
      sessionStorage.removeItem('snaresight_token');
    }
  },

  /**
   * Retrieve currently authenticated user context and permissions.
   */
  async getMe(): Promise<User | null> {
    const token = sessionStorage.getItem('snaresight_token');
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const res = await fetch(`${BASE_URL}/auth/me`, { headers });
    if (!res.ok) {
      return null;
    }
    return res.json();
  },

  /**
   * Update authenticated analyst password.
   */
  async changePassword(payload: ChangePasswordPayload): Promise<{ message: string }> {
    const token = sessionStorage.getItem('snaresight_token');
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const res = await fetch(`${BASE_URL}/auth/change-password`, {
      method: 'POST',
      headers,
      body: JSON.stringify(payload),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Password change failed' }));
      throw new Error(err.detail || 'Password change failed');
    }
    return res.json();
  },

  /**
   * Query immutable security audit logs.
   */
  async getAuditLogs(params: {
    action?: string;
    actor_username?: string;
    outcome?: string;
    page?: number;
    limit?: number;
  } = {}): Promise<AuditLogListResponse> {
    const token = sessionStorage.getItem('snaresight_token');
    const headers: Record<string, string> = {};
    if (token) headers['Authorization'] = `Bearer ${token}`;

    const searchParams = new URLSearchParams();
    if (params.action) searchParams.append('action', params.action);
    if (params.actor_username) searchParams.append('actor_username', params.actor_username);
    if (params.outcome) searchParams.append('outcome', params.outcome);
    if (params.page) searchParams.append('page', params.page.toString());
    if (params.limit) searchParams.append('limit', params.limit.toString());

    const res = await fetch(`${BASE_URL}/audit/logs?${searchParams.toString()}`, { headers });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Failed to fetch audit logs' }));
      throw new Error(err.detail || 'Failed to fetch audit logs');
    }
    return res.json();
  },
};

