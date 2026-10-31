/**
 * Authentication and authorization types for SnareSight SOC.
 */

export type UserRole = 'ADMIN' | 'ANALYST' | 'VIEWER';

export interface User {
  user_id: string;
  username: string;
  email: string;
  full_name?: string;
  role: UserRole;
  is_active: boolean;
  permissions: string[];
}

export interface LoginCredentials {
  username: string;
  password: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in_minutes: number;
  user_id: string;
  username: string;
  role: UserRole;
  permissions: string[];
}

export interface ChangePasswordPayload {
  current_password: string;
  new_password: string;
}

export interface SystemAuditLogEntry {
  id: string;
  actor_username: string;
  actor_role: string;
  action: string;
  resource_type: string;
  resource_id?: string;
  outcome: 'SUCCESS' | 'DENIED' | 'FAILED';
  status_code?: number;
  reason?: string;
  ip_address?: string;
  user_agent?: string;
  request_context?: Record<string, any>;
  created_at: string;
}

export interface AuditLogListResponse {
  total: number;
  page: number;
  limit: number;
  items: SystemAuditLogEntry[];
}

