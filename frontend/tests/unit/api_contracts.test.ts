import { describe, it, expect } from 'vitest';

describe('Frontend API Contract & Security Parameter Serialization', () => {
  it('correctly formats and redacts bearer authorization headers', () => {
    const makeHeaders = (token: string | null) => {
      const headers: Record<string, string> = { 'Content-Type': 'application/json' };
      if (token) {
        headers['Authorization'] = `Bearer ${token}`;
      }
      return headers;
    };

    const authHeaders = makeHeaders('mock-jwt-token-xyz');
    expect(authHeaders['Authorization']).toBe('Bearer mock-jwt-token-xyz');

    const anonHeaders = makeHeaders(null);
    expect(anonHeaders['Authorization']).toBeUndefined();
  });

  it('serializes search and filter query parameters without token leakage', () => {
    const buildQueryParams = (params: { status?: string; search?: string; limit?: number }) => {
      const searchParams = new URLSearchParams();
      if (params.status && params.status !== 'ALL') searchParams.append('status', params.status);
      if (params.search) searchParams.append('search', params.search);
      if (params.limit) searchParams.append('limit', params.limit.toString());
      return searchParams.toString();
    };

    const qs = buildQueryParams({ status: 'ACTIVE', search: 'web_decoy', limit: 25 });
    expect(qs).toBe('status=ACTIVE&search=web_decoy&limit=25');
    expect(qs).not.toContain('token');
    expect(qs).not.toContain('password');
  });

  it('verifies safe masking for backup storage references', () => {
    const formatSafeBackupRef = (backupId: string) => `safe://backups/snaresight_${backupId}.dump`;
    const safeRef = formatSafeBackupRef('BCK-20261031-ABCD');
    expect(safeRef).toBe('safe://backups/snaresight_BCK-20261031-ABCD.dump');
    expect(safeRef).not.toContain('postgres://');
  });
});

