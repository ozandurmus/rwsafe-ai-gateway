import { afterEach, describe, expect, it, vi } from 'vitest';
import { ApiError, api } from '../api';
import { fakeServer } from './fakeServer';

afterEach(() => {
  vi.unstubAllGlobals();
  document.cookie = 'XSRF-TOKEN=; expires=Thu, 01 Jan 1970 00:00:00 GMT';
});

describe('api client', () => {
  it('carries the server reason and sentence on a failure', async () => {
    fakeServer({
      'GET /api/v1/traffic': () => ({
        status: 400,
        body: { reason: 'INVALID_USER_FILTER', message: 'The user filter takes a USR- pseudonym only.' },
      }),
    });
    const e = await api.traffic({ user: 'x' }).catch((err) => err);
    expect(e).toBeInstanceOf(ApiError);
    expect(e.status).toBe(400);
    expect(e.reason).toBe('INVALID_USER_FILTER');
    expect(e.message).toContain('pseudonym');
  });

  it('names the status when the server gives no reason', async () => {
    fakeServer({ 'GET /api/v1/health': () => ({ status: 502 }) });
    const e = await api.health().catch((err) => err);
    expect(e.reason).toBe('HTTP_502');
  });

  it('reports an unreachable control plane with a reason', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Promise.reject(new TypeError('network'))));
    const e = await api.me().catch((err) => err);
    expect(e.reason).toBe('CONTROL_PLANE_UNREACHABLE');
  });

  it('sends the CSRF cookie as a header on a mutation and the filters as a query', async () => {
    const server = fakeServer({
      'GET /api/v1/auth/csrf': () => ({ status: 200, body: { headerName: 'X-XSRF-TOKEN', token: 'synthetic-token' } }),
      'POST /api/v1/auth/login': () => ({
        status: 200,
        body: { displayName: 'synthetic-viewer', roles: ['viewer'], masked: false, source: 'ldap' },
      }),
      'GET /api/v1/traffic': () => ({ status: 200, body: { items: [], nextCursor: null } }),
    });
    document.cookie = 'XSRF-TOKEN=synthetic-token';
    await api.login('synthetic-viewer', 'synthetic-password');
    const post = server.calls.find((c) => c.method === 'POST');
    expect((post?.init.headers as Record<string, string>)['X-XSRF-TOKEN']).toBe('synthetic-token');
    await api.traffic({ platform: 'claude', verdict: 'BLOCK', user: '', limit: 50 });
    const get = server.calls.filter((c) => c.url.pathname === '/api/v1/traffic')[0];
    expect(get?.url.searchParams.get('platform')).toBe('claude');
    expect(get?.url.searchParams.get('verdict')).toBe('BLOCK');
    expect(get?.url.searchParams.has('user')).toBe(false);
  });
});
