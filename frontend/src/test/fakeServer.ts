import { vi } from 'vitest';

type Handler = (url: URL, init: RequestInit) => { status: number; body?: unknown; headers?: Record<string, string> };

/** Replaces fetch with a router of synthetic answers; records the calls. */
export function fakeServer(routes: Record<string, Handler>) {
  const calls: { method: string; url: URL; init: RequestInit }[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
    const url = new URL(String(input), 'http://localhost');
    const method = init.method ?? 'GET';
    calls.push({ method, url, init });
    const handler = routes[`${method} ${url.pathname}`];
    const r = handler ? handler(url, init) : { status: 404, body: { reason: 'NOT_FOUND', message: 'No such route.' } };
    return new Response(r.body === undefined ? null : JSON.stringify(r.body), {
      status: r.status,
      headers: { 'Content-Type': 'application/json', ...(r.headers ?? {}) },
    });
  });
  vi.stubGlobal('fetch', fetchMock);
  return { calls };
}

export const SYNTHETIC_EVENT = {
  eventId: '7e333ed3-40c7-1185-e8f9-081f9ff9ce6e',
  receivedAt: '2026-10-30T09:15:00Z',
  service: 'reqmod',
  platform: 'claude',
  surface: 'web',
  step: 'chat',
  verdict: 'REDACT',
  reason: 'customer_data',
  findings: [{ dataClass: 'TCKN', count: 2 }],
  bodyBytes: 2048,
  decisionMicros: 310,
  user: 'USR-0123456789',
  clientSubnet: '248.1.2.0/24',
  transport: 'plain_allowlisted',
  snapshotVersion: 1,
  correlationId: '7e333ed3-40c7-1185-e8f9-081f9ff9ce6e',
  pseudonymKeyId: 'k0000abcd',
};
