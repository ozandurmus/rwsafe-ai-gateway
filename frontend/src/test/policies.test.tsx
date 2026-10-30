import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Registry, RuleVersion } from '../api';
import { fakeServer } from './fakeServer';
import { renderApp } from './render';

afterEach(() => {
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

function version(ruleId: string, v: number, over: Partial<RuleVersion>): RuleVersion {
  return {
    ruleId,
    version: v,
    action: null,
    enforceFailClosed: null,
    hostSuffixes: null,
    apiHosts: null,
    loginHosts: null,
    mode: 'enforce',
    rolloutStage: 'all',
    status: 'active',
    source: 'seed',
    author: 'system:seed-fixture',
    reasonCode: 'SEED_FIXTURE',
    createdAt: '2026-10-30T09:00:00Z',
    activatedAt: '2026-10-30T09:00:00Z',
    supersededAt: null,
    approvals: [],
    inSnapshot: true,
    ...over,
  };
}

function registry(): Registry {
  return {
    rules: [
      {
        ruleId: 'class.SECRET',
        kind: 'class_action',
        subject: 'SECRET',
        failClosed: true,
        versions: [version('class.SECRET', 1, { action: 'BLOCK' })],
      },
      {
        ruleId: 'class.TCKN',
        kind: 'class_action',
        subject: 'TCKN',
        failClosed: true,
        versions: [
          version('class.TCKN', 2, {
            action: 'BLOCK',
            rolloutStage: 'pct25',
            status: 'pending',
            source: 'registry',
            author: 'USR-00000000a1',
            reasonCode: 'RISK_REVIEW',
            activatedAt: null,
            inSnapshot: false,
            approvals: [{ role: 'security_admin', approver: 'USR-00000000a1', approvedAt: '2026-10-30T10:00:00Z' }],
          }),
          version('class.TCKN', 1, { action: 'REDACT' }),
        ],
      },
      {
        ruleId: 'flow.ai-category',
        kind: 'flow',
        subject: 'ai-category',
        failClosed: true,
        versions: [version('flow.ai-category', 1, { enforceFailClosed: true })],
      },
      {
        ruleId: 'platform.claude',
        kind: 'platform',
        subject: 'claude',
        failClosed: false,
        versions: [
          version('platform.claude', 1, {
            hostSuffixes: ['claude.ai', 'anthropic.com'],
            apiHosts: ['api.anthropic.com'],
            loginHosts: [],
          }),
        ],
      },
    ],
    snapshot: {
      version: 3,
      id: 'registry-0123456789ab',
      issuedAt: '2026-10-30T10:00:00Z',
      documentSha256: 'a'.repeat(64),
      ruleVersions: ['class.SECRET@v1'],
      approvers: ['system:seed-fixture'],
      keyId: 'synthetic-key',
    },
    failClosedClasses: ['SECRET', 'TCKN', 'TR_IBAN', 'PAYMENT_CARD'],
    actions: ['ALLOW', 'WARN', 'REDACT', 'BLOCK'],
    modes: ['monitor', 'enforce'],
    stages: ['pilot', 'pct25', 'pct50', 'all'],
  };
}

const user = (name: string, roles: string[], masked = false) => ({
  displayName: masked ? 'masked session' : name,
  roles,
  masked,
  source: 'ldap',
});

describe('policies screen', () => {
  it('lists the registry in Turkish and lets the privacy officer give the second approval', async () => {
    const server = fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: user('synthetic-officer', ['privacy_officer']) }),
      'GET /api/v1/policy/rules': () => ({ status: 200, body: registry() }),
      'POST /api/v1/policy/rules/class.TCKN/versions/2/approvals': () => ({
        status: 200,
        body: version('class.TCKN', 2, { action: 'BLOCK', status: 'pending' }),
      }),
    });
    renderApp('/policies');
    const table = await screen.findByRole('table', { name: 'Politika kuralları' });
    expect(within(table).getByText('Gizli anahtar')).toBeInTheDocument();
    expect(within(table).getByText('Yapay zekâ kategorisi akışı')).toBeInTheDocument();
    expect(within(table).queryByText('Claude')).not.toBeInTheDocument();
    expect(within(table).getByText('1 onay bekliyor')).toBeInTheDocument();
    expect(within(table).getByRole('img', { name: 'Yayılım aşaması: %25' })).toBeInTheDocument();
    expect(screen.getByText(/Etkin anlık görüntü v3/)).toBeInTheDocument();

    await userEvent.click(within(table).getByText('TCKN'));
    expect(await screen.findByText('Güvenlik yöneticisi onayı')).toBeInTheDocument();
    expect(screen.getAllByText(/USR-00000000a1/).length).toBeGreaterThan(0);
    expect(screen.queryByRole('heading', { name: 'Yeni sürüm' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Veri koruma sorumlusu olarak onayla' }));
    await waitFor(() =>
      expect(server.calls.some((c) => c.method === 'POST' && c.url.pathname.endsWith('/approvals'))).toBe(true),
    );
    const post = server.calls.find((c) => c.method === 'POST')!;
    expect(JSON.parse(String(post.init.body))).toEqual({ role: 'privacy_officer' });
    await waitFor(() =>
      expect(server.calls.filter((c) => c.url.pathname === '/api/v1/policy/rules').length).toBeGreaterThan(1),
    );
  });

  it('runs the simulation for a class rule and shows counts only', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: user('synthetic-viewer', ['viewer']) }),
      'GET /api/v1/policy/rules': () => ({ status: 200, body: registry() }),
      'GET /api/v1/policy/simulation': (url) => ({
        status: 200,
        body: {
          ruleId: url.searchParams.get('ruleId'),
          dataClass: 'TCKN',
          currentAction: 'REDACT',
          proposedAction: url.searchParams.get('action'),
          from: '2026-10-23T10:00:00Z',
          to: '2026-10-30T10:00:00Z',
          eventsInWindow: 12000,
          eventsWithClass: 300,
          eventsChanged: 280,
          eventsNotReevaluated: 20,
          transitions: [{ from: 'REDACT', to: 'BLOCK', events: 280 }],
        },
      }),
    });
    renderApp('/policies', 'en');
    await userEvent.click(within(await screen.findByRole('table', { name: 'Policy rules' })).getByText('TCKN'));
    await userEvent.click(screen.getByRole('button', { name: 'Simulate' }));
    expect(
      await screen.findByText('Last 7 days: 12,000 events, 300 with this class, 280 would change.'),
    ).toBeInTheDocument();
    expect(screen.getByText('Redacted → Blocked: 280')).toBeInTheDocument();
    expect(screen.getByText('Current action: Redact')).toBeInTheDocument();
  });

  it('offers the security administrator a draft without Allow or Warn for a fail-closed class', async () => {
    const server = fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: user('synthetic-admin', ['security_admin']) }),
      'GET /api/v1/policy/rules': () => ({ status: 200, body: registry() }),
      'POST /api/v1/policy/rules/class.SECRET/versions': () => ({
        status: 201,
        body: version('class.SECRET', 2, { action: 'BLOCK', status: 'pending' }),
      }),
    });
    renderApp('/policies', 'en');
    await userEvent.click(within(await screen.findByRole('table', { name: 'Policy rules' })).getByText('Secret'));
    expect(screen.getByText(/Allow and Warn are never offered/)).toBeInTheDocument();
    await userEvent.click(screen.getByLabelText('Action'));
    const options = within(screen.getByRole('listbox')).getAllByRole('option').map((o) => o.textContent);
    expect(options).toEqual(['Redact', 'Block']);
    await userEvent.click(screen.getByRole('option', { name: 'Block' }));
    await userEvent.type(screen.getByLabelText('Reason code'), 'risk_review');
    await userEvent.click(screen.getByRole('button', { name: 'Submit for approval' }));
    expect(await screen.findByText('Version 2 awaits two approvals.')).toBeInTheDocument();
    const post = server.calls.find((c) => c.method === 'POST')!;
    expect(JSON.parse(String(post.init.body))).toEqual({
      action: 'BLOCK',
      mode: 'enforce',
      rolloutStage: 'pilot',
      reasonCode: 'RISK_REVIEW',
    });
  });

  it('shows a masked session the registry without any action', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: user('', ['replay_viewer'], true) }),
      'GET /api/v1/policy/rules': () => ({ status: 200, body: registry() }),
    });
    renderApp('/policies');
    await userEvent.click(within(await screen.findByRole('table', { name: 'Politika kuralları' })).getByText('TCKN'));
    expect(await screen.findByText('Güvenlik yöneticisi onayı')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /olarak onayla/ })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Onaya gönder' })).not.toBeInTheDocument();
    expect(screen.getByText('Maskeli görünüm')).toBeInTheDocument();
  });

  it('shows the server reason when an approval is refused', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: user('synthetic-admin', ['security_admin']) }),
      'GET /api/v1/policy/rules': () => {
        const r = registry();
        r.rules[1]!.versions[0]!.approvals = [];
        return { status: 200, body: r };
      },
      'POST /api/v1/policy/rules/class.TCKN/versions/2/approvals': () => ({
        status: 409,
        body: { reason: 'APPROVER_ALREADY_APPROVED', message: 'The two approvals must come from two different people.' },
      }),
    });
    renderApp('/policies');
    await userEvent.click(within(await screen.findByRole('table', { name: 'Politika kuralları' })).getByText('TCKN'));
    await userEvent.click(await screen.findByRole('button', { name: 'Güvenlik yöneticisi olarak onayla' }));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('İkinci onay başka bir kişiden gelmeli');
    expect(alert).toHaveTextContent('APPROVER_ALREADY_APPROVED');
  });
});

describe('platforms screen', () => {
  it('lists the platform rows with their vendor hosts', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: user('synthetic-viewer', ['viewer']) }),
      'GET /api/v1/policy/rules': () => ({ status: 200, body: registry() }),
    });
    renderApp('/platforms');
    const table = await screen.findByRole('table', { name: 'Platform satırları' });
    expect(within(table).getByText('Claude')).toBeInTheDocument();
    expect(within(table).getByText('api.anthropic.com')).toBeInTheDocument();
    expect(within(table).getByText('Anlık görüntüde')).toBeInTheDocument();
    expect(within(table).queryByText('TCKN')).not.toBeInTheDocument();
  });
});
