import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Registry, RuleVersion } from '../api';
import { foldGroupName } from '../pages/PoliciesPage';
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
    scope: { kind: 'ANY', groups: [] },
    retirement: null,
    withdrawal: null,
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
          version('class.TCKN', 3, {
            action: 'BLOCK',
            scope: { kind: 'GROUPS', groups: ['GRP-ALPHA', 'GRP-GAMMA'] },
            status: 'pending',
            source: 'registry',
            author: 'USR-00000000a1',
            reasonCode: 'RISK_REVIEW',
            activatedAt: null,
            inSnapshot: false,
            approvals: [{ role: 'security_admin', approver: 'USR-00000000a1', approvedAt: '2026-10-30T10:00:00Z' }],
          }),
          version('class.TCKN', 2, {
            action: 'BLOCK',
            scope: { kind: 'GROUPS', groups: ['GRP-BETA'] },
            source: 'registry',
            author: 'USR-00000000a1',
            reasonCode: 'RISK_REVIEW',
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
      {
        ruleId: 'platform.github',
        kind: 'platform',
        subject: 'github',
        failClosed: false,
        versions: [
          version('platform.github', 1, {
            hostSuffixes: ['github.com'],
            apiHosts: ['api.github.com'],
            loginHosts: [],
            status: 'retired',
            inSnapshot: false,
            retirement: { retiredAt: '2026-10-30T11:00:00Z', retiredBy: 'USR-00000000a1', reason: 'Synthetic retirement' },
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
    scopeKinds: ['ANY', 'GROUPS'],
    maxScopeGroups: 32,
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
      'POST /api/v1/policy/rules/class.TCKN/versions/3/approvals': () => ({
        status: 200,
        body: version('class.TCKN', 3, { action: 'BLOCK', status: 'pending' }),
      }),
    });
    renderApp('/policies');
    const table = await screen.findByRole('table', { name: 'Politika kuralları' });
    expect(within(table).getByText('Gizli anahtar')).toBeInTheDocument();
    expect(within(table).getByText('Yapay zekâ kategorisi akışı')).toBeInTheDocument();
    expect(within(table).queryByText('Claude')).not.toBeInTheDocument();
    expect(within(table).getByText('1 onay bekliyor')).toBeInTheDocument();
    expect(within(table).queryByRole('img', { name: /Yayılım aşaması/ })).not.toBeInTheDocument();
    expect(within(table).getByRole('columnheader', { name: 'Kapsam' })).toBeInTheDocument();
    expect(within(table).getAllByText('Herkes').length).toBeGreaterThan(0);
    expect(within(table).getByText('GRP-BETA')).toBeInTheDocument();
    expect(within(table).queryByText('GRP-ALPHA')).not.toBeInTheDocument();
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
      scope: { kind: 'ANY', groups: [] },
      reasonCode: 'RISK_REVIEW',
    });
  });

  it('drafts a group-scoped version with the scope picker', async () => {
    const server = fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: user('synthetic-admin', ['security_admin']) }),
      'GET /api/v1/policy/rules': () => {
        const r = registry();
        r.maxScopeGroups = 2;
        return { status: 200, body: r };
      },
      'POST /api/v1/policy/rules/class.SECRET/versions': () => ({
        status: 201,
        body: version('class.SECRET', 2, { action: 'REDACT', status: 'pending' }),
      }),
    });
    renderApp('/policies');
    await userEvent.click(within(await screen.findByRole('table', { name: 'Politika kuralları' })).getByText('Gizli anahtar'));
    expect(screen.queryByRole('textbox', { name: 'Dizin grubu' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('radio', { name: 'Seçilen dizin grupları' }));
    expect(screen.getByText('En az bir grup ekleyin.')).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('Gerekçe kodu'), 'risk_review');
    expect(screen.getByRole('button', { name: 'Onaya gönder' })).toBeDisabled();
    const field = screen.getByRole('textbox', { name: 'Dizin grubu' });
    expect(screen.getByText(/Kısa dizin grubu adını virgül kullanmadan yazıp/)).toBeInTheDocument();
    await userEvent.type(field, 'GRP-ALPHA,GRP-BETA{Enter}');
    expect(screen.getByText(/grup adında virgül olmaz/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Grubu ekle' })).toBeDisabled();
    expect(screen.getByText('En az bir grup ekleyin.')).toBeInTheDocument();
    await userEvent.clear(field);
    await userEvent.type(field, '  GRP-ALPHA {Enter}');
    await userEvent.type(field, 'grp-alpha{Enter}');
    await userEvent.type(field, 'GRP-ALPHA{Enter}');
    expect(screen.getAllByText(/^GRP-ALPHA$/i)).toHaveLength(1);
    await userEvent.type(field, 'GRP-BETA');
    await userEvent.click(screen.getByRole('button', { name: 'Grubu ekle' }));
    expect(screen.getByText('En çok 2 grup eklenebilir.')).toBeInTheDocument();
    expect(screen.getByRole('textbox', { name: 'Dizin grubu' })).toBeDisabled();
    await userEvent.click(screen.getByRole('button', { name: 'GRP-BETA grubunu çıkar' }));
    expect(screen.getAllByText('GRP-BETA')).toHaveLength(1); // the table's chip only
    await userEvent.type(screen.getByRole('textbox', { name: 'Dizin grubu' }), 'GRP-DELTA{Enter}');
    await userEvent.click(screen.getByRole('button', { name: 'Onaya gönder' }));
    expect(await screen.findByText('Sürüm 2 iki onay bekliyor.')).toBeInTheDocument();
    const post = server.calls.find((c) => c.method === 'POST')!;
    expect(JSON.parse(String(post.init.body))).toEqual({
      action: 'BLOCK',
      mode: 'enforce',
      scope: { kind: 'GROUPS', groups: ['GRP-ALPHA', 'GRP-DELTA'] },
      reasonCode: 'RISK_REVIEW',
    });
    expect(JSON.stringify(window.localStorage)).not.toContain('GRP-');
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
      'POST /api/v1/policy/rules/class.TCKN/versions/3/approvals': () => ({
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

describe('group name folding', () => {
  it('folds the Turkish and Latin i forms, case, NFC and spaces like the server', () => {
    const expected = 'grp-istanbul-iki';
    for (const raw of [
      'GRP-\u0130STANBUL-\u0130K\u0130',
      '  grp-Istanbul-Iki ',
      'grp-\u0131stanbul-\u0131k\u0131',
      'grp-i\u0307stanbul-iki',
      'GRP-I\u0307STANBUL-IKI',
    ]) {
      expect(foldGroupName(raw)).toBe(expected);
    }
    expect(foldGroupName('GRP-E\u0301QUIPE')).toBe('grp-\u00e9quipe');
  });
});

describe('withdrawing a group scope', () => {
  it('withdraws at once with a reason and an in-page confirmation, without approval steps', async () => {
    let withdrawn = false;
    const withdrawal = {
      withdrawsVersion: null,
      reason: 'Pilot finished',
      withdrawnAt: '2026-10-31T09:15:00Z',
      withdrawnBy: 'USR-00000000a1',
    };
    const server = fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: user('synthetic-admin', ['security_admin']) }),
      'GET /api/v1/policy/rules': () => {
        const r = registry();
        const tckn = r.rules[1]!;
        if (withdrawn) {
          tckn.versions = tckn.versions.map((v) =>
            v.version === 2 ? { ...v, status: 'withdrawn', inSnapshot: false, withdrawal } : v,
          );
        }
        return { status: 200, body: r };
      },
      'POST /api/v1/policy/rules/class.TCKN/versions/2/withdrawal': () => {
        withdrawn = true;
        return {
          status: 200,
          body: version('class.TCKN', 2, {
            action: 'BLOCK',
            scope: { kind: 'GROUPS', groups: ['GRP-BETA'] },
            status: 'withdrawn',
            source: 'registry',
            inSnapshot: false,
            withdrawal,
          }),
        };
      },
    });
    const confirm = vi.fn(() => true);
    vi.stubGlobal('confirm', confirm);
    renderApp('/policies');
    await userEvent.click(within(await screen.findByRole('table', { name: 'Politika kuralları' })).getByText('TCKN'));
    const buttons = screen.getAllByRole('button', { name: 'Geri çek' });
    expect(buttons).toHaveLength(1);
    await userEvent.click(buttons[0]!);
    const form = screen.getByRole('form', { name: 'Sürüm 2 gruplarından geri çekilsin' });
    expect(within(form).getByRole('button', { name: 'Devam et' })).toBeDisabled();
    await userEvent.type(within(form).getByRole('textbox', { name: /Gerekçe/ }), 'Pilot finished');
    await userEvent.click(within(form).getByRole('button', { name: 'Devam et' }));
    expect(within(form).getByText(/Sürüm 2 hemen geri çekilecek; onay beklenmez/)).toBeInTheDocument();
    expect(server.calls.some((c) => c.method === 'POST')).toBe(false);
    await userEvent.click(within(form).getByRole('button', { name: 'Evet, geri çek' }));
    expect(
      await screen.findByText('Sürüm 2 geri çekildi. Bu gruplara artık herkese uygulanan kural uygulanıyor.'),
    ).toBeInTheDocument();
    const posts = server.calls.filter((c) => c.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(JSON.parse(String(posts[0]!.init.body))).toEqual({ reason: 'Pilot finished' });
    expect(
      await screen.findByText(/31\.10\.2026 12:15:00 tarihinde USR-00000000a1 tarafından geri çekildi\. Gerekçe: Pilot finished/),
    ).toBeInTheDocument();
    expect(screen.getByText(/GRP-BETA · Geri çekildi/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Geri çek' })).not.toBeInTheDocument();
    expect(screen.queryByText(/geri çekiliyor/)).not.toBeInTheDocument();
    expect(screen.queryByText(/geri çekme isteği/i)).not.toBeInTheDocument();
    expect(confirm).not.toHaveBeenCalled();
  });

  it('shows the server reason when the withdrawal is refused and changes nothing', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: user('synthetic-admin', ['security_admin']) }),
      'GET /api/v1/policy/rules': () => ({ status: 200, body: registry() }),
      'POST /api/v1/policy/rules/class.TCKN/versions/2/withdrawal': () => ({
        status: 400,
        body: { reason: 'REASON_HOLDS_IDENTIFIER', message: 'The reason holds an identifier.' },
      }),
    });
    renderApp('/policies');
    await userEvent.click(within(await screen.findByRole('table', { name: 'Politika kuralları' })).getByText('TCKN'));
    await userEvent.click(screen.getByRole('button', { name: 'Geri çek' }));
    const form = screen.getByRole('form', { name: 'Sürüm 2 gruplarından geri çekilsin' });
    await userEvent.type(within(form).getByRole('textbox', { name: /Gerekçe/ }), 'Synthetic reason');
    await userEvent.click(within(form).getByRole('button', { name: 'Devam et' }));
    await userEvent.click(within(form).getByRole('button', { name: 'Evet, geri çek' }));
    expect(await within(form).findByText('Gerekçede kimlik bilgisi var')).toBeInTheDocument();
    expect(screen.queryByText(/geri çekildi\./)).not.toBeInTheDocument();
    expect(within(form).getByRole('button', { name: 'Devam et' })).toBeInTheDocument();
  });

  it('offers no withdrawal to the viewer, the privacy officer or a masked session', async () => {
    for (const me of [
      user('synthetic-viewer', ['viewer']),
      user('synthetic-officer', ['privacy_officer']),
      user('', ['replay_viewer', 'security_admin'], true),
    ]) {
      fakeServer({
        'GET /api/v1/auth/me': () => ({ status: 200, body: me }),
        'GET /api/v1/policy/rules': () => ({ status: 200, body: registry() }),
      });
      const view = renderApp('/policies');
      await userEvent.click(within(await screen.findByRole('table', { name: 'Politika kuralları' })).getByText('TCKN'));
      expect(screen.queryByRole('button', { name: 'Geri çek' })).not.toBeInTheDocument();
      view.unmount();
      vi.unstubAllGlobals();
    }
  });
});

describe('platforms screen', () => {
  it('lists the platform rows with their vendor hosts and a retired row greyed with its reason', async () => {
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
    const retired = within(table).getByText('github').closest('tr')!;
    expect(retired).toHaveAttribute('data-retired', 'true');
    expect(within(retired).getByText('Kullanımdan kaldırıldı')).toBeInTheDocument();
    expect(within(retired).getByText(/Gerekçe: Synthetic retirement/)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Kullanımdan kaldır' })).not.toBeInTheDocument();
  });

  it('offers no retire action to a masked session', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: user('', ['replay_viewer', 'security_admin'], true) }),
      'GET /api/v1/policy/rules': () => ({ status: 200, body: registry() }),
    });
    renderApp('/platforms');
    await screen.findByRole('table', { name: 'Platform satırları' });
    expect(screen.queryByRole('button', { name: 'Kullanımdan kaldır' })).not.toBeInTheDocument();
  });

  it('lets the security administrator retire a platform with a reason and a confirmation step', async () => {
    let retired = false;
    const server = fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: user('synthetic-admin', ['security_admin']) }),
      'GET /api/v1/policy/rules': () => {
        const r = registry();
        if (retired) {
          r.rules[3]!.versions[0]!.status = 'retired';
          r.rules[3]!.versions[0]!.retirement = {
            retiredAt: '2026-10-30T12:00:00Z',
            retiredBy: 'USR-00000000a1',
            reason: 'Synthetic vendor change',
          };
        }
        return { status: 200, body: r };
      },
      'POST /api/v1/policy/rules/platform.claude/retirement': () => {
        retired = true;
        return { status: 200, body: { retired: [] } };
      },
    });
    const confirm = vi.fn(() => true);
    vi.stubGlobal('confirm', confirm);
    renderApp('/platforms');
    const table = await screen.findByRole('table', { name: 'Platform satırları' });
    const buttons = within(table).getAllByRole('button', { name: 'Kullanımdan kaldır' });
    expect(buttons).toHaveLength(1);
    await userEvent.click(buttons[0]!);
    const form = screen.getByRole('form', { name: 'Claude platformunu kullanımdan kaldır' });
    expect(within(form).getByRole('button', { name: 'Devam et' })).toBeDisabled();
    await userEvent.type(within(form).getByRole('textbox', { name: /Gerekçe/ }), '   ');
    expect(within(form).getByRole('button', { name: 'Devam et' })).toBeDisabled();
    await userEvent.type(within(form).getByRole('textbox', { name: /Gerekçe/ }), 'Synthetic vendor change ');
    await userEvent.click(within(form).getByRole('button', { name: 'Devam et' }));
    expect(within(form).getByText(/Claude kullanımdan kaldırılacak/)).toBeInTheDocument();
    expect(server.calls.some((c) => c.method === 'POST')).toBe(false);
    await userEvent.click(within(form).getByRole('button', { name: 'Evet, kullanımdan kaldır' }));
    expect(await screen.findByText('Claude kullanımdan kaldırıldı.')).toBeInTheDocument();
    const post = server.calls.find((c) => c.method === 'POST')!;
    expect(JSON.parse(String(post.init.body))).toEqual({ reason: 'Synthetic vendor change' });
    expect(confirm).not.toHaveBeenCalled();
    await waitFor(() => expect(within(screen.getByRole('table')).getByText(/Gerekçe: Synthetic vendor change/)).toBeInTheDocument());
  });

  it('shows the server reason when a retirement is refused', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: user('synthetic-admin', ['security_admin']) }),
      'GET /api/v1/policy/rules': () => ({ status: 200, body: registry() }),
      'POST /api/v1/policy/rules/platform.claude/retirement': () => ({
        status: 409,
        body: {
          reason: 'RETIRE_WOULD_NOT_COMPILE',
          message: 'This retirement would leave a registry that does not compile; nothing changed.',
        },
      }),
    });
    renderApp('/platforms');
    const table = await screen.findByRole('table', { name: 'Platform satırları' });
    await userEvent.click(within(table).getByRole('button', { name: 'Kullanımdan kaldır' }));
    await userEvent.type(screen.getByRole('textbox', { name: /Gerekçe/ }), 'Synthetic');
    await userEvent.click(screen.getByRole('button', { name: 'Devam et' }));
    await userEvent.click(screen.getByRole('button', { name: 'Evet, kullanımdan kaldır' }));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Kaldırmak anlık görüntüyü bozar');
    expect(alert).toHaveTextContent('nothing changed');
  });
});
