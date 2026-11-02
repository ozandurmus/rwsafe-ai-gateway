import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { RAIL, selectedPath, visibleSections } from '../navigation';
import { toggleRole } from '../pages/admin/LocalUsersPage';
import { fakeServer } from './fakeServer';
import { renderApp } from './render';

// PO decision Q-47: the sectioned rail, the Administration page with its grouped menu, and Access part 1 (local users,
// sessions, roles and permissions). Every value is synthetic; the passwords are built at runtime (AGENTS.md 4.5).

const ONE_TIME = ['Synthetic', 'One', 'Time', '01'].join('');
const NEXT = ['Synthetic', 'long', 'pass', '1'].join('-');
const OTHER = ['Synthetic', 'long', 'pass', '2'].join('-');

const admin = { displayName: 'synthetic-admin', roles: ['security_admin'], masked: false, source: 'ldap' };
const viewer = { displayName: 'synthetic-viewer', roles: ['viewer'], masked: false, source: 'ldap' };
const masked = { displayName: 'masked session', roles: ['replay_viewer'], masked: true, source: 'ldap' };
const health = {
  checkedAt: '2026-11-02T09:00:00Z',
  components: [],
  eventsLastFiveMinutes: 0,
  totalEvents: 0,
  latestEventAt: null,
};

const USER = {
  subject: 'USR-00000000a1',
  loginName: 'synthetic.person',
  displayName: 'Synthetic Person',
  roles: ['viewer'],
  enabled: true,
  passwordChangeRequired: false,
  createdAt: '2026-11-02T08:00:00Z',
  updatedAt: '2026-11-02T08:00:00Z',
  passwordChangedAt: '2026-11-02T08:30:00Z',
};

function users(list = [USER]) {
  return {
    users: list,
    breakGlass: [{ loginName: 'synthetic-breakglass', roles: ['security_admin'], enabled: true, signInEnabled: true }],
    roles: ['security_admin', 'privacy_officer', 'viewer', 'replay_viewer'],
    enabledSecurityAdmins: 1,
    minPasswordLength: 14,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

describe('layout', () => {
  it('groups the screens under the product principle and keeps every path', () => {
    const paths = RAIL.flatMap((s) => s.items.map((i) => i.path));
    expect(paths).toEqual(['/', '/traffic', '/policies', '/platforms', '/notice', '/health', '/admin']);
    expect(RAIL.map((s) => s.heading)).toEqual([null, 'rail.see', 'rail.guard', 'rail.govern', 'rail.operate']);
    expect(selectedPath(paths, '/traffic/7e333ed3')).toBe('/traffic');
    expect(selectedPath(paths, '/')).toBe('/');
    expect(selectedPath(paths, '/admin/users')).toBe('/admin');
    expect(selectedPath(paths, '/adminx')).toBeNull();
  });

  it('shows Administration to a security administrator and a privacy officer, never to a masked session', () => {
    const admins = (me: typeof admin) => visibleSections(RAIL, me).flatMap((s) => s.items.map((i) => i.path));
    expect(admins(admin)).toContain('/admin');
    expect(admins(viewer)).not.toContain('/admin');
    // Q-47 decision 1.3: the privacy officer reads the audit log, and only that.
    expect(admins({ ...admin, roles: ['privacy_officer'] })).toContain('/admin');
    expect(admins({ ...masked, roles: ['replay_viewer', 'security_admin'] })).not.toContain('/admin');
    expect(admins({ ...masked, roles: ['replay_viewer', 'privacy_officer'] })).not.toContain('/admin');
  });

  it('renders the rail with section headings, the selected screen and a collapse button', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: viewer }),
      'GET /api/v1/health': () => ({ status: 200, body: health }),
    });
    renderApp('/health');
    const rail = await screen.findByRole('navigation', { name: 'Ekranlar' });
    for (const heading of ['Görünürlük', 'Koruma', 'Yönetişim', 'İşletim']) {
      expect(within(rail).getByRole('heading', { name: heading })).toBeInTheDocument();
    }
    expect(within(rail).getByRole('link', { name: 'Sağlık' })).toHaveAttribute('aria-current', 'page');
    expect(within(rail).getByRole('link', { name: 'Trafik' })).not.toHaveAttribute('aria-current');
    expect(within(rail).queryByRole('link', { name: 'Yönetim' })).toBeNull();
    expect(screen.getByRole('combobox', { name: 'Ekranlarda ara' })).toBeInTheDocument();

    await userEvent.click(within(rail).getByRole('button', { name: 'Menüyü daralt' }));
    expect(within(rail).queryByRole('heading', { name: 'Koruma' })).toBeNull();
    expect(within(rail).getByRole('link', { name: 'Trafik' })).toBeInTheDocument();
    expect(within(rail).getByRole('button', { name: 'Menüyü genişlet' })).toBeInTheDocument();
    expect(window.localStorage.getItem('rwsafe.ui.railCollapsed')).toBe('true');
  });

  it('refuses Administration to a masked session without asking the server', async () => {
    const server = fakeServer({ 'GET /api/v1/auth/me': () => ({ status: 200, body: masked }) });
    renderApp('/admin/users');
    expect(
      await screen.findByText('Yönetim bölümünü yalnızca güvenlik yöneticisi veya gizlilik sorumlusu açabilir.'),
    ).toBeInTheDocument();
    expect(screen.queryByRole('link', { name: 'Yönetim' })).toBeNull();
    expect(server.calls.some((c) => c.url.pathname.startsWith('/api/v1/admin'))).toBe(false);
  });

  it('finds a screen from the top bar search', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: admin }),
      'GET /api/v1/health': () => ({ status: 200, body: health }),
      'GET /api/v1/admin/sessions': () => ({ status: 200, body: { sessions: [] } }),
    });
    renderApp('/health', 'en');
    await userEvent.type(await screen.findByRole('combobox', { name: 'Search screens' }), 'Sess');
    await userEvent.click(await screen.findByRole('option', { name: 'Administration · Sessions' }));
    expect(await screen.findByText('No open session.')).toBeInTheDocument();
  });
});

describe('administration', () => {
  it('shows the page title, description and the grouped menu with the selected item', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: admin }),
      'GET /api/v1/admin/users': () => ({ status: 200, body: users() }),
    });
    renderApp('/admin');
    expect(await screen.findByRole('heading', { name: 'Yönetim', level: 1 })).toBeInTheDocument();
    const menu = screen.getByRole('navigation', { name: 'Yönetim menüsü' });
    expect(within(menu).getByRole('heading', { name: 'Erişim' })).toBeInTheDocument();
    await waitFor(() =>
      expect(within(menu).getByRole('link', { name: 'Yerel kullanıcılar' })).toHaveAttribute('aria-current', 'page'),
    );
    expect(within(menu).getByRole('link', { name: 'Oturumlar' })).toBeInTheDocument();
    expect(within(menu).getByRole('link', { name: 'Roller ve yetkiler' })).toBeInTheDocument();
    expect(within(menu).getByRole('link', { name: 'LDAP ayarları' })).toBeInTheDocument();
    expect(await screen.findByText('synthetic.person')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Yönetim' })).toHaveAttribute('aria-current', 'page');
  });

  it('creates a local user with a reason and shows the one-time password once', async () => {
    let created = false;
    const server = fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: admin }),
      'GET /api/v1/admin/users': () => ({ status: 200, body: users(created ? [USER] : []) }),
      'POST /api/v1/admin/users': () => {
        created = true;
        return { status: 201, body: { user: { ...USER, passwordChangeRequired: true }, oneTimePassword: ONE_TIME } };
      },
    });
    renderApp('/admin/users', 'en');
    expect(await screen.findByText(/No local user yet/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'New user' }));
    const dialog = await screen.findByRole('dialog');
    const create = within(dialog).getByRole('button', { name: 'Create' });
    await userEvent.type(within(dialog).getByLabelText(/Login name/), 'synthetic.person');
    await userEvent.type(within(dialog).getByLabelText(/Display name/), 'Synthetic Person');
    await userEvent.click(within(dialog).getByRole('checkbox', { name: 'Viewer' }));
    expect(create).toBeDisabled();
    await userEvent.type(within(dialog).getByLabelText(/Reason/), 'synthetic onboarding');
    await userEvent.click(create);

    const issued = await screen.findByRole('dialog', { name: /One-time password/ });
    expect(within(issued).getByText(ONE_TIME)).toBeInTheDocument();
    const post = server.calls.find((c) => c.method === 'POST');
    expect(JSON.parse(String(post?.init.body))).toEqual({
      loginName: 'synthetic.person',
      displayName: 'Synthetic Person',
      roles: ['viewer'],
      reason: 'synthetic onboarding',
    });
    await userEvent.click(within(issued).getByRole('button', { name: 'I have passed it on' }));
    await waitFor(() => expect(screen.queryByText(ONE_TIME)).toBeNull());
    expect(await screen.findByText('synthetic.person')).toBeInTheDocument();
  });

  it('shows the server reason when the last administrator would be disabled', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: admin }),
      'GET /api/v1/admin/users': () => ({ status: 200, body: users([{ ...USER, roles: ['security_admin'] }]) }),
      [`POST /api/v1/admin/users/${USER.subject}/disable`]: () => ({
        status: 409,
        body: { reason: 'LAST_SECURITY_ADMIN', message: 'This change would leave no enabled security administrator.' },
      }),
    });
    renderApp('/admin/users', 'en');
    expect(await screen.findByRole('table', { name: 'Break-glass account' })).toHaveTextContent('breakglass');
    await userEvent.click(await screen.findByRole('button', { name: 'Disable' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText(/Reason/), 'synthetic');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Disable' }));
    const alert = await within(dialog).findByRole('alert');
    expect(alert).toHaveTextContent('The last security administrator stays');
    expect(alert).toHaveTextContent('LAST_SECURITY_ADMIN');
  });

  it('offers no change on the signed-in local administrator own row (PR 48 review D-01)', async () => {
    const localAdmin = { displayName: USER.loginName, roles: ['security_admin'], masked: false, source: 'local_user' };
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: localAdmin }),
      'GET /api/v1/admin/users': () => ({ status: 200, body: users([{ ...USER, roles: ['security_admin'] }]) }),
    });
    renderApp('/admin/users', 'en');
    const table = await screen.findByRole('table', { name: 'Local users' });
    for (const name of ['Roles', 'Disable', 'Reset password']) {
      expect(within(table).getByRole('button', { name })).toBeDisabled();
    }
    expect(within(table).getByText(/another security administrator changes it/)).toBeInTheDocument();
  });

  it('keeps the masked viewer role alone', () => {
    expect(toggleRole(['viewer', 'security_admin'], 'replay_viewer')).toEqual(['replay_viewer']);
    expect(toggleRole(['replay_viewer'], 'viewer')).toEqual(['viewer']);
    expect(toggleRole(['viewer'], 'security_admin')).toEqual(['security_admin', 'viewer']);
    expect(toggleRole(['viewer', 'security_admin'], 'viewer')).toEqual(['security_admin']);
  });

  it('lists sessions without addresses and ends another one with a reason', async () => {
    const server = fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: admin }),
      'GET /api/v1/admin/sessions': () => ({
        status: 200,
        body: {
          sessions: [
            {
              handle: 'h-current',
              loginName: 'synthetic-admin',
              source: 'ldap',
              roles: ['security_admin'],
              signedInAt: '2026-11-02T09:00:00Z',
              lastActivity: '2026-11-02T09:05:00Z',
              passwordChangePending: false,
              current: true,
            },
            {
              handle: 'h-other',
              loginName: 'synthetic.person',
              source: 'local_user',
              roles: ['viewer'],
              signedInAt: '2026-11-02T08:00:00Z',
              lastActivity: '2026-11-02T08:10:00Z',
              passwordChangePending: true,
              current: false,
            },
          ],
        },
      }),
      'POST /api/v1/admin/sessions/h-other/end': () => ({ status: 204 }),
    });
    renderApp('/admin/sessions');
    const table = await screen.findByRole('table', { name: 'Açık oturumlar' });
    expect(within(table).getByText('Bu oturum')).toBeInTheDocument();
    expect(within(table).getByText('Yerel kullanıcı')).toBeInTheDocument();
    expect(within(table).getByText('Parola değişikliği bekleniyor')).toBeInTheDocument();
    const ends = within(table).getAllByRole('button', { name: 'Oturumu kapat' });
    expect(ends).toHaveLength(1);
    await userEvent.click(ends[0]!);
    const dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText(/Gerekçe/), 'synthetic drill');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Oturumu kapat' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    const end = server.calls.find((c) => c.method === 'POST');
    expect(end?.url.pathname).toBe('/api/v1/admin/sessions/h-other/end');
    expect(JSON.parse(String(end?.init.body))).toEqual({ reason: 'synthetic drill' });
  });

  it('describes each role from the server rules', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: admin }),
      'GET /api/v1/admin/roles': () => ({
        status: 200,
        body: {
          roles: [
            { role: 'security_admin', masked: false, permissions: ['session.own', 'admin.access', 'screens.read'] },
            { role: 'replay_viewer', masked: true, permissions: ['session.own', 'screens.read'] },
          ],
          rules: [
            {
              id: 'admin.access',
              method: 'ANY',
              pattern: '/api/v1/admin/**',
              anyOf: ['security_admin'],
              maskedRefused: true,
              pendingAllowed: false,
            },
          ],
        },
      }),
    });
    renderApp('/admin/roles', 'en');
    expect(await screen.findByRole('heading', { name: 'Security administrator' })).toBeInTheDocument();
    expect(screen.getByRole('list', { name: 'Security administrator: May' })).toHaveTextContent(
      'Administration: users, roles, sessions',
    );
    expect(screen.getByRole('list', { name: 'Masked viewer: May' })).not.toHaveTextContent('Administration');
    expect(screen.getByText(/passes the server's masking funnel/)).toBeInTheDocument();
    expect(screen.getByRole('table', { name: /Rules in the order/ })).toHaveTextContent('/api/v1/admin/**');
  });
});

describe('password change', () => {
  it('holds a local user on the password change until it is done', async () => {
    let changed = false;
    const local = { displayName: 'synthetic.person', roles: ['viewer'], masked: false, source: 'local_user' };
    const server = fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: { ...local, passwordChangeRequired: !changed } }),
      'POST /api/v1/auth/password': () => {
        changed = true;
        return { status: 200, body: { ...local, passwordChangeRequired: false } };
      },
      'GET /api/v1/health': () => ({ status: 200, body: health }),
    });
    renderApp('/health', 'en');
    expect(await screen.findByRole('heading', { name: 'Set a new password' })).toBeInTheDocument();
    expect(screen.queryByRole('navigation', { name: 'Screens' })).toBeNull();
    const submit = screen.getByRole('button', { name: 'Save the password' });
    await userEvent.type(screen.getByLabelText(/Current password/), ONE_TIME);
    await userEvent.type(screen.getByLabelText(/^New password \*/), 'short');
    expect(screen.getByText('Too short')).toBeInTheDocument();
    await userEvent.clear(screen.getByLabelText(/^New password \*/));
    await userEvent.type(screen.getByLabelText(/^New password \*/), NEXT);
    await userEvent.type(screen.getByLabelText(/New password again/), OTHER);
    expect(screen.getByText('The two entries differ')).toBeInTheDocument();
    expect(submit).toBeDisabled();
    await userEvent.clear(screen.getByLabelText(/New password again/));
    await userEvent.type(screen.getByLabelText(/New password again/), NEXT);
    await userEvent.click(submit);
    expect(await screen.findByRole('navigation', { name: 'Screens' })).toBeInTheDocument();
    const post = server.calls.find((c) => c.method === 'POST');
    expect(JSON.parse(String(post?.init.body))).toEqual({
      currentPassword: ONE_TIME,
      newPassword: NEXT,
    });
  });
});
