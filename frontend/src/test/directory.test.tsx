import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { connectionOf, formOf } from '../pages/admin/DirectorySettingsPage';
import { fakeServer } from './fakeServer';
import { renderApp } from './render';

// PO decision Q-47, decision 1.2: Administration -> Access -> LDAP settings. Every value is synthetic (example.test,
// dc=example,dc=test); the bind password is built at runtime (AGENTS.md 4.5).

const BIND = ['synthetic', 'bind', 'value', '7'].join('-');
const admin = { displayName: 'synthetic-admin', roles: ['security_admin'], masked: false, source: 'ldap' };

const SETTINGS = {
  enabled: true,
  urls: ['ldaps://synthetic-dc1.example.test:636', 'ldaps://synthetic-dc2.example.test:636'],
  tlsMode: 'ldaps',
  caCertificateCount: 1,
  caCertificateNotAfter: '2027-11-02T00:00:00Z',
  bindDn: 'cn=synthetic-service,dc=example,dc=test',
  passwordSet: true,
  userSearchBase: 'ou=synthetic-people,dc=example,dc=test',
  userSearchFilter: '(sAMAccountName={0})',
  groupAttribute: 'memberOf',
  groupSearchBase: null,
  groupSearchFilter: null,
  connectTimeoutMs: 5000,
  responseTimeoutMs: 10000,
  groupRoles: [{ group: 'synthetic-admins', roles: ['security_admin'] }],
};

function view(overrides: Record<string, unknown> = {}) {
  return {
    status: 'ACTIVE',
    statusReason: null,
    keyState: 'AVAILABLE',
    deployValuesPresent: true,
    version: 3,
    settings: SETTINGS,
    roles: ['security_admin', 'privacy_officer', 'viewer', 'replay_viewer'],
    history: [
      { version: 3, createdAt: '2026-11-02T09:00:00Z', actor: 'USR-00000000a1', changeKind: 'group_roles', reason: 'regrouping' },
      { version: 1, createdAt: '2026-11-01T09:00:00Z', actor: 'system:deploy-seed', changeKind: 'seed', reason: 'seed' },
    ],
    maxUrls: 8,
    maxGroups: 500,
    testsPerMinute: 6,
    plainLdapAllowed: false,
    ...overrides,
  };
}

afterEach(() => {
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

describe('LDAP settings', () => {
  it('shows the saved connection, the password only as set, the groups and the history', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: admin }),
      'GET /api/v1/admin/directory': () => ({ status: 200, body: view() }),
    });
    renderApp('/admin/directory', 'en');
    expect(await screen.findByText('Directory sign-in is on')).toBeInTheDocument();
    expect(screen.getByText('Password saved')).toBeInTheDocument();
    expect((screen.getByLabelText('Service account password') as HTMLInputElement).value).toBe('');
    expect((screen.getByLabelText(/Directory addresses/) as HTMLTextAreaElement).value).toBe(SETTINGS.urls.join('\n'));
    expect(screen.getByText(/1 trusted certificate\(s\) saved/)).toBeInTheDocument();
    expect(screen.getByDisplayValue('synthetic-admins')).toBeInTheDocument();
    const history = screen.getByRole('table', { name: 'Change history' });
    expect(within(history).getByText('Copied from the installation')).toBeInTheDocument();
    expect(within(history).getByText('system:deploy-seed')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'LDAP settings' })).toHaveAttribute('aria-current', 'page');
  });

  it('says in plain words why the directory is unavailable', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: admin }),
      'GET /api/v1/admin/directory': () => ({
        status: 200,
        body: view({ status: 'NOT_CONFIGURED', statusReason: 'DIRECTORY_KEY_MISSING', keyState: 'MISSING', version: 0,
          settings: null, history: [] }),
      }),
    });
    renderApp('/admin/directory', 'tr');
    expect(await screen.findByText('Henüz dizin ayarlanmadı')).toBeInTheDocument();
    expect(screen.getByText(/Saklanan parolayı koruyan anahtar sunucuda yok/)).toBeInTheDocument();
    expect(screen.getByText('Parola yok')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Grupları kaydet' })).toBeDisabled();
  });

  it('tests the saved settings, then the entered ones, and shows the classified answer', async () => {
    const server = fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: admin }),
      'GET /api/v1/admin/directory': () => ({ status: 200, body: view() }),
      'POST /api/v1/admin/directory/test': (_url, init) => {
        const body = JSON.parse(String(init.body));
        return body.settings === null
          ? { status: 200, body: { result: 'OK', detail: null, server: 1, groupsFound: 3, groupsBound: 1,
              roles: ['security_admin'] } }
          : { status: 200, body: { result: 'TLS_FAILED', detail: 'CERTIFICATE_UNTRUSTED', server: 0, groupsFound: null,
              groupsBound: null, roles: [] } };
      },
    });
    renderApp('/admin/directory', 'en');
    await userEvent.type(await screen.findByLabelText(/Login name to look up/), 'synthetic.person');
    await userEvent.click(screen.getByRole('button', { name: 'Test connection' }));
    const ok = await screen.findByRole('status', { name: 'Test result' });
    expect(ok).toHaveTextContent('The connection works');
    expect(ok).toHaveTextContent('3 groups found, 1 of them bound to a role');
    expect(ok).toHaveTextContent('this person would get: Security administrator');
    const first = server.calls.find((c) => c.url.pathname.endsWith('/test'));
    expect(JSON.parse(String(first?.init.body))).toEqual({ settings: null, loginName: 'synthetic.person' });

    await userEvent.click(screen.getByLabelText('Remove the saved certificate'));
    await userEvent.click(screen.getByRole('button', { name: 'Test connection' }));
    await waitFor(() =>
      expect(screen.getByRole('status', { name: 'Test result' })).toHaveTextContent(
        "The encrypted connection could not be set up · the server's certificate is not trusted",
      ),
    );
    const second = server.calls.filter((c) => c.url.pathname.endsWith('/test'))[1];
    const sent = JSON.parse(String(second?.init.body));
    expect(sent.settings.clearCaCertificate).toBe(true);
    expect(sent.settings.newPassword).toBeUndefined();
  });

  it('saves the connection with a new password and a reason, never echoing the password back', async () => {
    let saved: Record<string, unknown> | null = null;
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: admin }),
      'GET /api/v1/admin/directory': () => ({ status: 200, body: view({ version: saved ? 4 : 3 }) }),
      'POST /api/v1/admin/directory/connection': (_url, init) => {
        saved = JSON.parse(String(init.body));
        return { status: 200, body: view({ version: 4 }) };
      },
    });
    renderApp('/admin/directory', 'en');
    await userEvent.type(await screen.findByLabelText('Service account password'), BIND);
    await userEvent.click(screen.getByRole('button', { name: 'Save connection' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText(/Reason/), 'service account rotation');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(saved).toMatchObject({
      expectedVersion: 3,
      newPassword: BIND,
      reason: 'service account rotation',
      tlsMode: 'ldaps',
      urls: SETTINGS.urls,
    });
    await waitFor(() => expect((screen.getByLabelText('Service account password') as HTMLInputElement).value).toBe(''));
  });

  it('adds and removes group rows and saves the bindings with a reason', async () => {
    let saved: { expectedVersion: number; bindings: unknown; reason: string } | null = null;
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: admin }),
      'GET /api/v1/admin/directory': () => ({ status: 200, body: view() }),
      'POST /api/v1/admin/directory/group-roles': (_url, init) => {
        saved = JSON.parse(String(init.body));
        return { status: 200, body: view({ version: 4 }) };
      },
    });
    renderApp('/admin/directory', 'en');
    await screen.findByDisplayValue('synthetic-admins');
    await userEvent.click(screen.getByRole('button', { name: 'Add group' }));
    const save = screen.getByRole('button', { name: 'Save groups' });
    expect(save).toBeDisabled();
    await userEvent.type(screen.getByLabelText('Group name 2'), 'Synthetic-Denetim');
    await userEvent.click(screen.getByLabelText('Masked viewer 2'));
    await userEvent.click(screen.getByLabelText('Viewer 2'));
    expect(save).toBeEnabled();
    await userEvent.click(screen.getByRole('button', { name: 'Add group' }));
    await userEvent.click(screen.getByRole('button', { name: 'Remove group 3' }));
    await userEvent.click(save);
    const dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText(/Reason/), 'audit team access');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(saved).not.toBeNull());
    expect(saved).toEqual({
      expectedVersion: 3,
      reason: 'audit team access',
      bindings: [
        { group: 'synthetic-admins', roles: ['security_admin'] },
        { group: 'Synthetic-Denetim', roles: ['viewer'] },
      ],
    });
  });

  it('turns the form into a request: blank fields are null, a blank password is left out', () => {
    const c = connectionOf({ ...formOf(SETTINGS as never), urls: ' ldaps://a.example.test:636 \n\n', groupAttribute: ' ' });
    expect(c.urls).toEqual(['ldaps://a.example.test:636']);
    expect(c.groupAttribute).toBeNull();
    expect('newPassword' in c).toBe(false);
    expect('caCertificatePem' in c).toBe(false);
    expect(formOf(null).tlsMode).toBe('ldaps');
  });

  it('offers no plain LDAP outside tests and refuses a group name with an equals sign (PR 50 review Q-1, D-08)', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: admin }),
      'GET /api/v1/admin/directory': () => ({ status: 200, body: view() }),
    });
    renderApp('/admin/directory', 'en');
    await screen.findByDisplayValue('synthetic-admins');
    await userEvent.click(screen.getByRole('combobox', { name: 'Encryption' }));
    const options = within(await screen.findByRole('listbox')).getAllByRole('option').map((o) => o.textContent);
    expect(options).toEqual(['LDAPS (encrypted from the start)', 'StartTLS (encrypted after connecting)']);
    await userEvent.keyboard('{Escape}');
    await userEvent.click(screen.getByRole('button', { name: 'Add group' }));
    await userEvent.type(screen.getByLabelText('Group name 2'), 'cn=synthetic');
    await userEvent.click(screen.getByLabelText('Viewer 2'));
    expect(screen.getByRole('button', { name: 'Save groups' })).toBeDisabled();
  });

  it('keeps unsaved group rows when the connection is saved (PR 50 review D-08)', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: admin }),
      'GET /api/v1/admin/directory': () => ({ status: 200, body: view() }),
      'POST /api/v1/admin/directory/connection': () => ({ status: 200, body: view({ version: 4 }) }),
    });
    renderApp('/admin/directory', 'en');
    await screen.findByDisplayValue('synthetic-admins');
    await userEvent.click(screen.getByRole('button', { name: 'Add group' }));
    await userEvent.type(screen.getByLabelText('Group name 2'), 'Synthetic-Unsaved');
    await userEvent.click(screen.getByRole('button', { name: 'Save connection' }));
    const dialog = await screen.findByRole('dialog');
    await userEvent.type(within(dialog).getByLabelText(/Reason/), 'timeout change');
    await userEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    expect(screen.getByDisplayValue('Synthetic-Unsaved')).toBeInTheDocument();
  });
});
