import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fakeServer } from './fakeServer';
import { renderApp } from './render';

// PO decision Q-47 decisions 1.3 and 1.4: Administration -> Records (audit log, job log) and Platform (notifications,
// system logs, system). Every value is synthetic.

const admin = { displayName: 'synthetic-admin', roles: ['security_admin'], masked: false, source: 'ldap' };
const officer = { displayName: 'synthetic-officer', roles: ['privacy_officer'], masked: false, source: 'ldap' };

const ENTRY = {
  id: 42,
  occurredAt: '2026-11-02T08:00:00Z',
  actor: 'USR-00000000a1',
  action: 'local_user.create',
  table: 'local_user',
  operation: 'INSERT',
  rowKey: 'USR-00000000b2',
  reason: 'onboarding',
};

function audit(entries = [ENTRY], nextCursor: string | null = null) {
  return {
    entries,
    nextCursor,
    actions: ['local_user.create', 'session.end'],
    from: '2026-10-03T08:00:00Z',
    to: '2026-11-02T08:00:00Z',
    limit: 50,
  };
}

const JOBS = {
  since: '2026-11-02T06:00:00Z',
  checkedAt: '2026-11-02T09:00:00Z',
  jobs: [
    {
      id: 'policy.snapshot_resign',
      kind: 'FIXED_DELAY',
      initialDelaySeconds: 60,
      delaySeconds: 300,
      cron: null,
      zone: null,
      state: 'OK',
      lastStartedAt: '2026-11-02T08:55:00Z',
      lastEndedAt: '2026-11-02T08:55:01Z',
      failure: null,
      counts: { reissued: 0, snapshotVersion: 12 },
      nextRunAt: '2026-11-02T09:00:01Z',
      runs: 35,
      failures: 0,
      recent: [],
    },
    {
      id: 'capture.retention',
      kind: 'CRON',
      initialDelaySeconds: null,
      delaySeconds: null,
      cron: '0 20 0,6,12,18 * * *',
      zone: 'Europe/Istanbul',
      state: 'FAILED',
      lastStartedAt: '2026-11-02T03:20:00Z',
      lastEndedAt: '2026-11-02T03:20:02Z',
      failure: 'DataAccessException',
      counts: {},
      nextRunAt: '2026-11-02T09:20:00Z',
      runs: 1,
      failures: 1,
      recent: [],
    },
    {
      id: 'siem.export',
      kind: 'CONTINUOUS',
      initialDelaySeconds: null,
      delaySeconds: null,
      cron: null,
      zone: null,
      state: 'OFF',
      lastStartedAt: null,
      lastEndedAt: null,
      failure: null,
      counts: {},
      nextRunAt: null,
      runs: 0,
      failures: 0,
      recent: [],
    },
  ],
};

const SYSTEM = {
  version: 'dev',
  commit: null,
  buildTime: null,
  javaVersion: '21.0.5+11',
  schemaVersion: '11',
  startedAt: '2026-11-02T06:00:00Z',
  uptimeSeconds: 90_061,
  switches: {
    singleApproval: true,
    breakGlassSignIn: true,
    directoryConfigured: false,
    directoryEnabled: false,
    directoryKeyPresent: true,
    directoryStatus: 'NOT_CONFIGURED',
    captureMode: 'off',
    siemExport: false,
  },
};

const LOGS = {
  since: '2026-11-02T06:00:00Z',
  windowHours: 24,
  checkedAt: '2026-11-02T09:00:00Z',
  capturing: true,
  counts: [
    { level: 'INFO', logger: 'PolicyRegistryService', own: true, count: 120 },
    { level: 'WARN', logger: 'HikariPool', own: false, count: 2 },
  ],
  recent: [
    {
      at: '2026-11-02T08:30:00Z',
      level: 'WARN',
      logger: 'SiemExportService',
      own: true,
      exceptionClass: null,
      template: 'SIEM export to {} is not started: {}',
    },
    {
      at: '2026-11-02T08:00:00Z',
      level: 'ERROR',
      logger: 'HikariPool',
      own: false,
      exceptionClass: 'SQLTransientConnectionException',
      template: null,
    },
  ],
};

const NOTIFICATIONS = {
  siemEnabled: false,
  siemState: 'OFF',
  siemDestinations: [
    { kind: 'syslog', format: null, configured: false },
    { kind: 'hec', format: null, configured: false },
  ],
  emailAvailable: false,
};

afterEach(() => {
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

describe('administration menu', () => {
  it('adds the Records and Platform groups for a security administrator', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: admin }),
      'GET /api/v1/admin/system': () => ({ status: 200, body: SYSTEM }),
    });
    renderApp('/admin/system', 'en');
    const menu = await screen.findByRole('navigation', { name: 'Administration menu' });
    for (const heading of ['Access', 'Records', 'Platform']) {
      expect(within(menu).getByRole('heading', { name: heading })).toBeInTheDocument();
    }
    for (const item of ['Audit log', 'Job log', 'Notifications', 'System logs', 'System']) {
      expect(within(menu).getByRole('link', { name: item })).toBeInTheDocument();
    }
    await waitFor(() => expect(within(menu).getByRole('link', { name: 'System' })).toHaveAttribute('aria-current', 'page'));
  });

  it('opens only the audit log for a privacy officer', async () => {
    const server = fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: officer }),
      'GET /api/v1/admin/audit': () => ({ status: 200, body: audit() }),
    });
    renderApp('/admin', 'en');
    const menu = await screen.findByRole('navigation', { name: 'Administration menu' });
    expect(within(menu).getAllByRole('link').map((l) => l.textContent)).toEqual(['Audit log']);
    expect(within(menu).queryByRole('heading', { name: 'Access' })).toBeNull();
    expect(await screen.findByText('onboarding')).toBeInTheDocument();
    expect(server.calls.filter((c) => c.url.pathname.startsWith('/api/v1/admin')).map((c) => c.url.pathname)).toEqual([
      '/api/v1/admin/audit',
    ]);
  });
});

describe('audit log', () => {
  it('lists the ledger newest first with code names, the action, the record and the reason', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: admin }),
      'GET /api/v1/admin/audit': () => ({ status: 200, body: audit() }),
    });
    renderApp('/admin/audit');
    const table = await screen.findByRole('table', { name: 'Denetim kaydı satırları' });
    const row = within(table).getAllByRole('row')[1]!;
    for (const text of ['USR-00000000a1', 'local_user.create', 'local_user', 'USR-00000000b2', 'Eklendi', 'onboarding']) {
      expect(within(row).getByText(text)).toBeInTheDocument();
    }
    expect(screen.getByText(/SIEM'e gittiği haliyle gösterilir/)).toBeInTheDocument();
  });

  it('filters by action and code name only, and pages with the cursor', async () => {
    const server = fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: admin }),
      'GET /api/v1/admin/audit': (url) =>
        url.searchParams.get('cursor') === '42'
          ? { status: 200, body: audit([{ ...ENTRY, id: 41, reason: 'older entry' }]) }
          : { status: 200, body: audit([ENTRY], '42') },
    });
    renderApp('/admin/audit', 'en');
    await userEvent.click(await screen.findByRole('button', { name: 'Show older entries' }));
    expect(await screen.findByText('older entry')).toBeInTheDocument();

    const field = screen.getByRole('textbox', { name: 'Who (code name)' });
    await userEvent.type(field, 'synthetic-admin{enter}');
    expect(screen.getByText('Only a USR- code name or a system: name')).toBeInTheDocument();
    await userEvent.clear(field);
    await userEvent.type(field, 'USR-00000000a1{enter}');
    await waitFor(() =>
      expect(server.calls.some((c) => c.url.searchParams.get('actor') === 'USR-00000000a1')).toBe(true),
    );
    expect(server.calls.some((c) => c.url.searchParams.get('actor') === 'synthetic-admin')).toBe(false);

    await userEvent.click(screen.getByRole('combobox', { name: 'Action' }));
    await userEvent.click(await screen.findByRole('option', { name: 'session.end' }));
    await waitFor(() => expect(server.calls.some((c) => c.url.searchParams.get('action') === 'session.end')).toBe(true));
    const last = server.calls[server.calls.length - 1]!;
    expect(last.url.searchParams.get('limit')).toBe('50');
    expect(last.url.searchParams.get('from')).toBeTruthy();
  });

  it('shows the server reason when a filter is refused', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: admin }),
      'GET /api/v1/admin/audit': () => ({
        status: 503,
        body: { reason: 'MASKING_UNAVAILABLE', message: 'The masking dictionary is missing.' },
      }),
    });
    renderApp('/admin/audit', 'en');
    expect(await screen.findByText('The masking dictionary is missing.')).toBeInTheDocument();
  });
});

describe('job log', () => {
  it('shows each job with its schedule, state, counts and the time since the start', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: admin }),
      'GET /api/v1/admin/jobs': () => ({ status: 200, body: JOBS }),
    });
    renderApp('/admin/jobs', 'en');
    const table = await screen.findByRole('table', { name: 'Scheduled jobs' });
    const rows = within(table).getAllByRole('row');
    expect(within(rows[1]!).getByText('Policy signature renewal')).toBeInTheDocument();
    expect(within(rows[1]!).getByText('Every 5 minutes')).toBeInTheDocument();
    expect(within(rows[1]!).getByText('Succeeded')).toBeInTheDocument();
    expect(within(rows[1]!).getByText('renewed: 0 · policy version: 12')).toBeInTheDocument();
    expect(within(rows[1]!).getByText('35 (0)')).toBeInTheDocument();
    expect(within(rows[2]!).getByText(/Four times a day at 00:20/)).toBeInTheDocument();
    expect(within(rows[2]!).getByText('Failed')).toBeInTheDocument();
    expect(within(rows[2]!).getByText('DataAccessException')).toBeInTheDocument();
    expect(within(rows[3]!).getByText('All the time')).toBeInTheDocument();
    expect(within(rows[3]!).getByText('Off')).toBeInTheDocument();
    expect(screen.getByText(/Since the server last started:/)).toBeInTheDocument();
    expect(screen.getByText(/the log starts again when the server restarts/)).toBeInTheDocument();
  });

  it('says the schedule in plain Turkish', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: admin }),
      'GET /api/v1/admin/jobs': () => ({ status: 200, body: JOBS }),
    });
    renderApp('/admin/jobs');
    expect(await screen.findByText('5 dakikada bir')).toBeInTheDocument();
    expect(screen.getByText('Sürekli')).toBeInTheDocument();
  });
});

describe('platform', () => {
  it('shows the version facts and the switches, and says what the image does not record', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: admin }),
      'GET /api/v1/admin/system': () => ({ status: 200, body: SYSTEM }),
    });
    renderApp('/admin/system', 'en');
    expect(await screen.findByText('21.0.5+11')).toBeInTheDocument();
    expect(screen.getAllByText('Not recorded in this image')).toHaveLength(2);
    expect(screen.getByText('1 days 1 hours 1 minutes')).toBeInTheDocument();
    const switches = screen.getByRole('list', { name: 'Switches' });
    const item = (label: string) => within(switches).getByText(label).closest('li')!;
    expect(within(item('One administrator may activate a policy alone (pilot only)')).getByText('On')).toBeInTheDocument();
    expect(within(item('Directory (LDAP) settings saved')).getByText('Off')).toBeInTheDocument();
    expect(within(item('Directory password key present')).getByText('On')).toBeInTheDocument();
    expect(screen.getByText('Not set up')).toBeInTheDocument();
  });

  it('shows the system log as kinds and counts, never a message', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: admin }),
      'GET /api/v1/admin/logs': () => ({ status: 200, body: LOGS }),
    });
    renderApp('/admin/logs', 'en');
    const recent = await screen.findByRole('table', { name: 'Latest warnings and errors' });
    expect(within(recent).getByText('SIEM export to {} is not started: {}')).toBeInTheDocument();
    expect(within(recent).getByText('SQLTransientConnectionException')).toBeInTheDocument();
    expect(within(recent).getByText('Not shown')).toBeInTheDocument();
    const counts = screen.getByRole('table', { name: 'Counts per part and level, last 24 hours' });
    expect(within(counts).getByText('120')).toBeInTheDocument();
    expect(within(counts).getByText('Library')).toBeInTheDocument();
  });

  it('shows the outbound channels without an address and says e-mail is not available', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: admin }),
      'GET /api/v1/admin/notifications': () => ({ status: 200, body: NOTIFICATIONS }),
    });
    renderApp('/admin/notifications', 'en');
    expect(await screen.findByText('E-mail notifications are not available yet.')).toBeInTheDocument();
    expect(screen.getByText('State: Off')).toBeInTheDocument();
    const table = screen.getByRole('table', { name: 'Receivers' });
    expect(within(table).getByText('Syslog receiver')).toBeInTheDocument();
    expect(within(table).getByText('Splunk HEC receiver')).toBeInTheDocument();
    expect(within(table).getAllByText('No')).toHaveLength(2);
  });
});
