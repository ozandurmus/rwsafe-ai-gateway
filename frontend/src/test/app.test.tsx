import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { SYNTHETIC_EVENT, fakeServer } from './fakeServer';
import { renderApp } from './render';

const viewer = { displayName: 'synthetic-viewer', roles: ['viewer'], masked: false, source: 'ldap' };

afterEach(() => {
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

const health = {
  checkedAt: '2026-10-30T09:00:00Z',
  components: [{ component: 'database', state: 'UP', detail: 'PostgreSQL answers' }],
  eventsLastFiveMinutes: 0,
  totalEvents: 1234,
  latestEventAt: null,
};

describe('app', () => {
  it('asks for a sign-in in Turkish and shows the server reason as a label with its code', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 401, body: { reason: 'AUTHENTICATION_REQUIRED', message: 'Sign in first.' } }),
      'GET /api/v1/auth/csrf': () => ({ status: 200, body: { headerName: 'X-XSRF-TOKEN', token: 't' } }),
      'POST /api/v1/auth/login': () => ({
        status: 401,
        body: { reason: 'INVALID_CREDENTIALS', message: 'The login name or password is wrong.' },
      }),
    });
    renderApp();
    await userEvent.type(await screen.findByLabelText(/Kullanıcı adı/), 'synthetic-viewer');
    await userEvent.type(screen.getByLabelText(/Parola/), 'wrong');
    await userEvent.click(screen.getByRole('button', { name: 'Giriş yap' }));
    const alert = await screen.findByRole('alert');
    expect(alert).toHaveTextContent('Giriş reddedildi');
    expect(alert).toHaveTextContent('INVALID_CREDENTIALS');
    expect(alert).toHaveTextContent('The login name or password is wrong.');
  });

  it('lists traffic with pseudonyms, refuses a raw user filter and links to the event', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: viewer }),
      'GET /api/v1/platforms': () => ({ status: 200, body: { platforms: ['claude'] } }),
      'GET /api/v1/traffic': () => ({ status: 200, body: { items: [SYNTHETIC_EVENT], nextCursor: 'c1' } }),
      [`GET /api/v1/traffic/${SYNTHETIC_EVENT.eventId}`]: () => ({ status: 200, body: SYNTHETIC_EVENT }),
    });
    renderApp('/traffic');
    expect(await screen.findByText('USR-0123456789')).toBeInTheDocument();
    expect(screen.getByText('TCKN ×2')).toBeInTheDocument();
    expect(screen.getByText('Maskelendi')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Daha fazla yükle' })).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('Kullanıcı takma adı'), 'synthetic.user');
    expect(screen.getByText('USR- biçimindeki takma adı kullanın')).toBeInTheDocument();
    await userEvent.click(screen.getByText('USR-0123456789'));
    expect(await screen.findByText('Yalnızca sınıflar ve sayılar.', { exact: false })).toBeInTheDocument();
    expect(screen.getByText('TCKN: 2 eşleşme')).toBeInTheDocument();
  });

  it('marks a masked session and shows a 503 reason from the funnel', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({
        status: 200,
        body: { displayName: 'masked session', roles: ['replay_viewer'], masked: true, source: null },
        headers: { 'X-RWSAFE-Masked': 'true' },
      }),
      'GET /api/v1/overview': () => ({
        status: 503,
        body: { reason: 'MASKING_UNAVAILABLE', message: 'The masking key or dictionary is missing; nothing is served.' },
      }),
    });
    renderApp('/');
    expect(await screen.findByText('Maskeli görünüm')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('MASKING_UNAVAILABLE'));
    expect(screen.getByRole('alert')).toHaveTextContent('Maskeleme kullanılamıyor');
  });

  it('stays signed in and shows the reason when the sign-out fails', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: viewer }),
      'GET /api/v1/health': () => ({ status: 200, body: health }),
      'POST /api/v1/auth/logout': () => ({
        status: 403,
        body: { reason: 'CSRF_TOKEN_INVALID', message: 'The request lacks a valid CSRF token; reload the page.' },
      }),
    });
    renderApp('/health');
    await userEvent.click(await screen.findByRole('button', { name: 'Kullanıcı menüsü' }));
    await userEvent.click(screen.getByRole('menuitem', { name: 'Çıkış yap' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('CSRF_TOKEN_INVALID');
    expect(screen.getByRole('button', { name: 'Kullanıcı menüsü' })).toBeInTheDocument();
  });

  it('shows the reason when the platform list fails', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: viewer }),
      'GET /api/v1/platforms': () => ({ status: 503, body: { reason: 'DATABASE_UNAVAILABLE', message: 'No answer.' } }),
      'GET /api/v1/traffic': () => ({ status: 200, body: { items: [], nextCursor: null } }),
    });
    renderApp('/traffic');
    expect(await screen.findByRole('alert')).toHaveTextContent('DATABASE_UNAVAILABLE');
  });

  it('renders the overview in Turkish by default', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: viewer }),
      'GET /api/v1/overview': (url) => ({
        status: 200,
        body: {
          from: url.searchParams.get('from'),
          to: url.searchParams.get('to'),
          total: 3000,
          verdicts: [
            { verdict: 'ALLOW', count: 2000 },
            { verdict: 'REDACT', count: 1000 },
          ],
          platforms: [{ platform: 'copilot', total: 3000, redacted: 1000, blocked: 0, nonVerdicts: 0 }],
          hours: [],
          findings: [{ dataClass: 'TR_IBAN', events: 1, hits: 1 }],
        },
      }),
    });
    renderApp('/');
    expect(await screen.findByText('İncelenen işlem')).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: 'Genel bakış' })).toBeInTheDocument();
    expect(screen.getAllByText('3.000').length).toBeGreaterThan(0);
    expect(screen.getByText('toplamın %33,3')).toBeInTheDocument();
    expect(screen.getByText('GitHub Copilot')).toBeInTheDocument();
    expect(screen.getByText('TR IBAN')).toBeInTheDocument();
  });

  it('switches to English from the user menu and remembers the choice for that user', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: viewer }),
      'GET /api/v1/health': () => ({ status: 200, body: health }),
    });
    const first = renderApp('/health');
    expect(await screen.findByRole('heading', { name: 'Sağlık' })).toBeInTheDocument();
    expect(screen.getByText(/1\.234 olay saklı/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Kullanıcı menüsü' }));
    const menu = screen.getByRole('menu');
    expect(within(menu).getByText('Roller: İzleyici')).toBeInTheDocument();
    await userEvent.click(within(menu).getByRole('menuitemradio', { name: 'English' }));
    expect(await screen.findByRole('heading', { name: 'Health' })).toBeInTheDocument();
    expect(screen.getByText(/1,234 events stored/)).toBeInTheDocument();
    expect(screen.getByText('Database')).toBeInTheDocument();
    expect(window.localStorage.getItem('rwsafe.ui.lang:synthetic-viewer')).toBe('en');
    first.unmount();

    renderApp('/health');
    expect(await screen.findByRole('heading', { name: 'Health' })).toBeInTheDocument();
  });

  it('still works when the browser refuses storage', async () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: viewer }),
      'GET /api/v1/health': () => ({ status: 200, body: health }),
    });
    renderApp('/health');
    expect(await screen.findByRole('heading', { name: 'Sağlık' })).toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Kullanıcı menüsü' }));
    await userEvent.click(screen.getByRole('menuitemradio', { name: 'English' }));
    expect(await screen.findByRole('heading', { name: 'Health' })).toBeInTheDocument();
    vi.restoreAllMocks();
  });
});
