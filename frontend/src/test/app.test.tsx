import { ThemeProvider, createTheme } from '@mui/material';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { App } from '../App';
import { AuthProvider } from '../auth';
import { SYNTHETIC_EVENT, fakeServer } from './fakeServer';

function renderApp(path = '/') {
  return render(
    <ThemeProvider theme={createTheme()}>
      <MemoryRouter initialEntries={[path]}>
        <AuthProvider>
          <App />
        </AuthProvider>
      </MemoryRouter>
    </ThemeProvider>,
  );
}

const viewer = { displayName: 'synthetic-viewer', roles: ['viewer'], masked: false, source: 'ldap' };

afterEach(() => vi.unstubAllGlobals());

describe('app', () => {
  it('asks for a sign-in and shows the server reason when it fails', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 401, body: { reason: 'AUTHENTICATION_REQUIRED', message: 'Sign in first.' } }),
      'GET /api/v1/auth/csrf': () => ({ status: 200, body: { headerName: 'X-XSRF-TOKEN', token: 't' } }),
      'POST /api/v1/auth/login': () => ({
        status: 401,
        body: { reason: 'INVALID_CREDENTIALS', message: 'The login name or password is wrong.' },
      }),
    });
    renderApp();
    await userEvent.type(await screen.findByLabelText(/Login name/), 'synthetic-viewer');
    await userEvent.type(screen.getByLabelText(/Password/), 'wrong');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in' }));
    const alert = await screen.findByRole('alert');
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
    expect(screen.getByRole('button', { name: 'Load more' })).toBeInTheDocument();
    await userEvent.type(screen.getByLabelText('User pseudonym'), 'synthetic.user');
    expect(screen.getByText('Use the USR- pseudonym form')).toBeInTheDocument();
    await userEvent.click(screen.getByText('USR-0123456789'));
    expect(await screen.findByText('Classes and counts only.', { exact: false })).toBeInTheDocument();
    expect(screen.getByText('TCKN: 2 hits')).toBeInTheDocument();
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
    expect(await screen.findByText('Masked view · rwmask-v1')).toBeInTheDocument();
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('MASKING_UNAVAILABLE'));
  });

  it('renders the overview', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: viewer }),
      'GET /api/v1/overview': (url) => ({
        status: 200,
        body: {
          from: url.searchParams.get('from'),
          to: url.searchParams.get('to'),
          total: 3,
          verdicts: [
            { verdict: 'ALLOW', count: 2 },
            { verdict: 'REDACT', count: 1 },
          ],
          platforms: [{ platform: 'copilot', total: 3, redacted: 1, blocked: 0, nonVerdicts: 0 }],
          hours: [],
          findings: [{ dataClass: 'TR_IBAN', events: 1, hits: 1 }],
        },
      }),
    });
    renderApp('/');
    expect(await screen.findByText('Inspected transactions')).toBeInTheDocument();
    expect(screen.getByText('GitHub Copilot')).toBeInTheDocument();
    expect(screen.getByText('TR IBAN')).toBeInTheDocument();
  });
});
