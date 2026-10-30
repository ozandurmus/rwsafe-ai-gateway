import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { CAPTURE_REASON_CODES } from '../api';
import { CATALOGUES } from '../i18n';
import { SYNTHETIC_EVENT, fakeServer } from './fakeServer';
import { renderApp } from './render';

// The captured-content reader on the event screen (ADR-009 §5; PO decision on the PR 25 review Q-2): the reader roles
// only, never a masked session; a reason code and a case id; an in-page confirmation; the text as text only.

afterEach(() => {
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

const EVENT_PATH = `/traffic/${SYNTHETIC_EVENT.eventId}`;
const READ_PATH = `POST /api/v1/captures/${SYNTHETIC_EVENT.eventId}/read`;

function user(roles: string[], masked = false) {
  return { displayName: 'synthetic-reader', roles, masked, source: masked ? null : 'ldap' };
}

// Synthetic text with markup and a script tag: it must reach the screen as characters, never as elements.
const SYNTHETIC_TEXT = 'Line one <b>not bold</b>\n<script>window.synthetic = 1</script> [TCKN] masked';

function server(me: object, event: object = SYNTHETIC_EVENT, read?: () => { status: number; body?: unknown }) {
  return fakeServer({
    'GET /api/v1/auth/me': () => ({ status: 200, body: me }),
    [`GET /api/v1/traffic/${SYNTHETIC_EVENT.eventId}`]: () => ({ status: 200, body: event }),
    [READ_PATH]:
      read ??
      (() => ({
        status: 200,
        body: {
          eventId: SYNTHETIC_EVENT.eventId,
          text: SYNTHETIC_TEXT,
          withheld: false,
          truncated: true,
          maskRuleSet: 'rwmask-v1-slice1',
          capturedAt: '2026-10-30T09:15:01Z',
          expiresAt: '2027-01-28T09:15:01Z',
          readId: 42,
        },
      })),
  });
}

async function chooseReason(label: string) {
  await userEvent.click(screen.getByRole('combobox', { name: /Gerekçe/ }));
  await userEvent.click(await screen.findByRole('option', { name: label }));
}

describe('captured content reader', () => {
  it('opens only after a reason, a case id and an in-page confirmation, and shows the text inert', async () => {
    const s = server(user(['security_admin']));
    renderApp(EVENT_PATH);
    await userEvent.click(await screen.findByRole('button', { name: 'İçeriği aç' }));
    // The security administrator's list: every reason but the privacy officer's DSAR.
    await userEvent.click(screen.getByRole('combobox', { name: /Gerekçe/ }));
    const options = (await screen.findAllByRole('option')).map((o) => o.textContent);
    expect(options).toEqual([
      'Güvenlik olayı incelemesi',
      'Yanlış tespitin incelenmesi',
      'Hukuki nedenle saklanan kayıtların incelenmesi',
      'Resmî kurum talebi',
    ]);
    await userEvent.click(screen.getByRole('option', { name: 'Güvenlik olayı incelemesi' }));
    const proceed = screen.getByRole('button', { name: 'Devam' });
    expect(proceed).toBeDisabled();
    await userEvent.type(screen.getByLabelText(/Dosya numarası/), 'INC-2026-0042');
    await userEvent.click(proceed);

    // The confirmation step is on the page; nothing has been read yet.
    const confirm = await screen.findByRole('alert');
    expect(confirm).toHaveTextContent('Güvenlik olayı incelemesi');
    expect(confirm).toHaveTextContent('INC-2026-0042');
    expect(confirm).toHaveTextContent('kayda geçer');
    expect(s.calls.some((c) => c.method === 'POST')).toBe(false);
    await userEvent.click(within(confirm).getByRole('button', { name: 'Evet, aç' }));

    const text = await screen.findByTestId('capture-text');
    const post = s.calls.find((c) => c.method === 'POST');
    expect(post?.url.pathname).toBe(`/api/v1/captures/${SYNTHETIC_EVENT.eventId}/read`);
    expect(JSON.parse(String(post?.init.body))).toEqual({
      reasonCode: 'INCIDENT_INVESTIGATION',
      caseId: 'INC-2026-0042',
    });
    expect(text.textContent).toBe(SYNTHETIC_TEXT);
    expect(text.querySelector('b')).toBeNull();
    expect(text.querySelector('script')).toBeNull();
    expect((window as unknown as { synthetic?: number }).synthetic).toBeUndefined();
    expect(screen.getByText(/Bu okuma kayda geçti \(kayıt no 42\)/)).toBeInTheDocument();
    expect(screen.getByText('Metnin yalnızca başı saklandı; devamı kesildi.')).toBeInTheDocument();

    await userEvent.click(screen.getByRole('button', { name: 'İçeriği kapat' }));
    expect(screen.queryByTestId('capture-text')).toBeNull();
    expect(screen.getByRole('button', { name: 'İçeriği aç' })).toBeInTheDocument();
  });

  it('offers DSAR to the privacy officer', async () => {
    server(user(['privacy_officer']));
    renderApp(EVENT_PATH);
    await userEvent.click(await screen.findByRole('button', { name: 'İçeriği aç' }));
    await chooseReason('Kişinin kendi verisine erişim başvurusu');
    expect(screen.getByRole('combobox', { name: /Gerekçe/ })).toHaveTextContent('Kişinin kendi verisine erişim başvurusu');
  });

  it('goes back from the confirmation without reading', async () => {
    const s = server(user(['security_admin']));
    renderApp(EVENT_PATH);
    await userEvent.click(await screen.findByRole('button', { name: 'İçeriği aç' }));
    await chooseReason('Resmî kurum talebi');
    await userEvent.type(screen.getByLabelText(/Dosya numarası/), 'REG_7');
    await userEvent.click(screen.getByRole('button', { name: 'Devam' }));
    await userEvent.click(within(await screen.findByRole('alert')).getByRole('button', { name: 'Vazgeç' }));
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.getByRole('button', { name: 'Devam' })).toBeEnabled();
    expect(s.calls.some((c) => c.method === 'POST')).toBe(false);
  });

  it('refuses a case id that is not a plain reference before anything is sent', async () => {
    const s = server(user(['security_admin']));
    renderApp(EVENT_PATH);
    await userEvent.click(await screen.findByRole('button', { name: 'İçeriği aç' }));
    await chooseReason('Güvenlik olayı incelemesi');
    await userEvent.type(screen.getByLabelText(/Dosya numarası/), 'synthetic person name');
    expect(screen.getByText('3 ile 64 karakter arası harf, rakam, alt çizgi veya tire kullanın')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Devam' })).toBeDisabled();
    expect(s.calls.some((c) => c.method === 'POST')).toBe(false);
  });

  it("shows the server's refusal with its reason and returns to the form", async () => {
    server(user(['security_admin']), SYNTHETIC_EVENT, () => ({
      status: 404,
      body: {
        reason: 'CAPTURE_NOT_FOUND',
        message: 'No captured content exists for this event (not captured, expired or shredded).',
      },
    }));
    renderApp(EVENT_PATH);
    await userEvent.click(await screen.findByRole('button', { name: 'İçeriği aç' }));
    await chooseReason('Yanlış tespitin incelenmesi');
    await userEvent.type(screen.getByLabelText(/Dosya numarası/), 'FP-11');
    await userEvent.click(screen.getByRole('button', { name: 'Devam' }));
    await userEvent.click(within(await screen.findByRole('alert')).getByRole('button', { name: 'Evet, aç' }));
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('CAPTURE_NOT_FOUND'));
    const alert = screen.getByRole('alert');
    expect(alert).toHaveTextContent('Saklanan içerik yok');
    expect(alert).toHaveTextContent('expired or shredded');
    expect(screen.getByRole('button', { name: 'Devam' })).toBeInTheDocument();
    expect(screen.queryByTestId('capture-text')).toBeNull();
  });

  it('shows a withheld record without text', async () => {
    server(user(['security_admin']), SYNTHETIC_EVENT, () => ({
      status: 200,
      body: {
        eventId: SYNTHETIC_EVENT.eventId,
        text: null,
        withheld: true,
        truncated: false,
        maskRuleSet: 'rwmask-v1-slice1',
        capturedAt: '2026-10-30T09:15:01Z',
        expiresAt: '2027-01-28T09:15:01Z',
        readId: 7,
      },
    }));
    renderApp(EVENT_PATH);
    await userEvent.click(await screen.findByRole('button', { name: 'İçeriği aç' }));
    await chooseReason('Güvenlik olayı incelemesi');
    await userEvent.type(screen.getByLabelText(/Dosya numarası/), 'INC-1');
    await userEvent.click(screen.getByRole('button', { name: 'Devam' }));
    await userEvent.click(within(await screen.findByRole('alert')).getByRole('button', { name: 'Evet, aç' }));
    expect(await screen.findByText('Metin bu görünümde gösterilmez.')).toBeInTheDocument();
    expect(screen.queryByTestId('capture-text')).toBeNull();
  });

  it.each([
    ['a viewer', user(['viewer'])],
    ['the masked role', user(['replay_viewer'], true)],
    ['a security administrator in a masked session', user(['security_admin'], true)],
    ['a masked role that also holds a reader role', user(['privacy_officer', 'replay_viewer'])],
  ])('is never offered to %s', async (_name, me) => {
    server(me);
    renderApp(EVENT_PATH);
    expect(await screen.findByText('Bulgular')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'İçeriği aç' })).toBeNull();
    expect(screen.queryByText('Kaydedilen içerik')).toBeNull();
  });

  it('is not offered for an event without a REDACT verdict (nothing is captured for it)', async () => {
    server(user(['security_admin']), { ...SYNTHETIC_EVENT, verdict: 'BLOCK' });
    renderApp(EVENT_PATH);
    expect(await screen.findByText('Bulgular')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'İçeriği aç' })).toBeNull();
  });

  it('names every server reason code in both languages', () => {
    for (const code of CAPTURE_REASON_CODES) {
      expect(CATALOGUES.tr[`capture.reason.${code}`]).toBeTruthy();
      expect(CATALOGUES.en[`capture.reason.${code}`]).toBeTruthy();
    }
    for (const code of [
      'CAPTURE_REASON_REQUIRED',
      'ROLE_NOT_PERMITTED',
      'REASON_NOT_PERMITTED_FOR_ROLE',
      'CAPTURE_NOT_FOUND',
      'CAPTURE_KEY_SHREDDED',
      'CAPTURE_INTEGRITY',
    ]) {
      expect(Object.prototype.hasOwnProperty.call(CATALOGUES.tr, `reason.code_${code}`), code).toBe(true);
    }
  });
});
