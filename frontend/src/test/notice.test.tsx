import { screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fakeServer } from './fakeServer';
import { renderApp } from './render';

// The notice screen: version and sections for the unmasked roles, the masked projection as the server returns it, and
// the acknowledgement lookup by USR- pseudonym only. All values are synthetic.

afterEach(() => {
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

const viewer = { displayName: 'synthetic-viewer', roles: ['viewer'], masked: false, source: 'ldap' };
const masked = { displayName: 'masked session', roles: ['replay_viewer'], masked: true, source: null };

const NOTICE = {
  title: 'Yapay zekâ kullanımı aydınlatma metni',
  catalogueVersion: 'tr-2',
  currentVersion: 'tr-2+0a1b2c3d',
  complete: true,
  missingParameters: [],
  rejectedParameters: [],
  usersAcknowledged: 1234,
  sections: [
    { heading: 'Neyi inceliyoruz', paragraphs: ['Sentetik birinci paragraf <i>etiket değil</i>.', 'İkinci paragraf.'] },
    { heading: 'Haklarınız', paragraphs: ['Sentetik haklar paragrafı.'] },
  ],
};

const ACKS = {
  user: 'USR-0123456789',
  currentVersion: 'tr-2+0a1b2c3d',
  currentAcknowledged: true,
  records: [
    {
      noticeVersion: 'tr-2+0a1b2c3d',
      acknowledgedAt: '2026-10-30T09:15:00Z',
      source: 'banner',
      recordedAt: '2026-10-30T09:15:02Z',
      pseudonymKeyId: 'k0000abcd',
    },
  ],
};

describe('notice screen', () => {
  it('shows the current version, the count and the sections as text to an unmasked role', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: viewer }),
      'GET /api/v1/notice': () => ({ status: 200, body: NOTICE }),
    });
    renderApp('/notice');
    expect(await screen.findByText('tr-2+0a1b2c3d')).toBeInTheDocument();
    expect(screen.getByText('1.234')).toBeInTheDocument();
    expect(screen.getByText('Evet')).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: 'Neyi inceliyoruz' })).toBeInTheDocument();
    const paragraph = screen.getByText('Sentetik birinci paragraf <i>etiket değil</i>.');
    expect(paragraph.querySelector('i')).toBeNull();
    expect(screen.getByRole('tab', { name: 'Aydınlatma metni' })).toBeInTheDocument();
  });

  it('shows the masked projection as the server returns it: no sections', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: masked, headers: { 'X-RWSAFE-Masked': 'true' } }),
      'GET /api/v1/notice': () => ({ status: 200, body: { ...NOTICE, sections: null } }),
    });
    renderApp('/notice');
    expect(await screen.findByText('tr-2+0a1b2c3d')).toBeInTheDocument();
    expect(screen.getByText(/Metnin kendisi maskeli görünümde gösterilmez/)).toBeInTheDocument();
    expect(screen.queryByText('Neyi inceliyoruz')).toBeNull();
  });

  it('says what an incomplete notice means', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: viewer }),
      'GET /api/v1/notice': () => ({
        status: 200,
        body: {
          ...NOTICE,
          currentVersion: null,
          complete: false,
          missingParameters: ['controller_name'],
          usersAcknowledged: 0,
          sections: null,
        },
      }),
    });
    renderApp('/notice');
    expect(await screen.findByText('yok: metin eksik')).toBeInTheDocument();
    expect(screen.getByText('controller_name')).toBeInTheDocument();
    expect(screen.getByText(/kullanıcılara gösterilmiyor, onay alınmıyor ve içerik saklanmıyor/)).toBeInTheDocument();
    expect(screen.getByText('Gösterilecek metin yok: metin eksik.')).toBeInTheDocument();
  });

  it('says the notice is incomplete in the masked view too (PR 28 D-04)', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: masked, headers: { 'X-RWSAFE-Masked': 'true' } }),
      'GET /api/v1/notice': () => ({
        status: 200,
        body: { ...NOTICE, currentVersion: null, complete: false, missingParameters: ['dpo_contact'], sections: null },
      }),
    });
    renderApp('/notice');
    expect(await screen.findByText('Gösterilecek metin yok: metin eksik.')).toBeInTheDocument();
    expect(screen.queryByText(/Metnin kendisi maskeli görünümde gösterilmez/)).toBeNull();
  });

  it('looks up acknowledgements by pseudonym only and never sends anything else', async () => {
    const s = fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: viewer }),
      'GET /api/v1/notice': () => ({ status: 200, body: NOTICE }),
      'GET /api/v1/notice/acknowledgements': () => ({ status: 200, body: ACKS }),
    });
    renderApp('/notice');
    const field = await screen.findByLabelText('Kullanıcı takma adı');
    const button = screen.getByRole('button', { name: 'Sorgula' });
    await userEvent.type(field, 'synthetic.user');
    expect(screen.getByText('USR- biçimindeki takma adı kullanın')).toBeInTheDocument();
    expect(button).toBeDisabled();
    await userEvent.type(field, '{Enter}');
    expect(s.calls.some((c) => c.url.pathname === '/api/v1/notice/acknowledgements')).toBe(false);

    await userEvent.clear(field);
    await userEvent.type(field, 'USR-0123456789');
    await userEvent.click(button);
    expect(await screen.findByText(/USR-0123456789, güncel sürümü \(tr-2\+0a1b2c3d\) onayladı/)).toBeInTheDocument();
    const call = s.calls.find((c) => c.url.pathname === '/api/v1/notice/acknowledgements');
    expect(call?.url.searchParams.get('user')).toBe('USR-0123456789');
    const table = screen.getByRole('table', { name: 'Onaylar' });
    expect(within(table).getByText('Tarayıcıdaki bilgilendirme şeridi')).toBeInTheDocument();
    expect(within(table).getByText('k0000abcd')).toBeInTheDocument();
  });

  it("shows a user without the current acknowledgement and the server's refusal", async () => {
    let refuse = false;
    fakeServer({
      'GET /api/v1/auth/me': () => ({ status: 200, body: viewer }),
      'GET /api/v1/notice': () => ({ status: 200, body: NOTICE }),
      'GET /api/v1/notice/acknowledgements': () =>
        refuse
          ? {
              status: 503,
              body: { reason: 'MASKING_UNAVAILABLE', message: 'The masking key or dictionary is missing.' },
            }
          : { status: 200, body: { ...ACKS, currentAcknowledged: false, records: [] } },
    });
    renderApp('/notice');
    const field = await screen.findByLabelText('Kullanıcı takma adı');
    await userEvent.type(field, 'USR-00000000ff');
    await userEvent.click(screen.getByRole('button', { name: 'Sorgula' }));
    expect(await screen.findByText(/onaylamadı: bu kullanıcının içeriği saklanmaz/)).toBeInTheDocument();
    expect(screen.getByText('Bu kullanıcı için kayıtlı onay yok.')).toBeInTheDocument();

    refuse = true;
    await userEvent.click(screen.getByRole('button', { name: 'Sorgula' }));
    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('MASKING_UNAVAILABLE'));
    expect(screen.getByRole('alert')).toHaveTextContent('Maskeleme kullanılamıyor');
    expect(screen.getByRole('alert')).toHaveTextContent('The masking key or dictionary is missing.');
  });
});
