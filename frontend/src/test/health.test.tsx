import { screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { EXPLAINED_COMPONENTS, healthFacts } from '../healthFacts';
import { CATALOGUES, LANGUAGES } from '../i18n';
import { fakeServer } from './fakeServer';
import { renderApp } from './render';

// The Health screen's SIEM export and capture components: states in plain words, what to do, and the counts by name.
// The details below are the server's fixed vocabulary (SiemExportService.health, CaptureHealth) with synthetic numbers.

afterEach(() => {
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

const SIEM_DEGRADED =
  'syslog: stalled: no progress for over 180 s with 3 rows held behind an open database transaction, retrying after a ' +
  'failure (reader database, sender connect), 1200 events delivered, backlog 40, queue 2/64, 5 batches possibly lost ' +
  '(connection closed after the flush), 7 verdict events skipped at a latest start; hec: 9 events delivered, backlog not ' +
  'counted yet, queue 0/64';
const SIEM_DOWN =
  'siem: not started, the privacy key or the estate dictionary is missing; nothing is exported';
const CAPTURE_DEGRADED =
  'redacted mode, active key cap-k2; 12 records, 30 chunks, 1048576 of 34359738368 bytes, 1 on hold; to re-wrap from ' +
  'older mounted keys: 4 records and 9 chunks; held under shredded keys: 2; under missing keys: 6; since start: stored ' +
  '12, without acknowledgement 3, above the watermark 0, detector hit refused 8, evicted for the cap 0, other 1';
const WATERMARK_DEGRADED = '78.5 % used; above 75 %: raw off, redacted persists; 11 captures skipped since start';
const WATERMARK_STALE = 'no disk reading for 5 minutes: content is not persisted (fail closed); 2 captures skipped since start';

describe('health facts', () => {
  it('reads the SIEM destinations, their failures, backlog, held rows and possibly lost batches', () => {
    expect(healthFacts('siem', SIEM_DEGRADED)).toEqual([
      {
        group: 'syslog',
        facts: [
          { key: 'stalledSeconds', value: 180 },
          { key: 'heldRows', value: 3 },
          { key: 'readerFailure', value: 'database' },
          { key: 'senderFailure', value: 'connect' },
          { key: 'delivered', value: 1200 },
          { key: 'backlog', value: 40 },
          { key: 'queue', value: 2, of: 64 },
          { key: 'possiblyLost', value: 5 },
          { key: 'skippedAtStart', value: 7 },
        ],
      },
      {
        group: 'hec',
        facts: [
          { key: 'delivered', value: 9 },
          { key: 'backlogUncounted', value: '' },
          { key: 'queue', value: 0, of: 64 },
        ],
      },
    ]);
    // A refusal reason holds "; " itself and stays whole.
    expect(healthFacts('siem', SIEM_DOWN)).toEqual([
      {
        group: 'siem',
        facts: [{ key: 'notStarted', value: 'the privacy key or the estate dictionary is missing; nothing is exported' }],
      },
    ]);
  });

  it('reads the capture store, its key states and its skip counts', () => {
    const facts = healthFacts('capture', CAPTURE_DEGRADED)[0]?.facts ?? [];
    expect(Object.fromEntries(facts.map((f) => [f.key, f.value]))).toEqual({
      activeKey: 'cap-k2',
      records: 12,
      chunks: 30,
      storedBytes: 1048576,
      capBytes: 34359738368,
      onHold: 1,
      rewrapRecords: 4,
      rewrapChunks: 9,
      shreddedHeld: 2,
      missingKeys: 6,
      stored: 12,
      noAcknowledgement: 3,
      aboveWatermark: 0,
      detectorHit: 8,
      evicted: 0,
      other: 1,
    });
    // Capture off: no counts, only the sentence.
    expect(healthFacts('capture', 'capture is off: metadata and verdicts only')).toEqual([]);
  });

  it('reads the watermark, and yields nothing for a sentence it does not know', () => {
    expect(healthFacts('capture-watermark', WATERMARK_DEGRADED)).toEqual([
      { group: null, facts: [{ key: 'usedPercent', value: 78.5 }, { key: 'skipped', value: 11 }] },
    ]);
    expect(healthFacts('capture-watermark', WATERMARK_STALE)).toEqual([
      { group: null, facts: [{ key: 'skipped', value: 2 }] },
    ]);
    expect(healthFacts('siem', 'something the server never says')).toEqual([]);
    expect(healthFacts('database', 'PostgreSQL answers')).toEqual([]);
  });

  it('explains every state of the explained components in both languages', () => {
    for (const lang of LANGUAGES) {
      const catalogue = CATALOGUES[lang] as Record<string, string>;
      for (const component of EXPLAINED_COMPONENTS) {
        for (const state of ['UP', 'DEGRADED', 'DOWN']) {
          expect(catalogue[`health.meaning.${component}.${state}`], `${lang} ${component} ${state}`).toBeTruthy();
          expect(catalogue[`health.todo.${component}.${state}`], `${lang} ${component} ${state}`).toBeTruthy();
        }
      }
    }
  });
});

describe('health screen', () => {
  it('names the SIEM and capture states, what to do and the counts in Turkish, beside the server detail', async () => {
    fakeServer({
      'GET /api/v1/auth/me': () => ({
        status: 200,
        body: { displayName: 'synthetic-viewer', roles: ['viewer'], masked: false, source: 'ldap' },
      }),
      'GET /api/v1/health': () => ({
        status: 200,
        body: {
          checkedAt: '2026-10-30T09:00:00Z',
          components: [
            { component: 'database', state: 'UP', detail: 'PostgreSQL answers' },
            { component: 'siem', state: 'DEGRADED', detail: SIEM_DEGRADED },
            { component: 'capture', state: 'DEGRADED', detail: CAPTURE_DEGRADED },
            { component: 'capture-watermark', state: 'DOWN', detail: WATERMARK_STALE },
          ],
          eventsLastFiveMinutes: 0,
          totalEvents: 10,
          latestEventAt: null,
        },
      }),
    });
    renderApp('/health');
    const siem = await screen.findByRole('region', { name: 'SIEM aktarımı' });
    expect(within(siem).getByText('Kısıtlı')).toBeInTheDocument();
    expect(siem).toHaveTextContent('Ne anlama geliyor:');
    expect(siem).toHaveTextContent('Kayıtlar atılmaz');
    expect(siem).toHaveTextContent('Ne yapmalı:');
    expect(within(siem).getByText('Syslog alıcısı')).toBeInTheDocument();
    expect(within(siem).getByText('180 saniyeden uzun süredir ilerleme yok')).toBeInTheDocument();
    expect(siem).toHaveTextContent('Açık kalan bir veritabanı işleminin arkasında bekleyen satır3');
    expect(siem).toHaveTextContent('Okuma (yeniden deneniyor)veritabanı okunamıyor');
    expect(siem).toHaveTextContent('Gönderme (yeniden deneniyor)bağlantı kurulamıyor');
    expect(siem).toHaveTextContent('Gönderilen kayıt1.200');
    expect(siem).toHaveTextContent('Gönderilmeyi bekleyen kayıt40');
    expect(siem).toHaveTextContent('Kaybolmuş olabilecek paket5');
    expect(siem).toHaveTextContent('Gönderilmeyi bekleyen kayıthenüz sayılmadı');
    expect(siem).toHaveTextContent('Sunucunun ayrıntısı:');
    expect(siem).toHaveTextContent('5 batches possibly lost');

    const capture = screen.getByRole('region', { name: 'Maskelenmiş içerik kaydı' });
    expect(capture).toHaveTextContent('Kullanılan anahtarcap-k2');
    expect(capture).toHaveTextContent('Kullanılan alan1,0 MiB');
    expect(capture).toHaveTextContent('Alan sınırı32,0 GiB');
    expect(capture).toHaveTextContent('Anahtarı bulunamayan kayıt6');
    expect(capture).toHaveTextContent('Saklanmadı: kullanıcı aydınlatma metnini onaylamamış3');
    expect(capture).toHaveTextContent('Saklanmadı: metinde hâlâ hassas veri bulundu8');
    expect(capture).toHaveTextContent('içerik kaydı anahtarını kontrol edin');

    const watermark = screen.getByRole('region', { name: 'Disk doluluk eşiği' });
    expect(within(watermark).getByText('Çalışmıyor')).toBeInTheDocument();
    expect(watermark).toHaveTextContent('beş dakikadır disk ölçümü alınamıyor');
    expect(watermark).toHaveTextContent('Disk dolu olduğu için saklanmayan içerik (başlangıçtan beri)2');

    // A component without an explanation keeps its plain card.
    const database = screen.getByRole('region', { name: 'Veritabanı' });
    expect(database).not.toHaveTextContent('Ne anlama geliyor:');
    expect(database).toHaveTextContent('PostgreSQL answers');
  });
});
