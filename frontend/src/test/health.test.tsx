import { screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { EXPLAINED_COMPONENTS, healthFacts } from '../healthFacts';
import { CATALOGUES, LANGUAGES } from '../i18n';
import { fakeServer } from './fakeServer';
import { renderApp } from './render';

// The Health screen's SIEM export and capture components: states in plain words, what to do, and the counts by name,
// read from the server's structured `counts` (PR 28 review D-03; the keys are those SiemExportService.Health and
// CaptureHealth emit, which their Java tests assert). All numbers are synthetic.

afterEach(() => {
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

const SIEM_COUNTS = {
  'syslog.delivered': 1200,
  'syslog.backlog': 40,
  'syslog.queueDepth': 2,
  'syslog.queueCapacity': 64,
  'syslog.stalled': 1,
  'syslog.heldBehindOpenTransaction': 3,
  'syslog.possiblyLostBatches': 5,
  'syslog.skippedAtStart': 7,
  'syslog.readerFailure.database': 1,
  'syslog.senderFailure.connect': 1,
  'hec.delivered': 9,
  'hec.queueDepth': 0,
  'hec.queueCapacity': 64,
  'hec.stalled': 0,
  'hec.heldBehindOpenTransaction': 0,
  'hec.possiblyLostBatches': 0,
  'hec.skippedAtStart': 0,
};
const CAPTURE_COUNTS = {
  captureOn: 1,
  keyAvailable: 1,
  storeWritable: 1,
  records: 12,
  chunks: 30,
  storedBytes: 1048576,
  maxBytes: 34359738368,
  heldRecords: 1,
  rewrapRecords: 4,
  rewrapChunks: 9,
  shreddedKeyRecords: 2,
  missingKeyRecords: 6,
  stored: 12,
  noAcknowledgement: 3,
  aboveWatermark: 0,
  detectorHit: 8,
  evicted: 0,
  other: 1,
};

describe('health facts', () => {
  it('reads the SIEM destinations, their failures, backlog, held rows and possibly lost batches', () => {
    expect(healthFacts('siem', SIEM_COUNTS)).toEqual([
      {
        group: 'syslog',
        facts: [
          { key: 'stalled', value: true },
          { key: 'readerFailure', value: 'database' },
          { key: 'senderFailure', value: 'connect' },
          { key: 'delivered', value: 1200 },
          { key: 'backlog', value: 40 },
          { key: 'queue', value: 2, of: 64 },
          { key: 'heldBehindOpenTransaction', value: 3 },
          { key: 'possiblyLostBatches', value: 5 },
          { key: 'skippedAtStart', value: 7 },
        ],
      },
      {
        group: 'hec',
        facts: [
          { key: 'delivered', value: 9 },
          { key: 'backlogUncounted', value: true },
          { key: 'queue', value: 0, of: 64 },
          { key: 'heldBehindOpenTransaction', value: 0 },
          { key: 'possiblyLostBatches', value: 0 },
          { key: 'skippedAtStart', value: 0 },
        ],
      },
    ]);
    expect(healthFacts('siem', { 'siem.notStarted': 1 })).toEqual([
      { group: 'siem', facts: [{ key: 'notStarted', value: true }] },
    ]);
  });

  it('reads the capture store, its key states and its skip counts', () => {
    const facts = healthFacts('capture', CAPTURE_COUNTS)[0]?.facts ?? [];
    expect(Object.fromEntries(facts.map((f) => [f.key, f.value]))).toEqual({
      ...Object.fromEntries(Object.entries(CAPTURE_COUNTS).filter(([k]) => k !== 'captureOn')),
      keyAvailable: true,
      storeWritable: true,
    });
    expect(healthFacts('capture', { captureOn: 0 })).toEqual([]);
  });

  it('reads the watermark', () => {
    expect(healthFacts('capture-watermark', { stale: 0, usedPerMille: 785, skipped: 11 })).toEqual([
      { group: null, facts: [{ key: 'usedPercent', value: 78.5 }, { key: 'skipped', value: 11 }] },
    ]);
    expect(healthFacts('capture-watermark', { stale: 1, skipped: 2 })).toEqual([
      { group: null, facts: [{ key: 'stale', value: true }, { key: 'skipped', value: 2 }] },
    ]);
  });

  it('never shows a wrong number as fact (PR 28 review D-03)', () => {
    const bad = {
      captureOn: 1,
      records: -1,
      chunks: 2 ** 53,
      storedBytes: 1.5,
      maxBytes: Number.NaN,
      stored: '12',
      other: null,
      evicted: 7,
    } as unknown as Record<string, number>;
    expect(healthFacts('capture', bad)).toEqual([{ group: null, facts: [{ key: 'evicted', value: 7 }] }]);
    expect(healthFacts('capture-watermark', { usedPerMille: 1001 })).toEqual([]);
    // A destination with nothing recognised gets no empty header; no counts at all (an older server) give nothing.
    expect(healthFacts('siem', { 'syslog.unknownThing': 3, 'syslog.stalled': 2 })).toEqual([]);
    expect(healthFacts('siem', undefined)).toEqual([]);
    expect(healthFacts('database', { anything: 1 })).toEqual([]);
    // Inherited members are not counts.
    expect(healthFacts('capture', Object.create({ captureOn: 1, records: 3 }))).toEqual([]);
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
            { component: 'database', state: 'UP', detail: 'PostgreSQL answers', counts: {} },
            { component: 'siem', state: 'DEGRADED', detail: 'syslog: synthetic server sentence', counts: SIEM_COUNTS },
            { component: 'capture', state: 'DEGRADED', detail: 'synthetic capture sentence', counts: CAPTURE_COUNTS },
            {
              component: 'capture-watermark',
              state: 'DOWN',
              detail: 'synthetic watermark sentence',
              counts: { stale: 1, skipped: 2 },
            },
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
    expect(siem).toHaveTextContent('Takıldıüç dakikadan uzun süredir ilerleme yok');
    expect(siem).toHaveTextContent('Açık kalan bir veritabanı işleminin arkasında bekleyen satır3');
    expect(siem).toHaveTextContent('Okuma (yeniden deneniyor)veritabanı okunamıyor');
    expect(siem).toHaveTextContent('Gönderme (yeniden deneniyor)bağlantı kurulamıyor');
    expect(siem).toHaveTextContent('Gönderilen kayıt1.200');
    expect(siem).toHaveTextContent('Gönderilmeyi bekleyen kayıt40');
    expect(siem).toHaveTextContent('Kaybolmuş olabilecek paket5');
    expect(siem).toHaveTextContent('Gönderilmeyi bekleyen kayıthenüz sayılmadı');
    expect(siem).toHaveTextContent('Sunucunun ayrıntısı: syslog: synthetic server sentence');

    const capture = screen.getByRole('region', { name: 'Maskelenmiş içerik kaydı' });
    expect(capture).toHaveTextContent('İçerik kaydı anahtarı takılıEvet');
    expect(capture).toHaveTextContent('Kullanılan alan1,0 MiB');
    expect(capture).toHaveTextContent('Alan sınırı32,0 GiB');
    expect(capture).toHaveTextContent('Anahtarı bulunamayan kayıt6');
    expect(capture).toHaveTextContent('Saklanmadı: kullanıcı aydınlatma metnini onaylamamış3');
    expect(capture).toHaveTextContent('Saklanmadı: metinde hâlâ hassas veri bulundu8');
    expect(capture).toHaveTextContent('içerik kaydı anahtarını kontrol edin');

    const watermark = screen.getByRole('region', { name: 'Disk doluluk eşiği' });
    expect(within(watermark).getByText('Çalışmıyor')).toBeInTheDocument();
    expect(watermark).toHaveTextContent('beş dakikadır disk ölçümü alınamıyor');
    expect(watermark).toHaveTextContent('Disk ölçümübeş dakikadır alınamıyor');
    expect(watermark).toHaveTextContent('Disk dolu olduğu için saklanmayan içerik (başlangıçtan beri)2');

    // A component without an explanation keeps its plain card.
    const database = screen.getByRole('region', { name: 'Veritabanı' });
    expect(database).not.toHaveTextContent('Ne anlama geliyor:');
    expect(database).toHaveTextContent('PostgreSQL answers');
  });
});
