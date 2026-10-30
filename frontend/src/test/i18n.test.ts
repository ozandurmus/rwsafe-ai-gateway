import { describe, expect, it } from 'vitest';
import { CATALOGUES, DEFAULT_LANG, LANGUAGES, formatters, interpolate } from '../i18n';

// PO decision Q-38: one catalogue per language, keys in English; a key missing in either catalogue fails here (and in
// `tsc`, which types the Turkish catalogue against the English key set).

function placeholders(s: string): string[] {
  return [...s.matchAll(/\{([A-Za-z0-9_]+)\}/g)].map((m) => m[1] ?? '').sort();
}

describe('message catalogues', () => {
  it('have exactly the same keys in every language', () => {
    const [first, ...rest] = LANGUAGES.map((l) => ({ lang: l, keys: Object.keys(CATALOGUES[l]).sort() }));
    for (const other of rest) {
      const missingInOther = first!.keys.filter((k) => !other.keys.includes(k));
      const missingInFirst = other.keys.filter((k) => !first!.keys.includes(k));
      expect(missingInOther, `keys missing in ${other.lang}`).toEqual([]);
      expect(missingInFirst, `keys missing in ${first!.lang}`).toEqual([]);
    }
  });

  it('have a non-empty text and the same placeholders for every key', () => {
    for (const key of Object.keys(CATALOGUES.en) as (keyof typeof CATALOGUES.en)[]) {
      for (const lang of LANGUAGES) {
        expect(CATALOGUES[lang][key]?.trim(), `${lang}:${key}`).toBeTruthy();
      }
      expect(placeholders(CATALOGUES.tr[key]), `placeholders of ${key}`).toEqual(placeholders(CATALOGUES.en[key]));
    }
  });

  it('use English keys', () => {
    for (const key of Object.keys(CATALOGUES.en)) {
      expect(key, key).toMatch(/^[A-Za-z0-9_.-]+$/);
    }
  });

  it('carry the Turkish terms the Product Owner chose', () => {
    const tr = CATALOGUES.tr;
    expect(DEFAULT_LANG).toBe('tr');
    expect([tr['nav.overview'], tr['nav.traffic'], tr['nav.incidents'], tr['nav.policies'], tr['nav.platforms']]).toEqual(
      ['Genel bakış', 'Trafik', 'Olaylar', 'Politikalar', 'Platformlar'],
    );
    expect([tr['nav.identities'], tr['nav.administration'], tr['nav.health']]).toEqual([
      'Kimlikler ve roller',
      'Yönetim',
      'Sağlık',
    ]);
    expect([tr['kpi.inspected'], tr['kpi.redacted'], tr['kpi.blocked'], tr['kpi.notInspected'], tr['kpi.coverage']]).toEqual(
      ['İncelenen işlem', 'Maskelenen', 'Engellenen', 'Denetlenemeyen', 'Kapsama oranı'],
    );
    expect([
      tr['verdict.ALLOW'],
      tr['verdict.REDACT'],
      tr['verdict.BLOCK'],
      tr['verdict.UNINSPECTABLE'],
      tr['verdict.STREAM_ABORTED'],
    ]).toEqual(['İzin verildi', 'Maskelendi', 'Engellendi', 'Denetlenemedi', 'Akış kesildi']);
    expect([tr['session.masked'], tr['session.sampleData'], tr['user.signOut']]).toEqual([
      'Maskeli görünüm',
      'Örnek veri',
      'Çıkış yap',
    ]);
  });
});

describe('formatting', () => {
  it('formats numbers and dates as tr-TR and en-GB', () => {
    const tr = formatters('tr');
    const en = formatters('en');
    expect(tr.count(1234567)).toBe('1.234.567');
    expect(en.count(1234567)).toBe('1,234,567');
    expect(tr.bytes(1536)).toBe('1,5 KiB');
    expect(en.bytes(1536)).toBe('1.5 KiB');
    // 09:15 UTC is 12:15 in Istanbul (UTC+3).
    expect(tr.time('2026-10-30T09:15:00Z')).toBe('30.10.2026 12:15:00');
    expect(en.time('2026-10-30T09:15:00Z')).toBe('30/10/2026, 12:15:00');
    expect(tr.time(null)).toBe('—');
  });

  it('interpolates named placeholders and leaves unknown ones visible', () => {
    expect(interpolate('{a} of {b}', { a: 1, b: 'x' })).toBe('1 of x');
    expect(interpolate('{a} {missing}', { a: 1 })).toBe('1 {missing}');
  });
});
