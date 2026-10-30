import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import en from './en.json';
import trCatalogue from './tr.json';

// The admin UI's i18n layer (PO decision Q-38, PO_DECISION_RECORD_2026_10_30_ADMIN_UI_LANGUAGE): one message catalogue per
// language, keys in English, Turkish by default, the choice remembered per user. Server reason codes stay English
// identifiers and are mapped to labels here (`reason.code_<CODE>`); the server's own sentence is shown beside the label.

export type Lang = 'tr' | 'en';
export type MessageKey = keyof typeof en;
export type Catalogue = Record<MessageKey, string>;

/** Both catalogues are checked against the English key set by the compiler and by `i18n.test.ts`. */
const tr: Catalogue = trCatalogue;
export const CATALOGUES: Record<Lang, Catalogue> = { tr, en };
export const LANGUAGES: Lang[] = ['tr', 'en'];
export const DEFAULT_LANG: Lang = 'tr';
const LOCALE: Record<Lang, string> = { tr: 'tr-TR', en: 'en-GB' };
const ISTANBUL = 'Europe/Istanbul';

// Preference store: no server-side user settings store exists yet, so the choice lives in this browser, keyed by the
// signed-in user's display name (the last choice also applies on the sign-in page). Storage can be unavailable (private
// windows, blocked site data): every access is guarded and the UI falls back to the default.
const STORAGE_KEY = 'rwsafe.ui.lang';

function isLang(v: unknown): v is Lang {
  return v === 'tr' || v === 'en';
}

export function storedLanguage(user: string | null): Lang | null {
  try {
    const v = window.localStorage.getItem(user ? `${STORAGE_KEY}:${user}` : STORAGE_KEY);
    return isLang(v) ? v : null;
  } catch {
    return null;
  }
}

function storeLanguage(lang: Lang, user: string | null) {
  try {
    window.localStorage.setItem(STORAGE_KEY, lang);
    if (user) {
      window.localStorage.setItem(`${STORAGE_KEY}:${user}`, lang);
    }
  } catch {
    // the choice then lasts for this page only
  }
}

/** `{name}` placeholders; an unknown placeholder stays visible so a missing parameter is noticed. */
export function interpolate(template: string, params?: Record<string, string | number>): string {
  if (!params) {
    return template;
  }
  return template.replace(/\{([A-Za-z0-9_]+)\}/g, (whole, name: string) =>
    Object.prototype.hasOwnProperty.call(params, name) ? String(params[name]) : whole,
  );
}

/**
 * A catalogue entry by a key built at runtime (a server code, a platform id): only the catalogue's own keys count, so a
 * key such as `constructor` or `__proto__` gives the fallback, never an inherited member (PR 16 review D-07).
 */
export function catalogueLabel(lang: Lang, key: string, fallback: string): string {
  const lookup = CATALOGUES[lang] as Record<string, string>;
  return Object.prototype.hasOwnProperty.call(lookup, key) ? (lookup[key] ?? fallback) : fallback;
}

export interface Formatters {
  count: (n: number) => string;
  percent: (part: number, total: number) => string;
  /** A percentage given as a number from 0 to 100, with one decimal. */
  percentValue: (value: number) => string;
  time: (iso: string | null, withSeconds?: boolean) => string;
  hour: (iso: string) => string;
  bytes: (n: number) => string;
  micros: (us: number) => string;
}

/** Numbers and dates in the language's locale (tr-TR, en-GB); times read in Europe/Istanbul (AGENTS.md section 14). */
export function formatters(lang: Lang): Formatters {
  const locale = LOCALE[lang];
  const integer = new Intl.NumberFormat(locale);
  const oneDecimal = new Intl.NumberFormat(locale, { minimumFractionDigits: 1, maximumFractionDigits: 1 });
  const percent = new Intl.NumberFormat(locale, { style: 'percent', minimumFractionDigits: 1, maximumFractionDigits: 1 });
  const hour = new Intl.DateTimeFormat(locale, {
    timeZone: ISTANBUL,
    weekday: 'short',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
  return {
    count: (n) => integer.format(n),
    percent: (part, total) => percent.format(total === 0 ? 0 : part / total),
    percentValue: (value) => percent.format(value / 100),
    time: (iso, withSeconds = true) => {
      if (!iso) {
        return '—';
      }
      return new Intl.DateTimeFormat(locale, {
        timeZone: ISTANBUL,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: withSeconds ? '2-digit' : undefined,
        hour12: false,
      }).format(new Date(iso));
    },
    hour: (iso) => hour.format(new Date(iso)),
    bytes: (n) => {
      if (n < 1024) {
        return `${integer.format(n)} B`;
      }
      if (n < 1024 * 1024) {
        return `${oneDecimal.format(n / 1024)} KiB`;
      }
      if (n < 1024 * 1024 * 1024) {
        return `${oneDecimal.format(n / 1024 / 1024)} MiB`;
      }
      return `${oneDecimal.format(n / 1024 / 1024 / 1024)} GiB`;
    },
    micros: (us) => (us < 1000 ? `${integer.format(us)} µs` : `${oneDecimal.format(us / 1000)} ms`),
  };
}

export interface I18n {
  lang: Lang;
  locale: string;
  t: (key: MessageKey, params?: Record<string, string | number>) => string;
  /** A catalogue entry by a key built at runtime (a server code, a platform id), or `fallback` when there is none. */
  label: (key: string, fallback: string) => string;
  fmt: Formatters;
  setLanguage: (lang: Lang) => void;
}

const I18nContext = createContext<I18n | null>(null);

/**
 * Holds the language. `user` is the signed-in user's display name (null before sign-in): when it changes, that user's
 * remembered choice applies, and a new choice is remembered for that user.
 */
export function I18nProvider({
  children,
  initial,
  user = null,
}: {
  children: React.ReactNode;
  initial?: Lang;
  user?: string | null;
}) {
  const [lang, setLang] = useState<Lang>(() => initial ?? storedLanguage(null) ?? DEFAULT_LANG);

  useEffect(() => {
    if (user) {
      const remembered = storedLanguage(user);
      if (remembered) {
        setLang(remembered);
      }
    }
  }, [user]);

  useEffect(() => {
    try {
      document.documentElement.lang = lang;
    } catch {
      // no document (never in the browser)
    }
  }, [lang]);

  const setLanguage = useCallback(
    (next: Lang) => {
      setLang(next);
      storeLanguage(next, user);
    },
    [user],
  );

  const value = useMemo<I18n>(() => {
    const catalogue = CATALOGUES[lang];
    return {
      lang,
      locale: LOCALE[lang],
      t: (key, params) => interpolate(catalogue[key] ?? key, params),
      label: (key, fallback) => catalogueLabel(lang, key, fallback),
      fmt: formatters(lang),
      setLanguage,
    };
  }, [lang, setLanguage]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useI18n(): I18n {
  const ctx = useContext(I18nContext);
  if (!ctx) {
    throw new Error('useI18n outside I18nProvider');
  }
  return ctx;
}
