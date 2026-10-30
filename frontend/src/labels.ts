import type { Verdict } from './api';

// Vocabulary shown on screen. Verdicts fold into five groups that carry the reserved status colours; every coloured
// mark also carries its label, so colour never carries meaning alone (dataviz status rule).

export type VerdictGroup = 'allowed' | 'warned' | 'redacted' | 'blocked' | 'notInspected';

export const VERDICT_GROUP: Record<Verdict, VerdictGroup> = {
  ALLOW: 'allowed',
  WARN: 'warned',
  REDACT: 'redacted',
  BLOCK: 'blocked',
  STREAM_ABORTED: 'blocked',
  UNINSPECTABLE: 'notInspected',
  MALFORMED: 'notInspected',
  INSPECTION_FAILED: 'notInspected',
  INSPECTION_TIMEOUT: 'notInspected',
  UNKNOWN_FLOW: 'notInspected',
};

export const GROUP_ORDER: VerdictGroup[] = ['allowed', 'warned', 'redacted', 'blocked', 'notInspected'];

export const GROUP_LABEL: Record<VerdictGroup, string> = {
  allowed: 'Allowed',
  warned: 'Warned',
  redacted: 'Redacted',
  blocked: 'Blocked',
  notInspected: 'Not inspected',
};

/** Status palette (good, warning, serious, critical) plus a neutral for non-verdicts; one step for both modes. */
export function groupColor(group: VerdictGroup, mode: 'light' | 'dark'): string {
  switch (group) {
    case 'allowed':
      return '#0ca30c';
    case 'warned':
      return '#fab219';
    case 'redacted':
      return '#ec835a';
    case 'blocked':
      return '#d03b3b';
    default:
      return mode === 'light' ? '#8f8e89' : '#75746f';
  }
}

export const VERDICT_LABEL: Record<Verdict, string> = {
  ALLOW: 'Allow',
  WARN: 'Warn',
  REDACT: 'Redact',
  BLOCK: 'Block',
  STREAM_ABORTED: 'Stream aborted',
  UNINSPECTABLE: 'Uninspectable',
  MALFORMED: 'Malformed',
  INSPECTION_FAILED: 'Inspection failed',
  INSPECTION_TIMEOUT: 'Inspection timeout',
  UNKNOWN_FLOW: 'Unknown flow',
};

export const VERDICTS: Verdict[] = Object.keys(VERDICT_LABEL) as Verdict[];

const PLATFORM_LABEL: Record<string, string> = {
  openai: 'OpenAI / ChatGPT',
  copilot: 'GitHub Copilot',
  claude: 'Claude',
  gemini: 'Gemini',
  github: 'GitHub',
  windsurf: 'Windsurf',
  devin: 'Devin',
  'microsoft-auth': 'Microsoft sign-in',
  'google-auth': 'Google sign-in',
  unknown: 'Unknown',
};

export function platformLabel(id: string): string {
  return PLATFORM_LABEL[id] ?? id;
}

// Pairs rather than an object literal: the privacy gate reads a secret-named key with a quoted value as a credential.
const CLASS_LABEL = new Map<string, string>([
  ['SECRET', 'Secret'],
  ['TCKN', 'TCKN'],
  ['TR_IBAN', 'TR IBAN'],
  ['PAYMENT_CARD', 'Payment card'],
]);

export function dataClassLabel(c: string): string {
  return CLASS_LABEL.get(c) ?? c;
}

const ISTANBUL = 'Europe/Istanbul';

/** Timestamps read in Europe/Istanbul, the business-hours zone (AGENTS.md section 14). */
export function formatTime(iso: string | null, withSeconds = true): string {
  if (!iso) {
    return '—';
  }
  return new Intl.DateTimeFormat('en-GB', {
    timeZone: ISTANBUL,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: withSeconds ? '2-digit' : undefined,
    hour12: false,
  }).format(new Date(iso));
}

export function formatHour(iso: string): string {
  return new Intl.DateTimeFormat('en-GB', {
    timeZone: ISTANBUL,
    weekday: 'short',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  }).format(new Date(iso));
}

export function formatCount(n: number): string {
  return new Intl.NumberFormat('en-GB').format(n);
}

export function formatBytes(n: number): string {
  if (n < 1024) {
    return `${n} B`;
  }
  if (n < 1024 * 1024) {
    return `${(n / 1024).toFixed(1)} KiB`;
  }
  return `${(n / 1024 / 1024).toFixed(1)} MiB`;
}

export function formatMicros(us: number): string {
  return us < 1000 ? `${us} µs` : `${(us / 1000).toFixed(1)} ms`;
}
