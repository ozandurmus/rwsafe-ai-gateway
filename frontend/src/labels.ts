import type { Verdict } from './api';
import type { I18n } from './i18n';

// Vocabulary shown on screen. Verdicts fold into five groups that carry the reserved status colours; every coloured
// mark also carries its label, so colour never carries meaning alone (dataviz status rule). The words come from the
// message catalogues (src/i18n); the identifiers here stay the server's English vocabulary.

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

export const VERDICTS: Verdict[] = Object.keys(VERDICT_GROUP) as Verdict[];

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

// The template-literal keys below are checked by the compiler against the catalogue: a verdict or group without a
// label does not build.

export function verdictLabel(i: I18n, v: Verdict): string {
  return i.t(`verdict.${v}`);
}

export function groupLabel(i: I18n, g: VerdictGroup): string {
  return i.t(`group.${g}`);
}

/** Platform ids come from data; an id the catalogue does not name is shown as it is. */
export function platformLabel(i: I18n, id: string): string {
  return i.label(`platform.${id}`, id);
}

export function dataClassLabel(i: I18n, c: string): string {
  return i.label(`dataClass.${c}.label`, c);
}

/**
 * A server reason code as a label in the selected language; an unmapped code is shown as the code. The keys are
 * `reason.code_<CODE>`: a dot straight before a code such as INTERNAL would read as an internal host name to the
 * repository privacy gate.
 */
export function reasonLabel(i: I18n, code: string): string {
  return i.label(`reason.code_${code}`, code);
}

export function roleLabel(i: I18n, role: string): string {
  return i.label(`role.${role}`, role);
}
