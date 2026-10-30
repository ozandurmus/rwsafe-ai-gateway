// Counts and states from the Health screen's server details, for the components that carry them (SIEM export, capture,
// capture watermark). The server writes each detail in a fixed English vocabulary (SiemExportService.health,
// CaptureHealth); this reads the numbers out of it so the screen can name them in the selected language. A sentence it
// does not recognise yields no fact: the screen always shows the server's own detail beside them, so nothing is hidden.
// The patterns are anchored on literal words and bounded digit runs; the detail is short, server-made text.

export type FactKey =
  | 'notStarted'
  | 'stalledSeconds'
  | 'heldRows'
  | 'readerFailure'
  | 'senderFailure'
  | 'delivered'
  | 'backlog'
  | 'backlogUncounted'
  | 'queue'
  | 'possiblyLost'
  | 'skippedAtStart'
  | 'activeKey'
  | 'records'
  | 'chunks'
  | 'storedBytes'
  | 'capBytes'
  | 'onHold'
  | 'rewrapRecords'
  | 'rewrapChunks'
  | 'shreddedHeld'
  | 'missingKeys'
  | 'stored'
  | 'noAcknowledgement'
  | 'aboveWatermark'
  | 'detectorHit'
  | 'evicted'
  | 'other'
  | 'usedPercent'
  | 'skipped';

export interface HealthFact {
  key: FactKey;
  /** A count (bytes for `storedBytes` and `capBytes`, a percentage for `usedPercent`) or the server's word. */
  value: number | string;
  /** For `queue`: the capacity beside the depth. */
  of?: number;
}

/** One block of facts; `group` is a SIEM destination (`syslog`, `hec`, `siem`) or null. */
export interface FactGroup {
  group: string | null;
  facts: HealthFact[];
}

/** The components the screen explains in words and reads facts from. */
export const EXPLAINED_COMPONENTS = ['siem', 'capture', 'capture-watermark'] as const;

function num(detail: string, pattern: RegExp, key: FactKey, out: HealthFact[]) {
  const m = pattern.exec(detail);
  if (m?.[1] !== undefined) {
    out.push({ key, value: Number(m[1]) });
  }
}

function siem(detail: string): FactGroup[] {
  const groups: FactGroup[] = [];
  // A destination's part starts with its name; a refusal reason may hold "; " itself, so split only before a name.
  for (const part of detail.split(/; (?=(?:syslog|hec|siem): )/)) {
    const m = /^(syslog|hec|siem): ([\s\S]*)$/.exec(part);
    if (!m) {
      continue;
    }
    const group = m[1] ?? null;
    const rest = m[2] ?? '';
    const facts: HealthFact[] = [];
    if (rest.startsWith('not started, ')) {
      facts.push({ key: 'notStarted', value: rest.substring('not started, '.length) });
      groups.push({ group, facts });
      continue;
    }
    const stall = /stalled: no progress for over (\d{1,9}) s with (\d{1,18}) rows held/.exec(rest);
    if (stall) {
      facts.push({ key: 'stalledSeconds', value: Number(stall[1]) });
      facts.push({ key: 'heldRows', value: Number(stall[2]) });
    }
    const retry = /retrying after a failure \(([a-z ,]{1,80})\)/.exec(rest);
    if (retry?.[1]) {
      for (const piece of retry[1].split(', ')) {
        const [who, what] = piece.split(' ');
        if (what && (who === 'reader' || who === 'sender')) {
          facts.push({ key: who === 'reader' ? 'readerFailure' : 'senderFailure', value: what });
        }
      }
    }
    num(rest, /(\d{1,18}) events delivered/, 'delivered', facts);
    if (/backlog not counted yet/.test(rest)) {
      facts.push({ key: 'backlogUncounted', value: '' });
    } else {
      num(rest, /backlog (\d{1,18})/, 'backlog', facts);
    }
    const queue = /queue (\d{1,9})\/(\d{1,9})/.exec(rest);
    if (queue) {
      facts.push({ key: 'queue', value: Number(queue[1]), of: Number(queue[2]) });
    }
    num(rest, /(\d{1,18}) batches possibly lost/, 'possiblyLost', facts);
    num(rest, /(\d{1,18}) verdict events skipped at a latest start/, 'skippedAtStart', facts);
    groups.push({ group, facts });
  }
  return groups;
}

function capture(detail: string): FactGroup[] {
  const facts: HealthFact[] = [];
  const key = /active key ([^;]{1,64});/.exec(detail);
  if (key?.[1]) {
    facts.push({ key: 'activeKey', value: key[1] });
  }
  const totals = /(\d{1,18}) records, (\d{1,18}) chunks, (\d{1,18}) of (\d{1,18}) bytes, (\d{1,18}) on hold/.exec(detail);
  if (totals) {
    facts.push({ key: 'records', value: Number(totals[1]) });
    facts.push({ key: 'chunks', value: Number(totals[2]) });
    facts.push({ key: 'storedBytes', value: Number(totals[3]) });
    facts.push({ key: 'capBytes', value: Number(totals[4]) });
    facts.push({ key: 'onHold', value: Number(totals[5]) });
  }
  const rewrap = /re-wrap from older mounted keys: (\d{1,18}) records and (\d{1,18}) chunks/.exec(detail);
  if (rewrap) {
    facts.push({ key: 'rewrapRecords', value: Number(rewrap[1]) });
    facts.push({ key: 'rewrapChunks', value: Number(rewrap[2]) });
  }
  num(detail, /held under shredded keys: (\d{1,18})/, 'shreddedHeld', facts);
  num(detail, /; under missing keys: (\d{1,18})/, 'missingKeys', facts);
  const since =
    /since start: stored (\d{1,18}), without acknowledgement (\d{1,18}), above the watermark (\d{1,18}), detector hit refused (\d{1,18}), evicted for the cap (\d{1,18}), other (\d{1,18})/.exec(
      detail,
    );
  if (since) {
    const keys: FactKey[] = ['stored', 'noAcknowledgement', 'aboveWatermark', 'detectorHit', 'evicted', 'other'];
    keys.forEach((k, i) => facts.push({ key: k, value: Number(since[i + 1]) }));
  }
  return facts.length === 0 ? [] : [{ group: null, facts }];
}

function watermark(detail: string): FactGroup[] {
  const facts: HealthFact[] = [];
  const used = /^(\d{1,3}(?:\.\d)?) % used/.exec(detail);
  if (used) {
    facts.push({ key: 'usedPercent', value: Number(used[1]) });
  }
  num(detail, /(\d{1,18}) captures skipped since start/, 'skipped', facts);
  return facts.length === 0 ? [] : [{ group: null, facts }];
}

/** The facts of one component's detail; empty for a component the screen does not read facts from. */
export function healthFacts(component: string, detail: string): FactGroup[] {
  switch (component) {
    case 'siem':
      return siem(detail);
    case 'capture':
      return capture(detail);
    case 'capture-watermark':
      return watermark(detail);
    default:
      return [];
  }
}
