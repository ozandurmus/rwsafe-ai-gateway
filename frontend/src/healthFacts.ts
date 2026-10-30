// The Health screen's counts for the components that carry them (SIEM export, capture, capture watermark), read from the
// server's structured `counts` (PR 28 review D-03: SiemExportService.Health, CaptureHealth), never from the detail
// sentence. A value that is not a non-negative safe integer is dropped, so a wrong number is never shown as fact; the
// server's own detail is always shown beside the facts.

export type FactKey =
  | 'notStarted'
  | 'stalled'
  | 'heldBehindOpenTransaction'
  | 'readerFailure'
  | 'senderFailure'
  | 'delivered'
  | 'backlog'
  | 'backlogUncounted'
  | 'queue'
  | 'possiblyLostBatches'
  | 'skippedAtStart'
  | 'keyAvailable'
  | 'storeWritable'
  | 'records'
  | 'chunks'
  | 'storedBytes'
  | 'maxBytes'
  | 'heldRecords'
  | 'rewrapRecords'
  | 'rewrapChunks'
  | 'shreddedKeyRecords'
  | 'missingKeyRecords'
  | 'stored'
  | 'noAcknowledgement'
  | 'aboveWatermark'
  | 'detectorHit'
  | 'evicted'
  | 'other'
  | 'usedPercent'
  | 'stale'
  | 'skipped';

export interface HealthFact {
  key: FactKey;
  /**
   * A count (bytes for `storedBytes` and `maxBytes`, a percentage for `usedPercent`), a yes/no state
   * (`keyAvailable`, `storeWritable`), a failure class (`readerFailure`, `senderFailure`), or true for a condition
   * (`notStarted`, `stalled`, `stale`, `backlogUncounted`).
   */
  value: number | string | boolean;
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

const SIEM_DESTINATIONS = ['siem', 'syslog', 'hec'] as const;
const FAILURE_CLASSES = ['connect', 'tls', 'io', 'timeout', 'auth', 'rejected', 'unavailable', 'database'];

type Counts = Record<string, unknown> | undefined | null;

/** A count the screen may show: a non-negative safe integer, or undefined. */
function count(counts: Counts, key: string): number | undefined {
  if (!counts || !Object.prototype.hasOwnProperty.call(counts, key)) {
    return undefined;
  }
  const v = counts[key];
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 ? v : undefined;
}

function push(out: HealthFact[], key: FactKey, value: number | undefined) {
  if (value !== undefined) {
    out.push({ key, value });
  }
}

function siem(counts: Counts): FactGroup[] {
  const groups: FactGroup[] = [];
  for (const d of SIEM_DESTINATIONS) {
    const k = (name: string) => count(counts, `${d}.${name}`);
    const facts: HealthFact[] = [];
    if (k('notStarted') === 1) {
      facts.push({ key: 'notStarted', value: true });
    }
    if (k('stalled') === 1) {
      facts.push({ key: 'stalled', value: true });
    }
    for (const thread of ['readerFailure', 'senderFailure'] as const) {
      for (const cls of FAILURE_CLASSES) {
        if (k(`${thread}.${cls}`) === 1) {
          facts.push({ key: thread, value: cls });
        }
      }
    }
    const delivered = k('delivered');
    push(facts, 'delivered', delivered);
    const backlog = k('backlog');
    if (backlog !== undefined) {
      facts.push({ key: 'backlog', value: backlog });
    } else if (delivered !== undefined) {
      facts.push({ key: 'backlogUncounted', value: true });
    }
    const depth = k('queueDepth');
    const capacity = k('queueCapacity');
    if (depth !== undefined && capacity !== undefined) {
      facts.push({ key: 'queue', value: depth, of: capacity });
    }
    push(facts, 'heldBehindOpenTransaction', k('heldBehindOpenTransaction'));
    push(facts, 'possiblyLostBatches', k('possiblyLostBatches'));
    push(facts, 'skippedAtStart', k('skippedAtStart'));
    if (facts.length > 0) {
      groups.push({ group: d, facts });
    }
  }
  return groups;
}

function flag(out: HealthFact[], key: FactKey, value: number | undefined) {
  if (value === 0 || value === 1) {
    out.push({ key, value: value === 1 });
  }
}

function capture(counts: Counts): FactGroup[] {
  const facts: HealthFact[] = [];
  if (count(counts, 'captureOn') !== 1) {
    return [];
  }
  flag(facts, 'keyAvailable', count(counts, 'keyAvailable'));
  flag(facts, 'storeWritable', count(counts, 'storeWritable'));
  const keys: FactKey[] = [
    'records',
    'chunks',
    'storedBytes',
    'maxBytes',
    'heldRecords',
    'rewrapRecords',
    'rewrapChunks',
    'shreddedKeyRecords',
    'missingKeyRecords',
    'stored',
    'noAcknowledgement',
    'aboveWatermark',
    'detectorHit',
    'evicted',
    'other',
  ];
  keys.forEach((k) => push(facts, k, count(counts, k)));
  return facts.length === 0 ? [] : [{ group: null, facts }];
}

function watermark(counts: Counts): FactGroup[] {
  const facts: HealthFact[] = [];
  if (count(counts, 'stale') === 1) {
    facts.push({ key: 'stale', value: true });
  }
  const perMille = count(counts, 'usedPerMille');
  if (perMille !== undefined && perMille <= 1000) {
    facts.push({ key: 'usedPercent', value: perMille / 10 });
  }
  push(facts, 'skipped', count(counts, 'skipped'));
  return facts.length === 0 ? [] : [{ group: null, facts }];
}

/** The facts of one component's counts; empty for a component the screen does not read facts from. */
export function healthFacts(component: string, counts: Counts): FactGroup[] {
  switch (component) {
    case 'siem':
      return siem(counts);
    case 'capture':
      return capture(counts);
    case 'capture-watermark':
      return watermark(counts);
    default:
      return [];
  }
}
