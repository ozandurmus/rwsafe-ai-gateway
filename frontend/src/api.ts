// The one API client module (CORPORATE_TECHNOLOGY_STACK §2: the browser fetch API behind one module). Same-origin calls,
// the session cookie, and the CSRF header from the CSRF cookie on every mutation. A failure always carries the server's
// reason class and sentence (AGENTS.md section 14), never a bare "Request failed".

export type Verdict =
  | 'ALLOW'
  | 'WARN'
  | 'REDACT'
  | 'BLOCK'
  | 'UNINSPECTABLE'
  | 'MALFORMED'
  | 'INSPECTION_FAILED'
  | 'INSPECTION_TIMEOUT'
  | 'UNKNOWN_FLOW'
  | 'STREAM_ABORTED';

export interface Me {
  displayName: string;
  roles: string[];
  masked: boolean;
  source: string | null;
}

export interface Overview {
  from: string;
  to: string;
  total: number;
  verdicts: { verdict: Verdict; count: number }[];
  platforms: { platform: string; total: number; redacted: number; blocked: number; nonVerdicts: number }[];
  hours: { hour: string; total: number; byVerdict: Partial<Record<Verdict, number>> }[];
  findings: { dataClass: string; events: number; hits: number }[];
}

export interface EventItem {
  eventId: string;
  receivedAt: string;
  service: 'reqmod' | 'respmod';
  platform: string;
  surface: string;
  step: string;
  verdict: Verdict;
  reason: string | null;
  findings: { dataClass: string; count: number }[];
  bodyBytes: number;
  decisionMicros: number;
  user: string | null;
  clientSubnet: string | null;
  transport: string;
  snapshotVersion: number;
  correlationId: string;
  pseudonymKeyId: string;
  /** Snapshot format 2 scoped-rule ids that decided the verdict, and the monitor rules that would have changed it. */
  appliedRuleIds?: string[];
  monitorRuleIds?: string[];
}

export interface TrafficPage {
  items: EventItem[];
  nextCursor: string | null;
}

export interface Health {
  checkedAt: string;
  components: { component: string; state: 'UP' | 'DOWN' | 'DEGRADED' | 'UNKNOWN'; detail: string }[];
  eventsLastFiveMinutes: number;
  totalEvents: number;
  latestEventAt: string | null;
}

// Policy registry (AGENTS.md section 6): vocabulary stays the server's English identifiers.
export type RuleKind = 'class_action' | 'platform' | 'flow';
export type PolicyAction = 'ALLOW' | 'WARN' | 'REDACT' | 'BLOCK';
export type PolicyMode = 'monitor' | 'enforce';
export type RolloutStage = 'pilot' | 'pct25' | 'pct50' | 'all';
export type VersionStatus = 'pending' | 'active' | 'superseded' | 'retired' | 'withdrawn';
/** PO decision Q-39: a version applies to everyone (ANY) or to the members of named directory groups. */
export type ScopeKind = 'ANY' | 'GROUPS';

export interface Scope {
  kind: ScopeKind;
  groups: string[];
}
export type ApproverRole = 'security_admin' | 'privacy_officer';

export interface RuleVersion {
  ruleId: string;
  version: number;
  action: PolicyAction | null;
  enforceFailClosed: boolean | null;
  hostSuffixes: string[] | null;
  apiHosts: string[] | null;
  loginHosts: string[] | null;
  mode: PolicyMode;
  rolloutStage: RolloutStage;
  status: VersionStatus;
  source: 'seed' | 'registry';
  author: string;
  reasonCode: string;
  createdAt: string;
  activatedAt: string | null;
  supersededAt: string | null;
  scope: Scope;
  /** PO decision Q-40: how a platform row left service; null for every other version. */
  retirement: { retiredAt: string; retiredBy: string; reason: string } | null;
  /**
   * PR 21 Q-41: on a withdrawal request, the version it withdraws and the reason; on a withdrawn version, when (the
   * other two fields are null). Null for every other version.
   */
  withdrawal: { withdrawsVersion: number | null; reason: string | null; withdrawnAt: string | null } | null;
  approvals: { role: ApproverRole; approver: string; approvedAt: string }[];
  inSnapshot: boolean;
}

export interface Rule {
  ruleId: string;
  kind: RuleKind;
  subject: string;
  failClosed: boolean;
  versions: RuleVersion[];
}

export interface Registry {
  rules: Rule[];
  snapshot: {
    version: number;
    id: string;
    issuedAt: string;
    documentSha256: string;
    ruleVersions: string[];
    approvers: string[];
    keyId: string | null;
  } | null;
  failClosedClasses: string[];
  actions: PolicyAction[];
  modes: PolicyMode[];
  stages: RolloutStage[];
  scopeKinds: ScopeKind[];
  maxScopeGroups: number;
}

export interface DraftRequest {
  action?: PolicyAction;
  enforceFailClosed?: boolean;
  hostSuffixes?: string[];
  apiHosts?: string[];
  loginHosts?: string[];
  mode: PolicyMode;
  scope: Scope;
  reasonCode: string;
}

export interface Simulation {
  ruleId: string;
  dataClass: string;
  currentAction: PolicyAction | null;
  proposedAction: PolicyAction;
  from: string;
  to: string;
  eventsInWindow: number;
  eventsWithClass: number;
  eventsChanged: number;
  eventsNotReevaluated: number;
  transitions: { from: Verdict; to: Verdict; events: number }[];
}

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly reason: string,
    message: string,
  ) {
    super(message);
  }
}

function csrfToken(): string {
  const match = document.cookie.split('; ').find((c) => c.startsWith('XSRF-TOKEN='));
  return match ? decodeURIComponent(match.substring('XSRF-TOKEN='.length)) : '';
}

async function request<T>(method: 'GET' | 'POST', path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (method !== 'GET') {
    headers['Content-Type'] = 'application/json';
    headers['X-XSRF-TOKEN'] = csrfToken();
  }
  let response: Response;
  try {
    response = await fetch(path, {
      method,
      headers,
      credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError(0, 'CONTROL_PLANE_UNREACHABLE', 'The control plane did not answer; check that it is running.');
  }
  if (response.status === 204) {
    return undefined as T;
  }
  const text = await response.text();
  let json: unknown = null;
  if (text) {
    try {
      json = JSON.parse(text);
    } catch {
      json = null;
    }
  }
  if (!response.ok) {
    const e = json as { reason?: unknown; message?: unknown } | null;
    const reason = typeof e?.reason === 'string' ? e.reason : `HTTP_${response.status}`;
    const message =
      typeof e?.message === 'string' ? e.message : `The control plane answered ${response.status} without a reason.`;
    throw new ApiError(response.status, reason, message);
  }
  return json as T;
}

function query(params: Record<string, string | number | undefined | null>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== '') {
      q.set(k, String(v));
    }
  }
  const s = q.toString();
  return s ? `?${s}` : '';
}

export interface TrafficFilter {
  from?: string;
  to?: string;
  platform?: string;
  verdict?: Verdict | '';
  service?: string;
  user?: string;
  limit?: number;
  cursor?: string | null;
}

export const api = {
  csrf: () => request<{ headerName: string; token: string }>('GET', '/api/v1/auth/csrf'),
  async login(loginName: string, password: string): Promise<Me> {
    await api.csrf();
    return request<Me>('POST', '/api/v1/auth/login', { loginName, password });
  },
  me: () => request<Me>('GET', '/api/v1/auth/me'),
  logout: () => request<void>('POST', '/api/v1/auth/logout'),
  overview: (from: string, to: string) => request<Overview>('GET', `/api/v1/overview${query({ from, to })}`),
  traffic: (f: TrafficFilter) =>
    request<TrafficPage>(
      'GET',
      `/api/v1/traffic${query({
        from: f.from,
        to: f.to,
        platform: f.platform,
        verdict: f.verdict,
        service: f.service,
        user: f.user,
        limit: f.limit,
        cursor: f.cursor,
      })}`,
    ),
  event: (id: string) => request<EventItem>('GET', `/api/v1/traffic/${encodeURIComponent(id)}`),
  platforms: (from: string, to: string) =>
    request<{ platforms: string[] }>('GET', `/api/v1/platforms${query({ from, to })}`),
  health: () => request<Health>('GET', '/api/v1/health'),
  policyRules: () => request<Registry>('GET', '/api/v1/policy/rules'),
  draftVersion: (ruleId: string, body: DraftRequest) =>
    request<RuleVersion>('POST', `/api/v1/policy/rules/${encodeURIComponent(ruleId)}/versions`, body),
  approve: (ruleId: string, version: number, role: ApproverRole) =>
    request<RuleVersion>(
      'POST',
      `/api/v1/policy/rules/${encodeURIComponent(ruleId)}/versions/${version}/approvals`,
      { role },
    ),
  requestWithdrawal: (ruleId: string, version: number, reason: string) =>
    request<RuleVersion>(
      'POST',
      `/api/v1/policy/rules/${encodeURIComponent(ruleId)}/versions/${version}/withdrawal`,
      { reason },
    ),
  retirePlatform: (ruleId: string, reason: string) =>
    request<{ retired: RuleVersion[] }>('POST', `/api/v1/policy/rules/${encodeURIComponent(ruleId)}/retirement`, {
      reason,
    }),
  simulate: (ruleId: string, action: PolicyAction) =>
    request<Simulation>('GET', `/api/v1/policy/simulation${query({ ruleId, action })}`),
};
