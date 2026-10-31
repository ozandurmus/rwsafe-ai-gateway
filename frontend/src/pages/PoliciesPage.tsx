import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Chip,
  FormControl,
  FormControlLabel,
  FormLabel,
  Grid,
  InputLabel,
  MenuItem,
  Radio,
  RadioGroup,
  Select,
  Step,
  StepContent,
  StepLabel,
  Stepper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material';
import { useState } from 'react';
import {
  api,
  type ApproverRole,
  type DraftRequest,
  type PolicyAction,
  type PolicyMode,
  type Registry,
  type Rule,
  type RuleVersion,
  type Scope,
  type ScopeKind,
  type Simulation,
} from '../api';
import { useAuth } from '../auth';
import { Empty, ErrorPanel, Loading } from '../components/StatePanel';
import { type I18n, useI18n } from '../i18n';
import {
  actionLabel,
  dataClassLabel,
  modeLabel,
  platformLabel,
  roleLabel,
  stageLabel,
  statusLabel,
  verdictLabel,
} from '../labels';
import { useApi } from '../useApi';

const APPROVER_ROLES: ApproverRole[] = ['security_admin', 'privacy_officer'];
const RELAXING: PolicyAction[] = ['ALLOW', 'WARN'];

/** The version the data plane enforces for everyone: active, enforce, stage all, scope ANY (snapshot classActions). */
export function baseline(rule: Rule): RuleVersion | undefined {
  return rule.versions.find(
    (v) => v.status === 'active' && v.mode === 'enforce' && v.rolloutStage === 'all' && v.scope.kind === 'ANY',
  );
}

/**
 * The active group-scoped versions (snapshot scopedRules, enforce and monitor), oldest first. A withdrawn version is not
 * active; an active V3 withdrawal request kept as history only marks a withdrawn scope and is left out.
 */
export function scopedVersions(rule: Rule): RuleVersion[] {
  return rule.versions
    .filter((v) => v.status === 'active' && v.scope.kind === 'GROUPS' && !isWithdrawalRequest(v))
    .reverse();
}

/** A V3 withdrawal request kept as history (it names the version it withdrew); none is created since PO decision Q-41. */
export function isWithdrawalRequest(v: RuleVersion): boolean {
  return v.withdrawal?.withdrawsVersion != null;
}

/**
 * The comparison form of a directory group name, the same rule as the server's (java/policy GroupNames): trim, NFC,
 * the Turkish capital dotted I, capital I and dotless i become i, lower case, a combining dot above after an i removed,
 * NFC again. Used only to tell the operator at once that a name is already in the list (PR 21 review D-07); the server
 * stores and compares this form itself.
 */
export function foldGroupName(name: string): string {
  return name
    .trim()
    .normalize('NFC')
    .replace(/[İIı]/g, 'i')
    .toLowerCase()
    .replace(/i̇/g, 'i')
    .normalize('NFC');
}

/** "Herkes" / "Everyone", or the group names (as the server sends them: real names, or pseudonyms when masked). */
export function scopeText(i18n: I18n, scope: Scope): string {
  return scope.kind === 'ANY' ? i18n.t('scope.everyone') : scope.groups.join(', ');
}

/** The scope as chips: one "Everyone" chip, or one chip per group. */
export function ScopeChips({ scope }: { scope: Scope }) {
  const { t } = useI18n();
  if (scope.kind === 'ANY') {
    return <Chip size="small" variant="outlined" label={t('scope.everyone')} />;
  }
  return (
    <Box component="span" display="inline-flex" gap={0.5} flexWrap="wrap" aria-label={t('scope.groupsAria')}>
      {scope.groups.map((g) => (
        <Chip key={g} size="small" color="info" variant="outlined" label={g} />
      ))}
    </Box>
  );
}

export function ruleName(i18n: I18n, rule: Rule): string {
  if (rule.kind === 'class_action') {
    return dataClassLabel(i18n, rule.subject);
  }
  if (rule.kind === 'flow') {
    return i18n.t('policies.flowRule');
  }
  return platformLabel(i18n, rule.subject);
}

function valueOf(i18n: I18n, v: RuleVersion | undefined): string {
  if (!v) {
    return '—';
  }
  if (v.action) {
    return actionLabel(i18n, v.action);
  }
  return v.enforceFailClosed ? i18n.t('policies.flowValue') : '—';
}

/** Policies: the registry table (class and flow rules), the selected rule's versions, approvals and simulation. */
export function PoliciesPage() {
  const i18n = useI18n();
  const { t, fmt } = i18n;
  const [generation, setGeneration] = useState(0);
  const { data, error, loading } = useApi(() => api.policyRules(), `rules:${generation}`);
  const [selected, setSelected] = useState<string | null>(null);
  const rules = (data?.rules ?? []).filter((r) => r.kind !== 'platform');
  const rule = rules.find((r) => r.ruleId === selected) ?? null;

  return (
    <Box display="grid" gap={2}>
      <Typography variant="h5" component="h1" sx={{ fontWeight: 600 }}>
        {t('policies.title')}
      </Typography>
      {data && (
        <Typography color="text.secondary">
          {data.snapshot
            ? t('policies.snapshot', {
                version: data.snapshot.version,
                id: data.snapshot.id,
                time: fmt.time(data.snapshot.issuedAt),
                keyId: data.snapshot.keyId ?? '—',
              })
            : t('policies.noSnapshot')}
        </Typography>
      )}
      {error !== null && <ErrorPanel error={error} />}
      {loading && !data && <Loading />}
      {data && (
        <Grid container spacing={2} alignItems="flex-start">
          <Grid item xs={12} lg={7}>
            <Card variant="outlined">
              <TableContainer>
                <Table size="small" aria-label={t('policies.table')}>
                  <TableHead>
                    <TableRow>
                      <TableCell>{t('policies.col.rule')}</TableCell>
                      <TableCell>{t('policies.col.action')}</TableCell>
                      <TableCell>{t('policies.col.mode')}</TableCell>
                      <TableCell>{t('policies.col.scope')}</TableCell>
                      <TableCell>{t('policies.col.version')}</TableCell>
                      <TableCell>{t('policies.col.status')}</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {rules.map((r) => {
                      const base = baseline(r);
                      const scoped = scopedVersions(r);
                      const pending = r.versions.filter((v) => v.status === 'pending').length;
                      return (
                        <TableRow
                          key={r.ruleId}
                          hover
                          selected={r.ruleId === selected}
                          tabIndex={0}
                          sx={{ cursor: 'pointer' }}
                          onClick={() => setSelected(r.ruleId)}
                          onKeyDown={(k) => k.key === 'Enter' && setSelected(r.ruleId)}
                        >
                          <TableCell>
                            <Box display="flex" alignItems="center" gap={1} flexWrap="wrap">
                              {ruleName(i18n, r)}
                              {r.failClosed && <Chip size="small" variant="outlined" label={t('policies.failClosed')} />}
                            </Box>
                          </TableCell>
                          <TableCell>{valueOf(i18n, base)}</TableCell>
                          <TableCell>{base ? modeLabel(i18n, base.mode) : '—'}</TableCell>
                          <TableCell>
                            <Box display="grid" gap={0.5} justifyItems="start">
                              {base && <ScopeChips scope={base.scope} />}
                              {scoped.map((v) => (
                                <Box key={v.version} display="flex" alignItems="center" gap={0.5} flexWrap="wrap">
                                  <ScopeChips scope={v.scope} />
                                  <Typography variant="caption" color="text.secondary">
                                    {`${valueOf(i18n, v)} · ${modeLabel(i18n, v.mode)}`}
                                  </Typography>
                                </Box>
                              ))}
                            </Box>
                          </TableCell>
                          <TableCell sx={{ whiteSpace: 'nowrap' }}>
                            {base ? t('policies.version', { version: base.version }) : '—'}
                            {pending > 0 && (
                              <Chip
                                size="small"
                                color="warning"
                                variant="outlined"
                                sx={{ ml: 1 }}
                                label={t('policies.pendingCount', { count: pending })}
                              />
                            )}
                          </TableCell>
                          <TableCell sx={{ whiteSpace: 'nowrap' }}>
                            {base ? statusLabel(i18n, base.status) : '—'}
                            {base?.inSnapshot && (
                              <Chip size="small" sx={{ ml: 1 }} label={t('policies.inSnapshot')} />
                            )}
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  </TableBody>
                </Table>
              </TableContainer>
            </Card>
          </Grid>
          <Grid item xs={12} lg={5}>
            {rule ? (
              <RuleDetail
                key={rule.ruleId}
                rule={rule}
                registry={data}
                onChanged={() => setGeneration((g) => g + 1)}
              />
            ) : (
              <Card variant="outlined">
                <CardContent>
                  <Empty>{t('policies.select')}</Empty>
                </CardContent>
              </Card>
            )}
          </Grid>
        </Grid>
      )}
    </Box>
  );
}

function RuleDetail({ rule, registry, onChanged }: { rule: Rule; registry: Registry; onChanged: () => void }) {
  const i18n = useI18n();
  const { t } = i18n;
  const { me } = useAuth();
  const canDraft = !!me && !me.masked && me.roles.includes('security_admin');
  const [withdrawing, setWithdrawing] = useState<number | null>(null);
  const [withdrawn, setWithdrawn] = useState<number | null>(null);
  // Q-41: drafts for different scopes may wait side by side; each has its own approval steps.
  const pendings = rule.versions.filter((v) => v.status === 'pending');
  const newestPending = pendings[0];
  return (
    <Box display="grid" gap={2}>
      <Card variant="outlined">
        <CardContent>
          <Typography variant="h6" component="h2" gutterBottom>
            {ruleName(i18n, rule)} · {t('policies.versions')}
          </Typography>
          {withdrawn !== null && (
            <Alert severity="success" sx={{ mb: 1 }} onClose={() => setWithdrawn(null)}>
              {t('policies.withdrawDone', { version: withdrawn })}
            </Alert>
          )}
          <Box component="ul" sx={{ m: 0, pl: 2.5, display: 'grid', gap: 0.5 }}>
            {rule.versions.map((v) => (
              <li key={v.version}>
                <Typography variant="body2" color={v.status === 'withdrawn' ? 'text.disabled' : undefined}>
                  <strong>{t('policies.version', { version: v.version })}</strong>{' '}
                  {isWithdrawalRequest(v)
                    ? t('policies.withdrawalLine', {
                        target: v.withdrawal?.withdrawsVersion ?? '—',
                        scope: scopeText(i18n, v.scope),
                        status: statusLabel(i18n, v.status),
                        reason: v.withdrawal?.reason ?? '—',
                      })
                    : t('policies.versionLine', {
                        action: valueOf(i18n, v),
                        mode: modeLabel(i18n, v.mode),
                        scope: scopeText(i18n, v.scope),
                        status: statusLabel(i18n, v.status),
                        reason: v.source === 'seed' ? t('policies.seedSource') : v.reasonCode,
                      })}
                  {v.rolloutStage !== 'all' && (
                    <Chip
                      size="small"
                      variant="outlined"
                      sx={{ ml: 1 }}
                      label={t('policies.legacyStage', { stage: stageLabel(i18n, v.rolloutStage) })}
                    />
                  )}
                  {v.inSnapshot && <Chip size="small" sx={{ ml: 1 }} label={t('policies.inSnapshot')} />}
                  {v.status === 'withdrawn' && v.withdrawal?.withdrawnBy && (
                    <>
                      <br />
                      {t('policies.withdrawnLine', {
                        time: i18n.fmt.time(v.withdrawal.withdrawnAt),
                        who: v.withdrawal.withdrawnBy,
                        reason: v.withdrawal.reason ?? '—',
                      })}
                    </>
                  )}
                  {canDraft &&
                    v.status === 'active' &&
                    v.scope.kind === 'GROUPS' &&
                    !isWithdrawalRequest(v) &&
                    withdrawing !== v.version && (
                      <Button
                        size="small"
                        color="warning"
                        sx={{ ml: 1 }}
                        onClick={() => {
                          setWithdrawn(null);
                          setWithdrawing(v.version);
                        }}
                      >
                        {t('policies.withdraw')}
                      </Button>
                    )}
                </Typography>
                {withdrawing === v.version && (
                  <WithdrawForm
                    version={v}
                    onCancel={() => setWithdrawing(null)}
                    onDone={(done) => {
                      setWithdrawing(null);
                      setWithdrawn(done);
                      onChanged();
                    }}
                  />
                )}
              </li>
            ))}
          </Box>
        </CardContent>
      </Card>
      {pendings.length === 0 ? (
        <ApprovalSteps version={undefined} onChanged={onChanged} />
      ) : (
        pendings.map((p) => <ApprovalSteps key={p.version} version={p} onChanged={onChanged} />)
      )}
      {rule.kind === 'class_action' && <SimulationPanel rule={rule} proposed={newestPending?.action ?? null} />}
      {canDraft && <DraftForm rule={rule} registry={registry} onChanged={onChanged} />}
    </Box>
  );
}

/**
 * PO decision Q-41: one security administrator withdraws an active group-scoped version, with a required reason and a
 * confirmation step in the page. It takes effect at once (no approvals): the groups follow everyone's rule from the next
 * snapshot; the version and its history stay.
 */
function WithdrawForm({
  version,
  onCancel,
  onDone,
}: {
  version: RuleVersion;
  onCancel: () => void;
  onDone: (withdrawnVersion: number) => void;
}) {
  const { t } = useI18n();
  const [reason, setReason] = useState('');
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const trimmed = reason.trim();
  const valid = trimmed.length > 0 && trimmed.length <= 500;

  async function send() {
    setBusy(true);
    setError(null);
    try {
      const done = await api.withdrawScope(version.ruleId, version.version, trimmed);
      onDone(done.version);
    } catch (e) {
      setError(e);
      setConfirming(false);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Box
      component="form"
      display="grid"
      gap={1}
      my={1}
      aria-label={t('policies.withdrawTitle', { version: version.version })}
      onSubmit={(e) => {
        e.preventDefault();
        if (valid) {
          setConfirming(true);
        }
      }}
    >
      <Typography variant="subtitle2" component="h3">
        {t('policies.withdrawTitle', { version: version.version })}
      </Typography>
      <TextField
        size="small"
        required
        label={t('policies.withdrawReason')}
        value={reason}
        disabled={confirming || busy}
        inputProps={{ maxLength: 500 }}
        onChange={(e) => setReason(e.target.value)}
        helperText={t('policies.withdrawHelp')}
      />
      {error !== null && <ErrorPanel error={error} />}
      {confirming ? (
        <Alert
          severity="warning"
          action={
            <Box display="flex" gap={1}>
              <Button color="warning" variant="contained" size="small" disabled={busy} onClick={() => void send()}>
                {t('policies.withdrawYes')}
              </Button>
              <Button size="small" disabled={busy} onClick={() => setConfirming(false)}>
                {t('policies.withdrawCancel')}
              </Button>
            </Box>
          }
        >
          {t('policies.withdrawConfirm', { version: version.version })}
        </Alert>
      ) : (
        <Box display="flex" gap={1}>
          <Button type="submit" variant="contained" color="warning" size="small" disabled={!valid}>
            {t('policies.withdrawContinue')}
          </Button>
          <Button size="small" onClick={onCancel}>
            {t('policies.withdrawCancel')}
          </Button>
        </Box>
      )}
    </Box>
  );
}

/** Draft → security administrator → privacy officer → active, for the version awaiting approval. */
function ApprovalSteps({ version, onChanged }: { version: RuleVersion | undefined; onChanged: () => void }) {
  const i18n = useI18n();
  const { t, fmt } = i18n;
  const { me } = useAuth();
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  if (!version) {
    return (
      <Card variant="outlined">
        <CardContent>
          <Typography variant="h6" component="h2" gutterBottom>
            {t('approval.title')}
          </Typography>
          <Typography color="text.secondary">{t('approval.none')}</Typography>
        </CardContent>
      </Card>
    );
  }
  const given = (role: ApproverRole) => version.approvals.find((a) => a.role === role);
  const activeStep = 1 + version.approvals.length;

  async function approve(role: ApproverRole) {
    if (!version) {
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await api.approve(version.ruleId, version.version, role);
      onChanged();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card variant="outlined">
      <CardContent>
        <Typography variant="h6" component="h2" gutterBottom>
          {t('approval.title')}
        </Typography>
        <Typography variant="body2" color="text.secondary" gutterBottom>
          {t('approval.forVersion', {
            version: version.version,
            action: valueOf(i18n, version),
            mode: modeLabel(i18n, version.mode),
            scope: scopeText(i18n, version.scope),
          })}
        </Typography>
        {error !== null && <ErrorPanel error={error} />}
        <Stepper activeStep={activeStep} orientation="vertical" aria-label={t('approval.title')}>
          <Step completed>
            <StepLabel optional={t('approval.by', { approver: version.author, time: fmt.time(version.createdAt) })}>
              {t('approval.draft')}
            </StepLabel>
          </Step>
          {APPROVER_ROLES.map((role) => {
            const a = given(role);
            const mine = !!me && !me.masked && me.roles.includes(role);
            return (
              <Step key={role} completed={!!a} expanded={!a}>
                <StepLabel
                  optional={a ? t('approval.by', { approver: a.approver, time: fmt.time(a.approvedAt) }) : undefined}
                >
                  {t(`approval.role.${role}`)}
                </StepLabel>
                <StepContent>
                  {mine ? (
                    <Button size="small" variant="contained" disabled={busy} onClick={() => void approve(role)}>
                      {t('approval.approve', { role: roleLabel(i18n, role) })}
                    </Button>
                  ) : (
                    <Typography variant="body2" color="text.secondary">
                      {t('approval.waiting')}
                    </Typography>
                  )}
                </StepContent>
              </Step>
            );
          })}
          <Step completed={false}>
            <StepLabel>{t('approval.active')}</StepLabel>
          </Step>
        </Stepper>
        <Typography variant="body2" color="text.secondary" mt={1}>
          {t('approval.twoPeople')}
        </Typography>
      </CardContent>
    </Card>
  );
}

/** The simulation stub: how the stored verdicts of the window would change under a proposed action (counts only). */
function SimulationPanel({ rule, proposed }: { rule: Rule; proposed: PolicyAction | null }) {
  const i18n = useI18n();
  const { t, fmt } = i18n;
  const [action, setAction] = useState<PolicyAction>(proposed ?? 'BLOCK');
  const [result, setResult] = useState<Simulation | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);

  async function run() {
    setBusy(true);
    setError(null);
    try {
      setResult(await api.simulate(rule.ruleId, action));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  const days = result
    ? Math.max(1, Math.round((new Date(result.to).getTime() - new Date(result.from).getTime()) / 86_400_000))
    : 0;
  return (
    <Card variant="outlined">
      <CardContent sx={{ display: 'grid', gap: 1.5 }}>
        <Typography variant="h6" component="h2">
          {t('simulation.title')}
        </Typography>
        <Box display="flex" gap={1.5} alignItems="center" flexWrap="wrap">
          <FormControl size="small" sx={{ minWidth: 160 }}>
            <InputLabel id="sim-action">{t('simulation.proposed')}</InputLabel>
            <Select
              labelId="sim-action"
              label={t('simulation.proposed')}
              value={action}
              onChange={(e) => setAction(e.target.value as PolicyAction)}
            >
              {(['ALLOW', 'WARN', 'REDACT', 'BLOCK'] as PolicyAction[]).map((a) => (
                <MenuItem key={a} value={a}>
                  {actionLabel(i18n, a)}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <Button variant="outlined" disabled={busy} onClick={() => void run()}>
            {t('simulation.run')}
          </Button>
        </Box>
        {error !== null && <ErrorPanel error={error} />}
        {result && (
          <Box display="grid" gap={0.75} aria-live="polite">
            <Typography variant="body2">
              {t('simulation.current', { action: result.currentAction ? actionLabel(i18n, result.currentAction) : '—' })}
            </Typography>
            <Typography variant="body2">
              {t('simulation.result', {
                days: fmt.count(days),
                inWindow: fmt.count(result.eventsInWindow),
                withClass: fmt.count(result.eventsWithClass),
                changed: fmt.count(result.eventsChanged),
              })}
            </Typography>
            {result.eventsNotReevaluated > 0 && (
              <Typography variant="body2" color="text.secondary">
                {t('simulation.notReevaluated', { count: fmt.count(result.eventsNotReevaluated) })}
              </Typography>
            )}
            {result.transitions.length === 0 ? (
              <Typography variant="body2" color="text.secondary">
                {t('simulation.noChange')}
              </Typography>
            ) : (
              <Box component="ul" aria-label={t('simulation.transitions')} sx={{ m: 0, pl: 2.5 }}>
                {result.transitions.map((tr) => (
                  <li key={`${tr.from}-${tr.to}`}>
                    <Typography variant="body2">
                      {t('simulation.transition', {
                        from: verdictLabel(i18n, tr.from),
                        to: verdictLabel(i18n, tr.to),
                        count: fmt.count(tr.events),
                      })}
                    </Typography>
                  </li>
                ))}
              </Box>
            )}
          </Box>
        )}
        <Typography variant="body2" color="text.secondary">
          {t('simulation.countsOnly')}
        </Typography>
      </CardContent>
    </Card>
  );
}

/** A new version of a class or flow rule (security_admin); it waits for two approvals before anything changes. */
function DraftForm({ rule, registry, onChanged }: { rule: Rule; registry: Registry; onChanged: () => void }) {
  const i18n = useI18n();
  const { t } = i18n;
  const actions = registry.actions.filter((a) => !(rule.failClosed && RELAXING.includes(a)));
  const [action, setAction] = useState<PolicyAction>(baseline(rule)?.action ?? actions[actions.length - 1] ?? 'BLOCK');
  const [mode, setMode] = useState<PolicyMode>('enforce');
  const [scope, setScope] = useState<Scope>({ kind: 'ANY', groups: [] });
  const [reasonCode, setReasonCode] = useState('');
  const [error, setError] = useState<unknown>(null);
  const [created, setCreated] = useState<number | null>(null);
  const reasonValid = /^[A-Z][A-Z0-9_]{2,63}$/.test(reasonCode);
  const scopeValid = scope.kind === 'ANY' || scope.groups.length > 0;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    const body: DraftRequest =
      rule.kind === 'flow'
        ? { enforceFailClosed: true, mode, scope: { kind: 'ANY', groups: [] }, reasonCode }
        : { action, mode, scope: scope.kind === 'ANY' ? { kind: 'ANY', groups: [] } : scope, reasonCode };
    try {
      const v = await api.draftVersion(rule.ruleId, body);
      setCreated(v.version);
      onChanged();
    } catch (err) {
      setError(err);
    }
  }

  return (
    <Card variant="outlined">
      <CardContent component="form" onSubmit={submit} sx={{ display: 'grid', gap: 1.5 }}>
        <Typography variant="h6" component="h2">
          {t('draft.title')}
        </Typography>
        {rule.failClosed && rule.kind === 'class_action' && (
          <Typography variant="body2" color="text.secondary">
            {t('draft.failClosedNote')}
          </Typography>
        )}
        <Box display="flex" gap={1.5} flexWrap="wrap">
          {rule.kind === 'class_action' && (
            <FormControl size="small" sx={{ minWidth: 140 }}>
              <InputLabel id="draft-action">{t('draft.action')}</InputLabel>
              <Select
                labelId="draft-action"
                label={t('draft.action')}
                value={action}
                onChange={(e) => setAction(e.target.value as PolicyAction)}
              >
                {actions.map((a) => (
                  <MenuItem key={a} value={a}>
                    {actionLabel(i18n, a)}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          )}
          <FormControl size="small" sx={{ minWidth: 140 }}>
            <InputLabel id="draft-mode">{t('draft.mode')}</InputLabel>
            <Select
              labelId="draft-mode"
              label={t('draft.mode')}
              value={mode}
              onChange={(e) => setMode(e.target.value as PolicyMode)}
            >
              {registry.modes.map((m) => (
                <MenuItem key={m} value={m}>
                  {modeLabel(i18n, m)}
                </MenuItem>
              ))}
            </Select>
          </FormControl>
          <TextField
            size="small"
            label={t('draft.reasonField')}
            value={reasonCode}
            onChange={(e) => setReasonCode(e.target.value.trim().toUpperCase())}
            helperText={t('draft.reasonHelp')}
            error={reasonCode !== '' && !reasonValid}
          />
        </Box>
        {rule.kind === 'class_action' && (
          <ScopePicker scope={scope} max={registry.maxScopeGroups} onChange={setScope} />
        )}
        {error !== null && <ErrorPanel error={error} />}
        {created !== null && <Alert severity="success">{t('draft.created', { version: created })}</Alert>}
        <Box>
          <Button type="submit" variant="contained" disabled={!reasonValid || !scopeValid}>
            {t('draft.submit')}
          </Button>
        </Box>
      </CardContent>
    </Card>
  );
}

/**
 * The scope picker of a new class-rule version (PO decision Q-39): everyone, or the members of directory groups typed
 * by the operator (chips; 1 to `max`; a name typed twice, ignoring case, is added once). Group names stay in this form
 * and the request; they are never written to the browser's storage.
 */
export function ScopePicker({ scope, max, onChange }: { scope: Scope; max: number; onChange: (s: Scope) => void }) {
  const { t } = useI18n();
  const [entry, setEntry] = useState('');
  const full = scope.groups.length >= max;
  const comma = entry.includes(',');

  function add() {
    const name = entry.trim();
    if (!name || full || comma) {
      return;
    }
    if (!scope.groups.some((g) => foldGroupName(g) === foldGroupName(name))) {
      onChange({ kind: 'GROUPS', groups: [...scope.groups, name] });
    }
    setEntry('');
  }

  return (
    <Box display="grid" gap={1}>
      <FormControl>
        <FormLabel id="draft-scope">{t('draft.scope')}</FormLabel>
        <RadioGroup
          row
          aria-labelledby="draft-scope"
          value={scope.kind}
          onChange={(e) => onChange({ kind: e.target.value as ScopeKind, groups: scope.groups })}
        >
          <FormControlLabel value="ANY" control={<Radio size="small" />} label={t('draft.scopeEveryone')} />
          <FormControlLabel value="GROUPS" control={<Radio size="small" />} label={t('draft.scopeGroups')} />
        </RadioGroup>
      </FormControl>
      {scope.kind === 'GROUPS' && (
        <Box display="grid" gap={1}>
          <Box display="flex" gap={1} alignItems="flex-start" flexWrap="wrap">
            <TextField
              size="small"
              label={t('draft.groupField')}
              value={entry}
              inputProps={{ maxLength: 256 }}
              onChange={(e) => setEntry(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  e.preventDefault();
                  add();
                }
              }}
              helperText={
                full ? t('draft.groupLimit', { max }) : comma ? t('draft.groupComma') : t('draft.groupHelp', { max })
              }
              error={comma}
              disabled={full}
            />
            <Button variant="outlined" onClick={add} disabled={full || comma || entry.trim() === ''}>
              {t('draft.groupAdd')}
            </Button>
          </Box>
          {scope.groups.length === 0 ? (
            <Typography variant="body2" color="warning.main">
              {t('draft.groupsNeeded')}
            </Typography>
          ) : (
            <Box display="flex" gap={0.5} flexWrap="wrap" aria-label={t('scope.groupsAria')}>
              {scope.groups.map((g) => (
                <Chip
                  key={g}
                  size="small"
                  label={g}
                  onDelete={() => onChange({ kind: 'GROUPS', groups: scope.groups.filter((x) => x !== g) })}
                  deleteIcon={
                    <Box component="span" role="button" aria-label={t('draft.groupRemove', { group: g })}>
                      ×
                    </Box>
                  }
                />
              ))}
            </Box>
          )}
          <Typography variant="body2" color="text.secondary">
            {t('draft.scopeNote')}
          </Typography>
        </Box>
      )}
    </Box>
  );
}
