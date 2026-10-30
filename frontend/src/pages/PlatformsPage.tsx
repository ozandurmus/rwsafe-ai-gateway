import {
  Alert,
  Box,
  Button,
  Card,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material';
import { Fragment, useState } from 'react';
import { api, type Rule, type RuleVersion } from '../api';
import { useAuth } from '../auth';
import { Empty, ErrorPanel, Loading } from '../components/StatePanel';
import { useI18n } from '../i18n';
import { modeLabel, platformLabel, statusLabel } from '../labels';
import { useApi } from '../useApi';
import { baseline } from './PoliciesPage';

const RETIRE_REASON_MAX = 500;

function Hosts({ hosts }: { hosts: string[] | null }) {
  if (!hosts || hosts.length === 0) {
    return <>—</>;
  }
  return (
    <Box component="ul" sx={{ m: 0, p: 0, listStyle: 'none', fontFamily: 'monospace', fontSize: 13 }}>
      {hosts.map((h) => (
        <li key={h}>{h}</li>
      ))}
    </Box>
  );
}

/** The row a platform shows: its active version, else its newest retired one, else its newest version. */
export function shownVersion(rule: Rule): RuleVersion | undefined {
  return baseline(rule) ?? rule.versions.find((v) => v.status === 'retired') ?? rule.versions[0];
}

/**
 * Platforms: the registry's platform rows as the data plane receives them (vendor-published endpoints only). A security
 * administrator may retire an active row with a reason (PO decision Q-40): a two-step form inside the row, then the
 * row stays listed, greyed, with its reason.
 */
export function PlatformsPage() {
  const i18n = useI18n();
  const { t } = i18n;
  const { me } = useAuth();
  const [generation, setGeneration] = useState(0);
  const { data, error, loading } = useApi(() => api.policyRules(), `platform-rules:${generation}`);
  const [retiring, setRetiring] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const canRetire = !!me && !me.masked && me.roles.includes('security_admin');
  const rows = (data?.rules ?? []).filter((r) => r.kind === 'platform');
  const columns = canRetire ? 7 : 6;
  return (
    <Box display="grid" gap={2}>
      <Typography variant="h5" component="h1" sx={{ fontWeight: 600 }}>
        {t('platforms.title')}
      </Typography>
      <Typography color="text.secondary">{t('platforms.note')}</Typography>
      {error !== null && <ErrorPanel error={error} />}
      {done !== null && (
        <Alert severity="success" onClose={() => setDone(null)}>
          {t('platforms.retireDone', { platform: done })}
        </Alert>
      )}
      {loading && !data && <Loading />}
      {data && (
        <Card variant="outlined">
          <TableContainer>
            <Table size="small" aria-label={t('platforms.table')}>
              <TableHead>
                <TableRow>
                  <TableCell>{t('platforms.col.platform')}</TableCell>
                  <TableCell>{t('platforms.col.hosts')}</TableCell>
                  <TableCell>{t('platforms.col.api')}</TableCell>
                  <TableCell>{t('platforms.col.login')}</TableCell>
                  <TableCell>{t('platforms.col.version')}</TableCell>
                  <TableCell>{t('platforms.col.status')}</TableCell>
                  {canRetire && <TableCell>{t('platforms.col.actions')}</TableCell>}
                </TableRow>
              </TableHead>
              <TableBody>
                {rows.map((r) => {
                  const v = shownVersion(r);
                  const retired = v?.status === 'retired';
                  const pending = r.versions.filter((x) => x.status === 'pending').length;
                  const name = platformLabel(i18n, r.subject);
                  return (
                    <Fragment key={r.ruleId}>
                      <TableRow
                        data-retired={retired ? 'true' : undefined}
                        sx={retired ? { '& td': { color: 'text.disabled' }, bgcolor: 'action.hover' } : undefined}
                      >
                        <TableCell>
                          <Typography variant="body2" sx={{ fontWeight: 600 }} color="inherit">
                            {name}
                          </Typography>
                          <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                            {r.subject}
                          </Typography>
                        </TableCell>
                        <TableCell>
                          <Hosts hosts={v?.hostSuffixes ?? null} />
                        </TableCell>
                        <TableCell>
                          <Hosts hosts={v?.apiHosts ?? null} />
                        </TableCell>
                        <TableCell>
                          <Hosts hosts={v?.loginHosts ?? null} />
                        </TableCell>
                        <TableCell sx={{ whiteSpace: 'nowrap' }}>
                          {v ? `${t('policies.version', { version: v.version })} · ${modeLabel(i18n, v.mode)}` : '—'}
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
                        <TableCell>
                          <Box sx={{ whiteSpace: 'nowrap' }}>
                            {v ? statusLabel(i18n, v.status) : '—'}
                            {v?.inSnapshot && !retired && (
                              <Chip size="small" sx={{ ml: 1 }} label={t('policies.inSnapshot')} />
                            )}
                          </Box>
                          {retired && v?.retirement && (
                            <Typography variant="caption" component="p" color="text.secondary" sx={{ maxWidth: 320 }}>
                              {t('platforms.retired', {
                                time: i18n.fmt.time(v.retirement.retiredAt),
                                who: v.retirement.retiredBy,
                                reason: v.retirement.reason,
                              })}
                            </Typography>
                          )}
                        </TableCell>
                        {canRetire && (
                          <TableCell>
                            {v?.status === 'active' && retiring !== r.ruleId && (
                              <Button
                                size="small"
                                color="error"
                                variant="outlined"
                                onClick={() => {
                                  setDone(null);
                                  setRetiring(r.ruleId);
                                }}
                              >
                                {t('platforms.retire')}
                              </Button>
                            )}
                          </TableCell>
                        )}
                      </TableRow>
                      {canRetire && retiring === r.ruleId && (
                        <TableRow>
                          <TableCell colSpan={columns}>
                            <RetireForm
                              ruleId={r.ruleId}
                              platform={name}
                              onCancel={() => setRetiring(null)}
                              onRetired={() => {
                                setRetiring(null);
                                setDone(name);
                                setGeneration((g) => g + 1);
                              }}
                            />
                          </TableCell>
                        </TableRow>
                      )}
                    </Fragment>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
          {rows.length === 0 && (
            <Box px={2}>
              <Empty>{t('platforms.empty')}</Empty>
            </Box>
          )}
        </Card>
      )}
    </Box>
  );
}

/** Step 1: the required reason. Step 2: the consequences and the confirmation. The server's reason on a refusal. */
function RetireForm({
  ruleId,
  platform,
  onCancel,
  onRetired,
}: {
  ruleId: string;
  platform: string;
  onCancel: () => void;
  onRetired: () => void;
}) {
  const { t } = useI18n();
  const [reason, setReason] = useState('');
  const [confirming, setConfirming] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const trimmed = reason.trim();
  const valid = trimmed.length > 0 && trimmed.length <= RETIRE_REASON_MAX;

  async function retire() {
    setBusy(true);
    setError(null);
    try {
      await api.retirePlatform(ruleId, trimmed);
      onRetired();
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
      gap={1.5}
      py={1}
      aria-label={t('platforms.retireTitle', { platform })}
      onSubmit={(e) => {
        e.preventDefault();
        if (valid) {
          setConfirming(true);
        }
      }}
    >
      <Typography variant="subtitle2" component="h2">
        {t('platforms.retireTitle', { platform })}
      </Typography>
      <TextField
        size="small"
        required
        label={t('platforms.retireReason')}
        value={reason}
        disabled={confirming || busy}
        inputProps={{ maxLength: RETIRE_REASON_MAX }}
        onChange={(e) => setReason(e.target.value)}
        helperText={t('platforms.retireReasonHelp')}
        sx={{ maxWidth: 560 }}
      />
      {error !== null && <ErrorPanel error={error} />}
      {confirming ? (
        <Alert
          severity="warning"
          action={
            <Box display="flex" gap={1}>
              <Button color="error" variant="contained" size="small" disabled={busy} onClick={() => void retire()}>
                {t('platforms.retireYes')}
              </Button>
              <Button size="small" disabled={busy} onClick={() => setConfirming(false)}>
                {t('platforms.cancel')}
              </Button>
            </Box>
          }
        >
          {t('platforms.retireConfirm', { platform })}
        </Alert>
      ) : (
        <Box display="flex" gap={1}>
          <Button type="submit" variant="contained" color="error" size="small" disabled={!valid}>
            {t('platforms.retireContinue')}
          </Button>
          <Button size="small" onClick={onCancel}>
            {t('platforms.cancel')}
          </Button>
        </Box>
      )}
    </Box>
  );
}
