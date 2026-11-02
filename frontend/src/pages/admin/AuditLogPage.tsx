import {
  Box,
  Button,
  FormControl,
  InputLabel,
  MenuItem,
  Select,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material';
import { useEffect, useState } from 'react';
import { type AuditEntry, api } from '../../api';
import { Empty, ErrorPanel, Loading } from '../../components/StatePanel';
import { type I18n, useI18n } from '../../i18n';

/** The audit log's time ranges; the server allows up to 366 days. */
export const AUDIT_WINDOWS = [
  { id: '24h', hours: 24 },
  { id: '7d', hours: 24 * 7 },
  { id: '30d', hours: 24 * 30 },
  { id: '90d', hours: 24 * 90 },
  { id: '365d', hours: 24 * 365 },
] as const;
export type AuditWindow = (typeof AUDIT_WINDOWS)[number]['id'];

/** The ledger's actor shapes: a `USR-` code name or a `system:` actor; the server refuses any other filter. */
export const ACTOR_PATTERN = /^(USR-[0-9a-f]{10}|system:[a-z_-]{1,32})$/;
const PAGE = 50;

function range(id: AuditWindow): { from: string; to: string } {
  const hours = AUDIT_WINDOWS.find((w) => w.id === id)?.hours ?? 24 * 30;
  const to = new Date(Math.ceil(Date.now() / 60_000) * 60_000);
  return { from: new Date(to.getTime() - hours * 3_600_000).toISOString(), to: to.toISOString() };
}

function operationLabel(i: I18n, op: string): string {
  return i.label(`audit.operation.${op}`, op);
}

/**
 * Records -> Audit log (PO decision Q-47 decision 1.3): the ledger, newest first, read only, filtered by time range,
 * action and actor (a code name only). The server shows each row as the SIEM export does; this page never receives a
 * name, an address or a body.
 */
export function AuditLogPage() {
  const i18n = useI18n();
  const { t, fmt } = i18n;
  const [win, setWin] = useState<AuditWindow>('30d');
  const [action, setAction] = useState('');
  const [actor, setActor] = useState('');
  const [actorDraft, setActorDraft] = useState('');
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [actions, setActions] = useState<string[]>([]);
  const [cursor, setCursor] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [span, setSpan] = useState(() => range('30d'));

  useEffect(() => {
    let live = true;
    setLoading(true);
    setError(null);
    api
      .adminAudit({ ...span, action, actor, limit: PAGE })
      .then((p) => {
        if (live) {
          setEntries(p.entries);
          setActions(p.actions);
          setCursor(p.nextCursor);
        }
      })
      .catch((e) => live && setError(e))
      .finally(() => live && setLoading(false));
    return () => {
      live = false;
    };
  }, [span, action, actor]);

  async function more() {
    setLoading(true);
    try {
      const p = await api.adminAudit({ ...span, action, actor, limit: PAGE, cursor });
      setEntries((prev) => [...prev, ...p.entries]);
      setCursor(p.nextCursor);
    } catch (e) {
      setError(e);
    } finally {
      setLoading(false);
    }
  }

  const actorValid = actorDraft === '' || ACTOR_PATTERN.test(actorDraft);
  const applyActor = () => actorValid && setActor(actorDraft);

  return (
    <Box display="grid" gap={2}>
      <Typography variant="body2" color="text.secondary">
        {t('audit.note')}
      </Typography>
      <Box display="flex" flexWrap="wrap" gap={1.5} alignItems="flex-start" role="search" aria-label={t('audit.filters')}>
        <FormControl size="small" sx={{ minWidth: 160 }}>
          <InputLabel id="a-window">{t('audit.window')}</InputLabel>
          <Select
            labelId="a-window"
            label={t('audit.window')}
            value={win}
            onChange={(e) => {
              const next = e.target.value as AuditWindow;
              setWin(next);
              setSpan(range(next));
            }}
          >
            {AUDIT_WINDOWS.map((w) => (
              <MenuItem key={w.id} value={w.id}>
                {t(`audit.window.${w.id}`)}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <FormControl size="small" sx={{ minWidth: 220 }}>
          <InputLabel id="a-action">{t('audit.action')}</InputLabel>
          <Select labelId="a-action" label={t('audit.action')} value={action} onChange={(e) => setAction(e.target.value)}>
            <MenuItem value="">{t('audit.allActions')}</MenuItem>
            {(actions.includes(action) || action === '' ? actions : [action, ...actions]).map((a) => (
              <MenuItem key={a} value={a} sx={{ fontFamily: 'monospace' }}>
                {a}
              </MenuItem>
            ))}
          </Select>
        </FormControl>
        <Box
          component="form"
          onSubmit={(e: React.FormEvent) => {
            e.preventDefault();
            applyActor();
          }}
        >
          <TextField
            size="small"
            label={t('audit.actor')}
            placeholder="USR-0123456789"
            value={actorDraft}
            onChange={(e) => setActorDraft(e.target.value.trim())}
            onBlur={applyActor}
            error={!actorValid}
            helperText={actorValid ? t('audit.actorHelp') : t('audit.actorInvalid')}
            inputProps={{ 'aria-label': t('audit.actor') }}
          />
        </Box>
      </Box>
      {error !== null && <ErrorPanel error={error} />}
      {loading && entries.length === 0 && <Loading />}
      {!loading && error === null && entries.length === 0 && <Empty>{t('audit.none')}</Empty>}
      {entries.length > 0 && (
        <TableContainer>
          <Table size="small" aria-label={t('audit.table')}>
            <TableHead>
              <TableRow>
                <TableCell>{t('audit.time')}</TableCell>
                <TableCell>{t('audit.who')}</TableCell>
                <TableCell>{t('audit.what')}</TableCell>
                <TableCell>{t('audit.target')}</TableCell>
                <TableCell>{t('audit.operation')}</TableCell>
                <TableCell>{t('audit.reason')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {entries.map((e) => (
                <TableRow key={e.id}>
                  <TableCell sx={{ whiteSpace: 'nowrap' }}>{fmt.time(e.occurredAt)}</TableCell>
                  <TableCell sx={{ fontFamily: 'monospace' }}>{e.actor}</TableCell>
                  <TableCell sx={{ fontFamily: 'monospace' }}>{e.action}</TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                      {e.table}
                    </Typography>
                    {e.rowKey && (
                      <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                        {e.rowKey}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell>{operationLabel(i18n, e.operation)}</TableCell>
                  <TableCell sx={{ maxWidth: 360, overflowWrap: 'anywhere' }}>{e.reason ?? '—'}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
      {cursor && (
        <Box>
          <Button onClick={more} disabled={loading}>
            {t('audit.more')}
          </Button>
        </Box>
      )}
    </Box>
  );
}
