import {
  Box,
  Button,
  Chip,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material';
import { useState } from 'react';
import { type SessionView, api } from '../../api';
import { ReasonDialog } from '../../components/ReasonDialog';
import { Empty, ErrorPanel, Loading } from '../../components/StatePanel';
import { type I18n, useI18n } from '../../i18n';
import { roleLabel } from '../../labels';
import { useApi } from '../../useApi';

export function sourceLabel(i: I18n, source: string | null): string {
  return source ? i.label(`source.code_${source}`, source) : '—';
}

/**
 * Sessions (PO decision Q-47): who is signed in now, from which source, since when and their last request. The server
 * never sends a client address or a session id; a session is named by a random handle. Ending one takes a reason and
 * signs the user out at their next request; one's own session is ended by signing out.
 */
export function SessionsPage() {
  const i18n = useI18n();
  const { t, fmt } = i18n;
  const [generation, setGeneration] = useState(0);
  const { data, error, loading } = useApi(() => api.adminSessions(), `admin-sessions:${generation}`);
  const [ending, setEnding] = useState<SessionView | null>(null);
  const reload = () => setGeneration((g) => g + 1);

  return (
    <Box display="grid" gap={2}>
      <Box display="flex" justifyContent="space-between" alignItems="center" gap={2} flexWrap="wrap">
        <Typography color="text.secondary">{t('sessions.instanceNote')}</Typography>
        <Button onClick={reload}>{t('admin.refresh')}</Button>
      </Box>
      {loading && !data && <Loading />}
      {error !== null && <ErrorPanel error={error} />}
      {data && data.sessions.length === 0 && <Empty>{t('sessions.none')}</Empty>}
      {data && data.sessions.length > 0 && (
        <TableContainer>
          <Table size="small" aria-label={t('sessions.table')}>
            <TableHead>
              <TableRow>
                <TableCell>{t('sessions.user')}</TableCell>
                <TableCell>{t('sessions.source')}</TableCell>
                <TableCell>{t('users.roles')}</TableCell>
                <TableCell>{t('sessions.signedIn')}</TableCell>
                <TableCell>{t('sessions.lastActivity')}</TableCell>
                <TableCell>{t('sessions.state')}</TableCell>
                <TableCell>{t('users.actions')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data.sessions.map((s) => (
                <TableRow key={s.handle} selected={s.current}>
                  <TableCell sx={{ fontFamily: 'monospace' }}>{s.loginName}</TableCell>
                  <TableCell>{sourceLabel(i18n, s.source)}</TableCell>
                  <TableCell>
                    <Stack direction="row" gap={0.5} flexWrap="wrap">
                      {s.roles.map((r) => (
                        <Chip key={r} size="small" label={roleLabel(i18n, r)} />
                      ))}
                    </Stack>
                  </TableCell>
                  <TableCell>{fmt.time(s.signedInAt)}</TableCell>
                  <TableCell>{fmt.time(s.lastActivity)}</TableCell>
                  <TableCell>
                    {s.current
                      ? t('sessions.current')
                      : s.passwordChangePending
                        ? t('sessions.pending')
                        : t('sessions.active')}
                  </TableCell>
                  <TableCell>
                    {!s.current && (
                      <Button size="small" color="error" onClick={() => setEnding(s)}>
                        {t('sessions.end')}
                      </Button>
                    )}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
      {ending && (
        <ReasonDialog
          open
          title={t('sessions.endTitle', { user: ending.loginName })}
          hint={t('sessions.endHint')}
          confirm={t('sessions.end')}
          danger
          onClose={() => setEnding(null)}
          onSubmit={async (reason) => {
            await api.endSession(ending.handle, reason);
            setEnding(null);
            reload();
          }}
        />
      )}
    </Box>
  );
}
