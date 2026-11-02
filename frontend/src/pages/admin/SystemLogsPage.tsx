import {
  Alert,
  Box,
  Button,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material';
import { useState } from 'react';
import { api } from '../../api';
import { Empty, ErrorPanel, Loading } from '../../components/StatePanel';
import { type I18n, useI18n } from '../../i18n';
import { useApi } from '../../useApi';

function levelLabel(i: I18n, level: string): string {
  return i.label(`logs.level.${level}`, level);
}

function levelColor(level: string): 'error' | 'warning' | 'default' {
  return level === 'ERROR' ? 'error' : level === 'WARN' ? 'warning' : 'default';
}

/**
 * Platform -> System logs (PO decision Q-47 decision 1.4; AGENTS.md 4.14): how often each part of the server wrote at
 * each level, and its latest warnings and errors as the part, the error kind and a fixed message text. The server never
 * sends a message's content, a value or a request body.
 */
export function SystemLogsPage() {
  const i18n = useI18n();
  const { t, fmt } = i18n;
  const [generation, setGeneration] = useState(0);
  const { data, error, loading } = useApi(() => api.adminLogs(), `admin-logs:${generation}`);

  return (
    <Box display="grid" gap={2}>
      <Box display="flex" justifyContent="space-between" alignItems="center" gap={2} flexWrap="wrap">
        <Box>
          {data && <Typography>{t('admin.since', { time: fmt.time(data.since) })}</Typography>}
          <Typography variant="body2" color="text.secondary">
            {t('logs.note')}
          </Typography>
        </Box>
        <Button onClick={() => setGeneration((g) => g + 1)}>{t('admin.refresh')}</Button>
      </Box>
      {loading && !data && <Loading />}
      {error !== null && <ErrorPanel error={error} />}
      {data && !data.capturing && <Alert severity="warning">{t('logs.notCapturing')}</Alert>}
      {data && (
        <>
          <Typography variant="subtitle1" component="h3" sx={{ fontWeight: 600 }}>
            {t('logs.recent')}
          </Typography>
          {data.recent.length === 0 ? (
            <Empty>{t('logs.noRecent')}</Empty>
          ) : (
            <TableContainer>
              <Table size="small" aria-label={t('logs.recent')}>
                <TableHead>
                  <TableRow>
                    <TableCell>{t('logs.time')}</TableCell>
                    <TableCell>{t('logs.level')}</TableCell>
                    <TableCell>{t('logs.logger')}</TableCell>
                    <TableCell>{t('logs.exception')}</TableCell>
                    <TableCell>{t('logs.template')}</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {data.recent.map((e, n) => (
                    <TableRow key={`${e.at}-${n}`}>
                      <TableCell sx={{ whiteSpace: 'nowrap' }}>{fmt.time(e.at)}</TableCell>
                      <TableCell>
                        <Chip size="small" color={levelColor(e.level)} label={levelLabel(i18n, e.level)} />
                      </TableCell>
                      <TableCell sx={{ fontFamily: 'monospace' }}>{e.logger}</TableCell>
                      <TableCell sx={{ fontFamily: 'monospace' }}>{e.exceptionClass ?? '—'}</TableCell>
                      <TableCell sx={{ fontFamily: e.template ? 'monospace' : undefined }}>
                        {e.template ?? (
                          <Typography component="span" variant="body2" color="text.secondary">
                            {t('admin.notShown')}
                          </Typography>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
          <Typography variant="subtitle1" component="h3" sx={{ fontWeight: 600 }}>
            {t('logs.counts', { hours: data.windowHours })}
          </Typography>
          {data.counts.length === 0 ? (
            <Empty>{t('logs.none')}</Empty>
          ) : (
            <TableContainer>
              <Table size="small" aria-label={t('logs.counts', { hours: data.windowHours })}>
                <TableHead>
                  <TableRow>
                    <TableCell>{t('logs.level')}</TableCell>
                    <TableCell>{t('logs.logger')}</TableCell>
                    <TableCell>{t('logs.origin')}</TableCell>
                    <TableCell align="right">{t('logs.count')}</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {data.counts.map((c) => (
                    <TableRow key={`${c.level}-${c.logger}-${c.own}`}>
                      <TableCell>
                        <Chip size="small" color={levelColor(c.level)} label={levelLabel(i18n, c.level)} />
                      </TableCell>
                      <TableCell sx={{ fontFamily: 'monospace' }}>{c.logger}</TableCell>
                      <TableCell>{c.own ? t('logs.own') : t('logs.library')}</TableCell>
                      <TableCell align="right">{fmt.count(c.count)}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </>
      )}
    </Box>
  );
}
