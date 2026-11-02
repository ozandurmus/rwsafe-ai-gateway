import {
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
import { type JobItem, api } from '../../api';
import { ErrorPanel, Loading } from '../../components/StatePanel';
import { type I18n, useI18n } from '../../i18n';
import { useApi } from '../../useApi';

/** "Every 5 minutes" from seconds; whole hours, minutes or seconds. */
export function everyLabel(i: I18n, seconds: number): string {
  const duration =
    seconds % 3600 === 0
      ? i.t('jobs.hours', { n: seconds / 3600 })
      : seconds % 60 === 0
        ? i.t('jobs.minutes', { n: seconds / 60 })
        : i.t('jobs.seconds', { n: seconds });
  return i.t('jobs.every', { duration });
}

export function scheduleLabel(i: I18n, job: JobItem): string {
  switch (job.kind) {
    case 'FIXED_DELAY':
      return job.delaySeconds === null ? '—' : everyLabel(i, job.delaySeconds);
    case 'CRON':
      return i.label(`jobs.schedule.${job.id}`, i.t('jobs.cron', { cron: job.cron ?? '', zone: job.zone ?? '' }));
    default:
      return i.t('jobs.continuous');
  }
}

/** Good, failed, in progress or waiting: the state's colour always comes with its words. */
function stateColor(state: string): 'success' | 'error' | 'warning' | 'default' | 'info' {
  switch (state) {
    case 'OK':
    case 'UP':
      return 'success';
    case 'FAILED':
    case 'DOWN':
      return 'error';
    case 'DEGRADED':
      return 'warning';
    case 'RUNNING':
      return 'info';
    default:
      return 'default';
  }
}

function countsLabel(i: I18n, counts: Record<string, number>): string {
  const entries = Object.entries(counts);
  if (entries.length === 0) {
    return '—';
  }
  return entries.map(([k, v]) => `${i.label(`jobs.count.${k}`, k)}: ${i.fmt.count(v)}`).join(' · ');
}

/**
 * Records -> Job log (PO decision Q-47 decision 1.3): every job the server runs on its own, its schedule, how its last
 * run went, what it counted and when it runs next. Runs live in the server's memory, so the log covers the time since
 * the server last started; the SIEM export runs all the time and shows its health instead of runs.
 */
export function JobLogPage() {
  const i18n = useI18n();
  const { t, fmt } = i18n;
  const [generation, setGeneration] = useState(0);
  const { data, error, loading } = useApi(() => api.adminJobs(), `admin-jobs:${generation}`);

  return (
    <Box display="grid" gap={2}>
      <Box display="flex" justifyContent="space-between" alignItems="center" gap={2} flexWrap="wrap">
        <Box>
          {data && <Typography>{t('admin.since', { time: fmt.time(data.since) })}</Typography>}
          <Typography variant="body2" color="text.secondary">
            {t('jobs.note')}
          </Typography>
        </Box>
        <Button onClick={() => setGeneration((g) => g + 1)}>{t('admin.refresh')}</Button>
      </Box>
      {loading && !data && <Loading />}
      {error !== null && <ErrorPanel error={error} />}
      {data && (
        <TableContainer>
          <Table size="small" aria-label={t('jobs.table')}>
            <TableHead>
              <TableRow>
                <TableCell>{t('jobs.job')}</TableCell>
                <TableCell>{t('jobs.schedule')}</TableCell>
                <TableCell>{t('jobs.state')}</TableCell>
                <TableCell>{t('jobs.lastRun')}</TableCell>
                <TableCell>{t('jobs.summary')}</TableCell>
                <TableCell>{t('jobs.nextRun')}</TableCell>
                <TableCell align="right">{t('jobs.runs')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data.jobs.map((j) => (
                <TableRow key={j.id}>
                  <TableCell>
                    <Typography variant="body2">{i18n.label(`jobs.name.${j.id}`, j.id)}</Typography>
                    <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                      {j.id}
                    </Typography>
                  </TableCell>
                  <TableCell>{scheduleLabel(i18n, j)}</TableCell>
                  <TableCell>
                    <Chip size="small" color={stateColor(j.state)} label={i18n.label(`jobs.state.${j.state}`, j.state)} />
                    {j.failure && (
                      <Typography variant="caption" display="block" sx={{ fontFamily: 'monospace' }}>
                        {j.failure}
                      </Typography>
                    )}
                  </TableCell>
                  <TableCell sx={{ whiteSpace: 'nowrap' }}>
                    {j.kind === 'CONTINUOUS'
                      ? j.lastEndedAt
                        ? t('jobs.lastDelivery', { time: fmt.time(j.lastEndedAt) })
                        : '—'
                      : fmt.time(j.lastStartedAt)}
                  </TableCell>
                  <TableCell sx={{ maxWidth: 340 }}>{countsLabel(i18n, j.counts)}</TableCell>
                  <TableCell sx={{ whiteSpace: 'nowrap' }}>{fmt.time(j.nextRunAt)}</TableCell>
                  <TableCell align="right">
                    {j.kind === 'CONTINUOUS' ? '—' : `${fmt.count(j.runs)} (${fmt.count(j.failures)})`}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
    </Box>
  );
}
