import { Box, Card, CardContent, Grid, ToggleButton, ToggleButtonGroup, Typography, useTheme } from '@mui/material';
import { useState } from 'react';
import { api, type Overview } from '../api';
import { BarList } from '../components/BarList';
import { HourlyChart } from '../components/HourlyChart';
import { KpiCard } from '../components/KpiCard';
import { Empty, ErrorPanel, Loading } from '../components/StatePanel';
import {
  GROUP_LABEL,
  GROUP_ORDER,
  VERDICT_GROUP,
  type VerdictGroup,
  dataClassLabel,
  formatCount,
  groupColor,
  platformLabel,
} from '../labels';
import { WINDOWS, type WindowId, useApi, windowRange } from '../useApi';

function share(part: number, total: number): string {
  return total === 0 ? '0 %' : `${((part / total) * 100).toFixed(1)} %`;
}

export function groupTotals(o: Overview): Record<VerdictGroup, number> {
  const t: Record<VerdictGroup, number> = { allowed: 0, warned: 0, redacted: 0, blocked: 0, notInspected: 0 };
  for (const v of o.verdicts) {
    t[VERDICT_GROUP[v.verdict]] += v.count;
  }
  return t;
}

/** Overview: headline counts, verdict mix, events per platform, events per hour and DLP finding classes. */
export function OverviewPage() {
  const theme = useTheme();
  const [win, setWin] = useState<WindowId>('24h');
  const range = windowRange(win);
  const { data, error, loading } = useApi(() => api.overview(range.from, range.to), `${win}:${range.to}`);
  const seriesBlue = theme.palette.mode === 'light' ? '#2a78d6' : '#3987e5';

  return (
    <Box display="grid" gap={2}>
      <Box display="flex" flexWrap="wrap" alignItems="center" justifyContent="space-between" gap={1}>
        <Typography variant="h5" component="h1" sx={{ fontWeight: 600 }}>
          Overview
        </Typography>
        <ToggleButtonGroup size="small" exclusive value={win} onChange={(_, v) => v && setWin(v)} aria-label="Window">
          {WINDOWS.map((w) => (
            <ToggleButton key={w.id} value={w.id}>
              {w.label}
            </ToggleButton>
          ))}
        </ToggleButtonGroup>
      </Box>
      {error !== null && <ErrorPanel error={error} />}
      {loading && !data && <Loading />}
      {data && <OverviewBody data={data} seriesBlue={seriesBlue} />}
    </Box>
  );
}

function OverviewBody({ data, seriesBlue }: { data: Overview; seriesBlue: string }) {
  const theme = useTheme();
  const groups = groupTotals(data);
  const findingEvents = data.findings.reduce((s, f) => s + f.events, 0);
  return (
    <>
      <Grid container spacing={2}>
        <Grid item xs={12} sm={6} md={3}>
          <KpiCard label="Inspected transactions" value={formatCount(data.total)} detail="REQMOD and RESPMOD" />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <KpiCard label="Redacted" value={formatCount(groups.redacted)} detail={`${share(groups.redacted, data.total)} of all`} />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <KpiCard label="Blocked" value={formatCount(groups.blocked)} detail={`${share(groups.blocked, data.total)} of all`} />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <KpiCard
            label="Not inspected"
            value={formatCount(groups.notInspected)}
            detail="uninspectable, malformed, failed, timed out, unknown flow"
          />
        </Grid>
      </Grid>
      <Card variant="outlined">
        <CardContent>
          <Typography variant="h6" component="h2" gutterBottom>
            Events per hour
          </Typography>
          {data.total === 0 ? <Empty>No events in this window.</Empty> : <HourlyChart overview={data} />}
        </CardContent>
      </Card>
      <Grid container spacing={2}>
        <Grid item xs={12} md={4}>
          <Card variant="outlined" sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="h6" component="h2" gutterBottom>
                Verdict mix
              </Typography>
              <BarList
                ariaLabel="Verdict mix"
                rows={GROUP_ORDER.map((g) => ({
                  key: g,
                  label: GROUP_LABEL[g],
                  value: groups[g],
                  color: groupColor(g, theme.palette.mode),
                  detail: share(groups[g], data.total),
                }))}
              />
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={5}>
          <Card variant="outlined" sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="h6" component="h2" gutterBottom>
                Per platform
              </Typography>
              {data.platforms.length === 0 ? (
                <Empty>No platform seen.</Empty>
              ) : (
                <BarList
                  ariaLabel="Events per platform"
                  rows={data.platforms.map((p) => ({
                    key: p.platform,
                    label: platformLabel(p.platform),
                    value: p.total,
                    color: seriesBlue,
                    detail: `${formatCount(p.redacted)} redacted, ${formatCount(p.blocked)} blocked`,
                  }))}
                />
              )}
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={3}>
          <Card variant="outlined" sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="h6" component="h2" gutterBottom>
                DLP finding classes
              </Typography>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                Events with a finding: {formatCount(findingEvents)}. Classes and counts only; no value is stored.
              </Typography>
              {data.findings.length === 0 ? (
                <Empty>No findings.</Empty>
              ) : (
                <BarList
                  ariaLabel="Finding classes"
                  rows={data.findings.map((f) => ({
                    key: f.dataClass,
                    label: dataClassLabel(f.dataClass),
                    value: f.events,
                    color: seriesBlue,
                    detail: `${formatCount(f.hits)} hits`,
                  }))}
                />
              )}
            </CardContent>
          </Card>
        </Grid>
      </Grid>
    </>
  );
}
