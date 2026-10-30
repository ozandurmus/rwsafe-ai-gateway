import { Box, Card, CardContent, Grid, ToggleButton, ToggleButtonGroup, Typography, useTheme } from '@mui/material';
import { useState } from 'react';
import { api, type Overview } from '../api';
import { BarList } from '../components/BarList';
import { HourlyChart } from '../components/HourlyChart';
import { KpiCard } from '../components/KpiCard';
import { Empty, ErrorPanel, Loading } from '../components/StatePanel';
import { useI18n } from '../i18n';
import {
  GROUP_ORDER,
  VERDICT_GROUP,
  type VerdictGroup,
  dataClassLabel,
  groupColor,
  groupLabel,
  platformLabel,
} from '../labels';
import { WINDOWS, type WindowId, useApi, windowRange } from '../useApi';

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
  const { t } = useI18n();
  const [win, setWin] = useState<WindowId>('24h');
  const range = windowRange(win);
  const { data, error, loading } = useApi(() => api.overview(range.from, range.to), `${win}:${range.to}`);
  const seriesBlue = theme.palette.mode === 'light' ? '#2a78d6' : '#3987e5';

  return (
    <Box display="grid" gap={2}>
      <Box display="flex" flexWrap="wrap" alignItems="center" justifyContent="space-between" gap={1}>
        <Typography variant="h5" component="h1" sx={{ fontWeight: 600 }}>
          {t('overview.title')}
        </Typography>
        <ToggleButtonGroup
          size="small"
          exclusive
          value={win}
          onChange={(_, v) => v && setWin(v)}
          aria-label={t('window.label')}
        >
          {WINDOWS.map((w) => (
            <ToggleButton key={w.id} value={w.id}>
              {t(`window.${w.id}`)}
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
  const i18n = useI18n();
  const { t, fmt } = i18n;
  const groups = groupTotals(data);
  const findingEvents = data.findings.reduce((s, f) => s + f.events, 0);
  const share = (part: number) => t('kpi.shareOfAll', { share: fmt.percent(part, data.total) });
  return (
    <>
      <Grid container spacing={2}>
        <Grid item xs={12} sm={6} md={3}>
          <KpiCard label={t('kpi.inspected')} value={fmt.count(data.total)} detail={t('kpi.inspectedDetail')} />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <KpiCard label={t('kpi.redacted')} value={fmt.count(groups.redacted)} detail={share(groups.redacted)} />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <KpiCard label={t('kpi.blocked')} value={fmt.count(groups.blocked)} detail={share(groups.blocked)} />
        </Grid>
        <Grid item xs={12} sm={6} md={3}>
          <KpiCard
            label={t('kpi.notInspected')}
            value={fmt.count(groups.notInspected)}
            detail={t('kpi.notInspectedDetail')}
          />
        </Grid>
      </Grid>
      <Card variant="outlined">
        <CardContent>
          <Typography variant="h6" component="h2" gutterBottom>
            {t('overview.perHour')}
          </Typography>
          {data.total === 0 ? <Empty>{t('overview.noEvents')}</Empty> : <HourlyChart overview={data} />}
        </CardContent>
      </Card>
      <Grid container spacing={2}>
        <Grid item xs={12} md={4}>
          <Card variant="outlined" sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="h6" component="h2" gutterBottom>
                {t('overview.verdictMix')}
              </Typography>
              <BarList
                ariaLabel={t('overview.verdictMix')}
                rows={GROUP_ORDER.map((g) => ({
                  key: g,
                  label: groupLabel(i18n, g),
                  value: groups[g],
                  color: groupColor(g, theme.palette.mode),
                  detail: fmt.percent(groups[g], data.total),
                }))}
              />
            </CardContent>
          </Card>
        </Grid>
        <Grid item xs={12} md={5}>
          <Card variant="outlined" sx={{ height: '100%' }}>
            <CardContent>
              <Typography variant="h6" component="h2" gutterBottom>
                {t('overview.perPlatform')}
              </Typography>
              {data.platforms.length === 0 ? (
                <Empty>{t('overview.noPlatform')}</Empty>
              ) : (
                <BarList
                  ariaLabel={t('overview.perPlatformAria')}
                  rows={data.platforms.map((p) => ({
                    key: p.platform,
                    label: platformLabel(i18n, p.platform),
                    value: p.total,
                    color: seriesBlue,
                    detail: t('overview.platformDetail', {
                      redacted: fmt.count(p.redacted),
                      blocked: fmt.count(p.blocked),
                    }),
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
                {t('overview.findingClasses')}
              </Typography>
              <Typography variant="body2" color="text.secondary" gutterBottom>
                {t('overview.findingNote', { count: fmt.count(findingEvents) })}
              </Typography>
              {data.findings.length === 0 ? (
                <Empty>{t('overview.noFindings')}</Empty>
              ) : (
                <BarList
                  ariaLabel={t('overview.findingClasses')}
                  rows={data.findings.map((f) => ({
                    key: f.dataClass,
                    label: dataClassLabel(i18n, f.dataClass),
                    value: f.events,
                    color: seriesBlue,
                    detail: t('overview.hits', { count: fmt.count(f.hits) }),
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
