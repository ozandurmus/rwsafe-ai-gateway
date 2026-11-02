import { Box, Card, CardContent, Chip, Grid, Typography } from '@mui/material';
import { api } from '../../api';
import { ErrorPanel, Loading } from '../../components/StatePanel';
import { type I18n, useI18n } from '../../i18n';
import { useApi } from '../../useApi';

export function uptimeLabel(i: I18n, seconds: number): string {
  const d = Math.floor(seconds / 86_400);
  const h = Math.floor((seconds % 86_400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return i.t('system.uptimeValue', { d, h, m });
}

function Fact({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <Box display="grid" gridTemplateColumns={{ xs: '1fr', sm: '220px 1fr' }} gap={1} py={0.75}>
      <Typography component="dt" variant="body2" color="text.secondary">
        {label}
      </Typography>
      <Typography component="dd" variant="body2" sx={{ m: 0, fontFamily: mono ? 'monospace' : undefined }}>
        {value}
      </Typography>
    </Box>
  );
}

/**
 * Platform -> System (PO decision Q-47 decision 1.4): the running version, since when, and the switches that change
 * what the product does. Read only; the switches are set in the deployment.
 */
export function SystemPage() {
  const i18n = useI18n();
  const { t, fmt } = i18n;
  const { data, error, loading } = useApi(() => api.adminSystem(), 'admin-system');
  if (loading && !data) {
    return <Loading />;
  }
  if (error !== null) {
    return <ErrorPanel error={error} />;
  }
  if (!data) {
    return null;
  }
  const s = data.switches;
  const switches: { label: string; on: boolean }[] = [
    { label: t('system.switch.singleApproval'), on: s.singleApproval },
    { label: t('system.switch.breakGlassSignIn'), on: s.breakGlassSignIn },
    { label: t('system.switch.directoryConfigured'), on: s.directoryConfigured },
    { label: t('system.switch.directoryEnabled'), on: s.directoryEnabled },
    { label: t('system.switch.directoryKeyPresent'), on: s.directoryKeyPresent },
    { label: t('system.switch.capture'), on: s.captureMode !== 'off' },
    { label: t('system.switch.siemExport'), on: s.siemExport },
  ];
  return (
    <Grid container spacing={2}>
      <Grid item xs={12} md={7}>
        <Card variant="outlined" sx={{ height: '100%' }}>
          <CardContent>
            <Typography variant="h6" component="h3" mb={1}>
              {t('system.facts')}
            </Typography>
            <Box component="dl" sx={{ m: 0 }}>
              <Fact label={t('system.version')} value={data.version} mono />
              <Fact label={t('system.commit')} value={data.commit ?? t('system.notRecorded')} mono={!!data.commit} />
              <Fact
                label={t('system.buildTime')}
                value={data.buildTime ? fmt.time(data.buildTime) : t('system.notRecorded')}
              />
              <Fact label={t('system.java')} value={data.javaVersion} mono />
              <Fact label={t('system.schema')} value={data.schemaVersion ?? '—'} mono />
              <Fact label={t('system.startedAt')} value={fmt.time(data.startedAt)} />
              <Fact label={t('system.uptime')} value={uptimeLabel(i18n, data.uptimeSeconds)} />
              <Fact
                label={t('system.directoryStatus')}
                value={i18n.label(`system.directoryStatus.${s.directoryStatus}`, s.directoryStatus)}
              />
            </Box>
          </CardContent>
        </Card>
      </Grid>
      <Grid item xs={12} md={5}>
        <Card variant="outlined" sx={{ height: '100%' }}>
          <CardContent>
            <Typography variant="h6" component="h3" mb={1}>
              {t('system.switches')}
            </Typography>
            <Box component="ul" sx={{ m: 0, p: 0, listStyle: 'none' }} aria-label={t('system.switches')}>
              {switches.map((x) => (
                <Box component="li" key={x.label} display="flex" justifyContent="space-between" gap={2} py={0.75}>
                  <Typography variant="body2">{x.label}</Typography>
                  <Chip
                    size="small"
                    color={x.on ? 'primary' : 'default'}
                    variant={x.on ? 'filled' : 'outlined'}
                    label={x.on ? t('system.on') : t('system.off')}
                  />
                </Box>
              ))}
            </Box>
          </CardContent>
        </Card>
      </Grid>
    </Grid>
  );
}
