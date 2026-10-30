import { Box, Card, CardContent, Grid, Typography } from '@mui/material';
import { api } from '../api';
import { ErrorPanel, Loading } from '../components/StatePanel';
import { useI18n } from '../i18n';
import { useApi } from '../useApi';

const STATE_COLOR: Record<string, string> = {
  UP: '#0ca30c',
  DEGRADED: '#fab219',
  DOWN: '#d03b3b',
  UNKNOWN: '#8f8e89',
};

/**
 * Health (stub): the control plane's own components; the data-plane signals arrive with the metrics slice. A component's
 * name and state are words in the selected language; its detail is the server's sentence.
 */
export function HealthPage() {
  const i18n = useI18n();
  const { t, fmt } = i18n;
  const { data, error, loading } = useApi(() => api.health(), 'health');
  return (
    <Box display="grid" gap={2}>
      <Typography variant="h5" component="h1" sx={{ fontWeight: 600 }}>
        {t('health.title')}
      </Typography>
      {error !== null && <ErrorPanel error={error} />}
      {loading && !data && <Loading />}
      {data && (
        <>
          <Typography color="text.secondary">
            {t('health.summary', {
              checked: fmt.time(data.checkedAt),
              total: fmt.count(data.totalEvents),
              last: fmt.time(data.latestEventAt),
              recent: fmt.count(data.eventsLastFiveMinutes),
            })}
          </Typography>
          <Grid container spacing={2}>
            {data.components.map((c) => (
              <Grid item xs={12} sm={6} md={4} key={c.component}>
                <Card variant="outlined" sx={{ height: '100%' }}>
                  <CardContent>
                    <Typography variant="body2" color="text.secondary">
                      {i18n.label(`health.component.${c.component}`, c.component)}
                    </Typography>
                    <Box display="flex" alignItems="center" gap={1} mt={0.5}>
                      <Box
                        aria-hidden
                        sx={{ width: 10, height: 10, borderRadius: '50%', bgcolor: STATE_COLOR[c.state] ?? '#8f8e89' }}
                      />
                      <Typography variant="h6" component="p">
                        {i18n.label(`health.state.${c.state}`, c.state)}
                      </Typography>
                    </Box>
                    <Typography variant="body2" color="text.secondary" mt={0.5}>
                      {c.detail}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>
        </>
      )}
    </Box>
  );
}
