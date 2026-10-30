import { Box, Card, CardContent, Grid, Typography } from '@mui/material';
import { api } from '../api';
import { ErrorPanel, Loading } from '../components/StatePanel';
import { formatCount, formatTime } from '../labels';
import { useApi } from '../useApi';

const STATE_WORD: Record<string, { word: string; color: string }> = {
  UP: { word: 'Up', color: '#0ca30c' },
  DEGRADED: { word: 'Degraded', color: '#fab219' },
  DOWN: { word: 'Down', color: '#d03b3b' },
  UNKNOWN: { word: 'Unknown', color: '#8f8e89' },
};

/** Health (stub): the control plane's own components; the data-plane signals arrive with the metrics slice. */
export function HealthPage() {
  const { data, error, loading } = useApi(() => api.health(), 'health');
  return (
    <Box display="grid" gap={2}>
      <Typography variant="h5" component="h1" sx={{ fontWeight: 600 }}>
        Health
      </Typography>
      {error !== null && <ErrorPanel error={error} />}
      {loading && !data && <Loading />}
      {data && (
        <>
          <Typography color="text.secondary">
            Checked {formatTime(data.checkedAt)} · {formatCount(data.totalEvents)} events stored · last event{' '}
            {formatTime(data.latestEventAt)} · {formatCount(data.eventsLastFiveMinutes)} ingested in the last 5 minutes
          </Typography>
          <Grid container spacing={2}>
            {data.components.map((c) => {
              const s = STATE_WORD[c.state] ?? { word: c.state, color: '#8f8e89' };
              return (
                <Grid item xs={12} sm={6} md={4} key={c.component}>
                  <Card variant="outlined" sx={{ height: '100%' }}>
                    <CardContent>
                      <Typography variant="body2" color="text.secondary">
                        {c.component}
                      </Typography>
                      <Box display="flex" alignItems="center" gap={1} mt={0.5}>
                        <Box aria-hidden sx={{ width: 10, height: 10, borderRadius: '50%', bgcolor: s.color }} />
                        <Typography variant="h6" component="p">
                          {s.word}
                        </Typography>
                      </Box>
                      <Typography variant="body2" color="text.secondary" mt={0.5}>
                        {c.detail}
                      </Typography>
                    </CardContent>
                  </Card>
                </Grid>
              );
            })}
          </Grid>
        </>
      )}
    </Box>
  );
}
