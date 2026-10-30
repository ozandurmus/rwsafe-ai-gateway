import { Box, Button, Card, CardContent, Grid, Typography } from '@mui/material';
import { Link as RouterLink, useLocation, useParams } from 'react-router-dom';
import { api } from '../api';
import { ErrorPanel, Loading } from '../components/StatePanel';
import { VerdictPill } from '../components/VerdictPill';
import { dataClassLabel, formatBytes, formatMicros, formatTime, platformLabel } from '../labels';
import { useApi } from '../useApi';

function Field({ label, value, mono = false }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <Grid item xs={12} sm={6} md={4}>
      <Typography variant="body2" color="text.secondary">
        {label}
      </Typography>
      <Typography sx={{ fontFamily: mono ? 'monospace' : undefined, wordBreak: 'break-all' }}>{value}</Typography>
    </Grid>
  );
}

/** One event: metadata, verdict and finding classes. There is no body to show (ADR-009 C1/C2/C6). */
export function EventPage() {
  const { eventId = '' } = useParams();
  const location = useLocation();
  const { data, error, loading } = useApi(() => api.event(eventId), eventId);
  return (
    <Box display="grid" gap={2}>
      <Box>
        <Button component={RouterLink} to={`/traffic${location.search}`} size="small">
          ← Traffic
        </Button>
      </Box>
      {error !== null && <ErrorPanel error={error} />}
      {loading && !data && <Loading />}
      {data && (
        <>
          <Box display="flex" flexWrap="wrap" alignItems="center" gap={1.5}>
            <Typography variant="h5" component="h1" sx={{ fontWeight: 600 }}>
              {platformLabel(data.platform)} · {data.surface} · {data.step}
            </Typography>
            <VerdictPill verdict={data.verdict} />
          </Box>
          <Typography color="text.secondary">
            {formatTime(data.receivedAt)} (Istanbul) · {data.service.toUpperCase()}
          </Typography>
          <Card variant="outlined">
            <CardContent>
              <Grid container spacing={2}>
                <Field label="Reason" value={data.reason ?? '—'} />
                <Field label="User (pseudonym)" value={data.user ?? '—'} mono />
                <Field label="Client subnet (masked)" value={data.clientSubnet ?? '—'} mono />
                <Field label="Decision time" value={formatMicros(data.decisionMicros)} />
                <Field label="Body size" value={formatBytes(data.bodyBytes)} />
                <Field label="Transport" value={data.transport} />
                <Field label="Policy snapshot" value={`v${data.snapshotVersion}`} />
                <Field label="Correlation id" value={data.correlationId} mono />
                <Field label="Event id" value={data.eventId} mono />
                <Field label="Pseudonym key" value={data.pseudonymKeyId} mono />
              </Grid>
            </CardContent>
          </Card>
          <Card variant="outlined">
            <CardContent>
              <Typography variant="h6" component="h2" gutterBottom>
                Findings
              </Typography>
              {data.findings.length === 0 ? (
                <Typography color="text.secondary">No detector finding.</Typography>
              ) : (
                <Box component="ul" sx={{ m: 0, pl: 2.5 }}>
                  {data.findings.map((f) => (
                    <li key={f.dataClass}>
                      {dataClassLabel(f.dataClass)}: {f.count} {f.count === 1 ? 'hit' : 'hits'}
                    </li>
                  ))}
                </Box>
              )}
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1.5 }}>
                Classes and counts only. The matched value is never stored, and prompt and response bodies are not shown
                on this screen.
              </Typography>
            </CardContent>
          </Card>
        </>
      )}
    </Box>
  );
}
