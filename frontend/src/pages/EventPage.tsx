import { Box, Button, Card, CardContent, Grid, Typography } from '@mui/material';
import { Link as RouterLink, useLocation, useParams } from 'react-router-dom';
import { api } from '../api';
import { useAuth } from '../auth';
import { CaptureReader, canReadCapture } from '../components/CaptureReader';
import { ErrorPanel, Loading } from '../components/StatePanel';
import { VerdictPill } from '../components/VerdictPill';
import { useI18n } from '../i18n';
import { dataClassLabel, platformLabel } from '../labels';
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

/**
 * One event: metadata, verdict and finding classes (ADR-009 C1/C2/C6). Only a REDACT verdict can have captured content
 * (C3, redacted mode); its reader is offered to the reader roles only and opens nothing without a reason and a case id.
 */
export function EventPage() {
  const i18n = useI18n();
  const { t, fmt } = i18n;
  const { me } = useAuth();
  const { eventId = '' } = useParams();
  const location = useLocation();
  const { data, error, loading } = useApi(() => api.event(eventId), eventId);
  return (
    <Box display="grid" gap={2}>
      <Box>
        <Button component={RouterLink} to={`/traffic${location.search}`} size="small">
          {t('event.back')}
        </Button>
      </Box>
      {error !== null && <ErrorPanel error={error} />}
      {loading && !data && <Loading />}
      {data && (
        <>
          <Box display="flex" flexWrap="wrap" alignItems="center" gap={1.5}>
            <Typography variant="h5" component="h1" sx={{ fontWeight: 600 }}>
              {platformLabel(i18n, data.platform)} · {data.surface} · {data.step}
            </Typography>
            <VerdictPill verdict={data.verdict} />
          </Box>
          <Typography color="text.secondary">
            {t('event.when', { time: fmt.time(data.receivedAt), service: data.service.toUpperCase() })}
          </Typography>
          <Card variant="outlined">
            <CardContent>
              <Grid container spacing={2}>
                <Field label={t('event.reason')} value={data.reason ?? '—'} />
                <Field label={t('event.user')} value={data.user ?? '—'} mono />
                <Field label={t('event.subnet')} value={data.clientSubnet ?? '—'} mono />
                <Field label={t('event.decisionTime')} value={fmt.micros(data.decisionMicros)} />
                <Field label={t('event.bodySize')} value={fmt.bytes(data.bodyBytes)} />
                <Field label={t('event.transport')} value={data.transport} />
                <Field label={t('event.snapshot')} value={`v${data.snapshotVersion}`} />
                <Field label={t('event.correlation')} value={data.correlationId} mono />
                <Field label={t('event.eventId')} value={data.eventId} mono />
                <Field label={t('event.pseudonymKey')} value={data.pseudonymKeyId} mono />
              </Grid>
            </CardContent>
          </Card>
          <Card variant="outlined">
            <CardContent>
              <Typography variant="h6" component="h2" gutterBottom>
                {t('event.findings')}
              </Typography>
              {data.findings.length === 0 ? (
                <Typography color="text.secondary">{t('event.noFinding')}</Typography>
              ) : (
                <Box component="ul" sx={{ m: 0, pl: 2.5 }}>
                  {data.findings.map((f) => (
                    <li key={f.dataClass}>
                      {dataClassLabel(i18n, f.dataClass)}:{' '}
                      {t(f.count === 1 ? 'event.hitsOne' : 'event.hitsMany', { count: fmt.count(f.count) })}
                    </li>
                  ))}
                </Box>
              )}
              <Typography variant="body2" color="text.secondary" sx={{ mt: 1.5 }}>
                {t('event.findingsNote')}
              </Typography>
            </CardContent>
          </Card>
          {me && canReadCapture(me) && data.verdict === 'REDACT' && (
            <CaptureReader key={data.eventId} me={me} eventId={data.eventId} />
          )}
        </>
      )}
    </Box>
  );
}
