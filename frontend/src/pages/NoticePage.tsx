import {
  Alert,
  Box,
  Button,
  Card,
  CardContent,
  Grid,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  TextField,
  Typography,
} from '@mui/material';
import { useState } from 'react';
import { USER_PSEUDONYM_PATTERN, api, type UserAcknowledgements } from '../api';
import { useAuth } from '../auth';
import { Empty, ErrorPanel, Loading } from '../components/StatePanel';
import { useI18n } from '../i18n';
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
 * The end-user notice (aydınlatma metni) as the server holds it: version, completeness and the number of users who
 * acknowledged it; the rendered sections for the unmasked roles (the masked projection carries none, they hold the
 * configured values); an acknowledgement lookup by USR- pseudonym only.
 */
export function NoticePage() {
  const i18n = useI18n();
  const { t, fmt } = i18n;
  const { me } = useAuth();
  const { data, error, loading } = useApi(() => api.notice(), 'notice');
  return (
    <Box display="grid" gap={2}>
      <Typography variant="h5" component="h1" sx={{ fontWeight: 600 }}>
        {t('notice.title')}
      </Typography>
      <Typography color="text.secondary">{t('notice.intro')}</Typography>
      {error !== null && <ErrorPanel error={error} />}
      {loading && !data && <Loading />}
      {data && (
        <>
          <Card variant="outlined">
            <CardContent>
              <Grid container spacing={2}>
                <Field label={t('notice.currentVersion')} value={data.currentVersion ?? t('notice.noVersion')} mono />
                <Field label={t('notice.catalogueVersion')} value={data.catalogueVersion} mono />
                <Field label={t('notice.complete')} value={data.complete ? t('notice.yes') : t('notice.no')} />
                <Field label={t('notice.acknowledgedCount')} value={fmt.count(data.usersAcknowledged)} />
                {data.missingParameters.length > 0 && (
                  <Field label={t('notice.missing')} value={data.missingParameters.join(', ')} mono />
                )}
                {data.rejectedParameters.length > 0 && (
                  <Field label={t('notice.rejected')} value={data.rejectedParameters.join(', ')} mono />
                )}
              </Grid>
              {!data.complete && (
                <Alert severity="warning" sx={{ mt: 2 }}>
                  {t('notice.incomplete')}
                </Alert>
              )}
            </CardContent>
          </Card>
          <Card variant="outlined">
            <CardContent>
              <Typography variant="h6" component="h2" gutterBottom>
                {data.title}
              </Typography>
              {data.sections === null ? (
                // PR 28 review D-04: an incomplete notice has no text for any role; only a complete one is withheld
                // from the masked view.
                <Alert severity="info">
                  {!data.complete || !me?.masked ? t('notice.sectionsNone') : t('notice.sectionsMasked')}
                </Alert>
              ) : (
                <Box display="grid" gap={1.5} lang="tr">
                  {data.sections.map((s, i) => (
                    <Box component="section" key={`${i}-${s.heading}`}>
                      <Typography variant="subtitle1" component="h3" sx={{ fontWeight: 600 }}>
                        {s.heading}
                      </Typography>
                      {s.paragraphs.map((p, j) => (
                        <Typography key={j} variant="body2" sx={{ mt: 0.5, whiteSpace: 'pre-wrap' }}>
                          {p}
                        </Typography>
                      ))}
                    </Box>
                  ))}
                </Box>
              )}
            </CardContent>
          </Card>
        </>
      )}
      <AcknowledgementLookup />
    </Box>
  );
}

/** One user's acknowledgements, looked up by USR- pseudonym; anything else is refused here before it is sent. */
function AcknowledgementLookup() {
  const i18n = useI18n();
  const { t, fmt } = i18n;
  const [user, setUser] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [result, setResult] = useState<UserAcknowledgements | null>(null);
  const trimmed = user.trim();
  const valid = USER_PSEUDONYM_PATTERN.test(trimmed);

  async function lookUp() {
    setBusy(true);
    setError(null);
    setResult(null);
    try {
      setResult(await api.noticeAcknowledgements(trimmed));
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Card variant="outlined">
      <CardContent sx={{ display: 'grid', gap: 1.5 }}>
        <Typography variant="h6" component="h2">
          {t('notice.lookupTitle')}
        </Typography>
        <Typography variant="body2" color="text.secondary">
          {t('notice.lookupIntro')}
        </Typography>
        <Box
          component="form"
          display="flex"
          gap={1}
          alignItems="flex-start"
          flexWrap="wrap"
          aria-label={t('notice.lookupTitle')}
          onSubmit={(e) => {
            e.preventDefault();
            if (valid && !busy) {
              void lookUp();
            }
          }}
        >
          <TextField
            size="small"
            label={t('notice.lookupUser')}
            placeholder="USR-0123456789"
            value={user}
            onChange={(e) => setUser(e.target.value)}
            error={trimmed !== '' && !valid}
            helperText={trimmed !== '' && !valid ? t('traffic.userInvalid') : ' '}
            inputProps={{ maxLength: 14, spellCheck: false, autoComplete: 'off' }}
            sx={{ minWidth: 260 }}
          />
          <Button type="submit" variant="contained" size="small" disabled={!valid || busy} sx={{ mt: 0.5 }}>
            {t('notice.lookupButton')}
          </Button>
        </Box>
        {error !== null && <ErrorPanel error={error} />}
        {busy && <Loading />}
        {result && (
          <>
            <Alert severity={result.currentAcknowledged ? 'success' : 'info'}>
              {result.currentVersion === null
                ? t('notice.lookupNoCurrent', { user: result.user })
                : result.currentAcknowledged
                  ? t('notice.lookupAcknowledged', { user: result.user, version: result.currentVersion })
                  : t('notice.lookupNotAcknowledged', { user: result.user, version: result.currentVersion })}
            </Alert>
            {result.records.length === 0 ? (
              <Empty>{t('notice.lookupEmpty')}</Empty>
            ) : (
              <TableContainer>
                <Table size="small" aria-label={t('notice.lookupTable')}>
                  <TableHead>
                    <TableRow>
                      <TableCell>{t('notice.col.version')}</TableCell>
                      <TableCell>{t('notice.col.acknowledgedAt')}</TableCell>
                      <TableCell>{t('notice.col.source')}</TableCell>
                      <TableCell>{t('notice.col.recordedAt')}</TableCell>
                      <TableCell>{t('notice.col.key')}</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {result.records.map((r, i) => (
                      <TableRow key={`${r.noticeVersion}-${r.source}-${i}`}>
                        <TableCell sx={{ fontFamily: 'monospace' }}>{r.noticeVersion}</TableCell>
                        <TableCell>{fmt.time(r.acknowledgedAt)}</TableCell>
                        <TableCell>{i18n.label(`notice.source.${r.source}`, r.source)}</TableCell>
                        <TableCell>{fmt.time(r.recordedAt)}</TableCell>
                        <TableCell sx={{ fontFamily: 'monospace' }}>{r.pseudonymKeyId}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            )}
          </>
        )}
      </CardContent>
    </Card>
  );
}
