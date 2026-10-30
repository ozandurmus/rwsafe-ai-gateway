import { Box, Card, CardContent, Grid, Typography } from '@mui/material';
import { api } from '../api';
import { ErrorPanel, Loading } from '../components/StatePanel';
import { EXPLAINED_COMPONENTS, type FactGroup, type HealthFact, healthFacts } from '../healthFacts';
import { type I18n, useI18n } from '../i18n';
import { useApi } from '../useApi';

const STATE_COLOR: Record<string, string> = {
  UP: '#0ca30c',
  DEGRADED: '#fab219',
  DOWN: '#d03b3b',
  UNKNOWN: '#8f8e89',
};

function factValue(i18n: I18n, f: HealthFact): string {
  const { t, fmt } = i18n;
  switch (f.key) {
    case 'storedBytes':
    case 'capBytes':
      return typeof f.value === 'number' ? fmt.bytes(f.value) : String(f.value);
    case 'usedPercent':
      return typeof f.value === 'number' ? fmt.percentValue(f.value) : String(f.value);
    case 'stalledSeconds':
      return t('health.stalledFor', { seconds: typeof f.value === 'number' ? fmt.count(f.value) : f.value });
    case 'queue':
      return t('health.queueOf', { depth: fmt.count(Number(f.value)), capacity: fmt.count(f.of ?? 0) });
    case 'backlogUncounted':
      return t('health.notCountedYet');
    case 'readerFailure':
    case 'senderFailure':
      return i18n.label(`health.siemFailure.${String(f.value)}`, String(f.value));
    default:
      return typeof f.value === 'number' ? fmt.count(f.value) : f.value;
  }
}

/** The facts read from a component's detail, as label and value rows per destination. */
function Facts({ groups }: { groups: FactGroup[] }) {
  const i18n = useI18n();
  return (
    <>
      {groups.map((g) => (
        <Box key={g.group ?? '-'} mt={1}>
          {g.group !== null && (
            <Typography variant="subtitle2" component="h3">
              {i18n.label(`health.siemDestination.${g.group}`, g.group)}
            </Typography>
          )}
          <Box component="dl" sx={{ m: 0, display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) auto', columnGap: 2 }}>
            {g.facts.map((f) => (
              <Box key={f.key} sx={{ display: 'contents' }}>
                <Typography component="dt" variant="body2" color="text.secondary">
                  {i18n.t(`health.fact.${f.key}`)}
                </Typography>
                <Typography component="dd" variant="body2" sx={{ m: 0, textAlign: 'right', wordBreak: 'break-word' }}>
                  {factValue(i18n, f)}
                </Typography>
              </Box>
            ))}
          </Box>
        </Box>
      ))}
    </>
  );
}

/**
 * Health: the control plane's own components. A component's name and state are words in the selected language; the SIEM
 * export and the capture components also say in plain words what their state means and what to do, and show their
 * counts by name. The server's own detail is always shown as it came.
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
            {data.components.map((c) => {
              const explained = (EXPLAINED_COMPONENTS as readonly string[]).includes(c.component);
              const meaning = explained ? i18n.label(`health.meaning.${c.component}.${c.state}`, '') : '';
              const todo = explained ? i18n.label(`health.todo.${c.component}.${c.state}`, '') : '';
              const groups = explained ? healthFacts(c.component, c.detail) : [];
              return (
                <Grid item xs={12} sm={explained ? 12 : 6} md={explained ? 6 : 4} key={c.component}>
                  <Card
                    variant="outlined"
                    sx={{ height: '100%' }}
                    component="section"
                    aria-label={i18n.label(`health.component.${c.component}`, c.component)}
                  >
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
                      {meaning !== '' && (
                        <Typography variant="body2" mt={1}>
                          <strong>{t('health.meaningLabel')}</strong> {meaning}
                        </Typography>
                      )}
                      {todo !== '' && (
                        <Typography variant="body2" mt={0.5}>
                          <strong>{t('health.todoLabel')}</strong> {todo}
                        </Typography>
                      )}
                      {groups.length > 0 && <Facts groups={groups} />}
                      <Typography variant="body2" color="text.secondary" mt={1}>
                        {explained && <>{t('health.serverDetail')} </>}
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
