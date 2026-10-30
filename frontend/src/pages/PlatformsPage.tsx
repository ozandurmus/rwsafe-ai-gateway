import {
  Box,
  Card,
  Chip,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material';
import { api } from '../api';
import { Empty, ErrorPanel, Loading } from '../components/StatePanel';
import { useI18n } from '../i18n';
import { modeLabel, platformLabel, statusLabel } from '../labels';
import { useApi } from '../useApi';
import { baseline } from './PoliciesPage';

function Hosts({ hosts }: { hosts: string[] | null }) {
  if (!hosts || hosts.length === 0) {
    return <>—</>;
  }
  return (
    <Box component="ul" sx={{ m: 0, p: 0, listStyle: 'none', fontFamily: 'monospace', fontSize: 13 }}>
      {hosts.map((h) => (
        <li key={h}>{h}</li>
      ))}
    </Box>
  );
}

/** Platforms: the registry's platform rows as the data plane receives them (vendor-published endpoints only). */
export function PlatformsPage() {
  const i18n = useI18n();
  const { t } = i18n;
  const { data, error, loading } = useApi(() => api.policyRules(), 'platform-rules');
  const rows = (data?.rules ?? []).filter((r) => r.kind === 'platform');
  return (
    <Box display="grid" gap={2}>
      <Typography variant="h5" component="h1" sx={{ fontWeight: 600 }}>
        {t('platforms.title')}
      </Typography>
      <Typography color="text.secondary">{t('platforms.note')}</Typography>
      {error !== null && <ErrorPanel error={error} />}
      {loading && !data && <Loading />}
      {data && (
        <Card variant="outlined">
          <TableContainer>
            <Table size="small" aria-label={t('platforms.table')}>
              <TableHead>
                <TableRow>
                  <TableCell>{t('platforms.col.platform')}</TableCell>
                  <TableCell>{t('platforms.col.hosts')}</TableCell>
                  <TableCell>{t('platforms.col.api')}</TableCell>
                  <TableCell>{t('platforms.col.login')}</TableCell>
                  <TableCell>{t('platforms.col.version')}</TableCell>
                  <TableCell>{t('platforms.col.status')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {rows.map((r) => {
                  const v = baseline(r) ?? r.versions[0];
                  const pending = r.versions.filter((x) => x.status === 'pending').length;
                  return (
                    <TableRow key={r.ruleId}>
                      <TableCell>
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>
                          {platformLabel(i18n, r.subject)}
                        </Typography>
                        <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                          {r.subject}
                        </Typography>
                      </TableCell>
                      <TableCell>
                        <Hosts hosts={v?.hostSuffixes ?? null} />
                      </TableCell>
                      <TableCell>
                        <Hosts hosts={v?.apiHosts ?? null} />
                      </TableCell>
                      <TableCell>
                        <Hosts hosts={v?.loginHosts ?? null} />
                      </TableCell>
                      <TableCell sx={{ whiteSpace: 'nowrap' }}>
                        {v ? `${t('policies.version', { version: v.version })} · ${modeLabel(i18n, v.mode)}` : '—'}
                        {pending > 0 && (
                          <Chip
                            size="small"
                            color="warning"
                            variant="outlined"
                            sx={{ ml: 1 }}
                            label={t('policies.pendingCount', { count: pending })}
                          />
                        )}
                      </TableCell>
                      <TableCell sx={{ whiteSpace: 'nowrap' }}>
                        {v ? statusLabel(i18n, v.status) : '—'}
                        {v?.inSnapshot && <Chip size="small" sx={{ ml: 1 }} label={t('policies.inSnapshot')} />}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </TableContainer>
          {rows.length === 0 && (
            <Box px={2}>
              <Empty>{t('platforms.empty')}</Empty>
            </Box>
          )}
        </Card>
      )}
    </Box>
  );
}
