import {
  Box,
  Card,
  CardContent,
  Grid,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Typography,
} from '@mui/material';
import { api } from '../../api';
import { ErrorPanel, Loading } from '../../components/StatePanel';
import { type I18n, useI18n } from '../../i18n';
import { roleLabel } from '../../labels';
import { useApi } from '../../useApi';

function permissionLabel(i: I18n, id: string): string {
  return i.label(`permission.${id}`, id);
}

/**
 * Roles & permissions (PO decision Q-47): read-only, and read from the server, which describes the very rules its
 * security chain applies (`AccessRules`), so this page cannot drift from what is enforced.
 */
export function RolesPage() {
  const i18n = useI18n();
  const { t } = i18n;
  const { data, error, loading } = useApi(() => api.adminRoles(), 'admin-roles');
  if (loading && !data) {
    return <Loading />;
  }
  if (error !== null) {
    return <ErrorPanel error={error} />;
  }
  if (!data) {
    return null;
  }
  return (
    <Box display="grid" gap={3}>
      <Grid container spacing={2}>
        {data.roles.map((r) => (
          <Grid item xs={12} md={6} key={r.role}>
            <Card variant="outlined" sx={{ height: '100%' }}>
              <CardContent>
                <Typography variant="h6" component="h3">
                  {roleLabel(i18n, r.role)}
                </Typography>
                <Typography variant="caption" color="text.secondary" sx={{ fontFamily: 'monospace' }}>
                  {r.role}
                </Typography>
                <Typography variant="subtitle2" mt={1}>
                  {t('roles.permissions')}
                </Typography>
                <Box component="ul" sx={{ m: 0, pl: 2.5 }} aria-label={`${roleLabel(i18n, r.role)}: ${t('roles.permissions')}`}>
                  {r.permissions.map((p) => (
                    <li key={p}>
                      <Typography variant="body2">{permissionLabel(i18n, p)}</Typography>
                    </li>
                  ))}
                  {r.permissions.length === 0 && (
                    <li>
                      <Typography variant="body2">{t('roles.none')}</Typography>
                    </li>
                  )}
                </Box>
                {r.masked && (
                  <Typography variant="body2" color="text.secondary" mt={1}>
                    {t('roles.maskedNote')}
                  </Typography>
                )}
              </CardContent>
            </Card>
          </Grid>
        ))}
      </Grid>
      <Box>
        <Typography variant="h6" component="h3">
          {t('roles.rulesTitle')}
        </Typography>
        <Typography variant="body2" color="text.secondary" mb={1}>
          {t('roles.rulesHint')}
        </Typography>
        <TableContainer>
          <Table size="small" aria-label={t('roles.rulesTitle')}>
            <TableHead>
              <TableRow>
                <TableCell>#</TableCell>
                <TableCell>{t('roles.rule')}</TableCell>
                <TableCell>{t('roles.method')}</TableCell>
                <TableCell>{t('roles.path')}</TableCell>
                <TableCell>{t('roles.allowedRoles')}</TableCell>
                <TableCell>{t('roles.maskedRefused')}</TableCell>
                <TableCell>{t('roles.beforePasswordChange')}</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {data.rules.map((rule, index) => (
                <TableRow key={rule.id}>
                  <TableCell>{index + 1}</TableCell>
                  <TableCell>{permissionLabel(i18n, rule.id)}</TableCell>
                  <TableCell sx={{ fontFamily: 'monospace' }}>{rule.method}</TableCell>
                  <TableCell sx={{ fontFamily: 'monospace' }}>{rule.pattern}</TableCell>
                  <TableCell>
                    {rule.anyOf.length === 0
                      ? t('roles.anySession')
                      : rule.anyOf.map((r) => roleLabel(i18n, r)).join(', ')}
                  </TableCell>
                  <TableCell>{rule.maskedRefused ? t('admin.yes') : t('admin.no')}</TableCell>
                  <TableCell>{rule.pendingAllowed ? t('admin.yes') : t('admin.no')}</TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      </Box>
    </Box>
  );
}
