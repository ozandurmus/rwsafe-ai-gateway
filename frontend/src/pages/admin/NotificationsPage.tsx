import {
  Alert,
  Box,
  Card,
  CardContent,
  Chip,
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
import { useI18n } from '../../i18n';
import { useApi } from '../../useApi';

/**
 * Platform -> Notifications (PO decision Q-47 decision 1.4): what leaves the product today. The SIEM export is the one
 * outbound channel; its receivers are shown by kind, never by address. E-mail notifications do not exist yet, and the
 * page says so rather than offering a setting that does nothing.
 */
export function NotificationsPage() {
  const i18n = useI18n();
  const { t } = i18n;
  const { data, error, loading } = useApi(() => api.adminNotifications(), 'admin-notifications');
  if (loading && !data) {
    return <Loading />;
  }
  if (error !== null) {
    return <ErrorPanel error={error} />;
  }
  if (!data) {
    return null;
  }
  const stateColor =
    data.siemState === 'UP'
      ? 'success'
      : data.siemState === 'DOWN'
        ? 'error'
        : data.siemState === 'DEGRADED'
          ? 'warning'
          : 'default';
  return (
    <Box display="grid" gap={2}>
      <Card variant="outlined">
        <CardContent>
          <Box display="flex" justifyContent="space-between" alignItems="center" gap={2} flexWrap="wrap">
            <Typography variant="h6" component="h3">
              {t('notifications.siem')}
            </Typography>
            <Chip
              size="small"
              color={stateColor}
              label={`${t('notifications.state')}: ${i18n.label(`jobs.state.${data.siemState}`, data.siemState)}`}
            />
          </Box>
          <Typography variant="body2" color="text.secondary" mb={2}>
            {t('notifications.siemHint')}
          </Typography>
          <TableContainer>
            <Table size="small" aria-label={t('notifications.destinations')}>
              <TableHead>
                <TableRow>
                  <TableCell>{t('notifications.kind')}</TableCell>
                  <TableCell>{t('notifications.format')}</TableCell>
                  <TableCell>{t('notifications.configured')}</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {data.siemDestinations.map((d) => (
                  <TableRow key={d.kind}>
                    <TableCell>{i18n.label(`notifications.kind.${d.kind}`, d.kind)}</TableCell>
                    <TableCell sx={{ fontFamily: 'monospace' }}>{d.format ? d.format.toUpperCase() : '—'}</TableCell>
                    <TableCell>{d.configured ? t('admin.yes') : t('admin.no')}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
          <Typography variant="caption" color="text.secondary" display="block" mt={1}>
            {t('notifications.addressNote')}
          </Typography>
        </CardContent>
      </Card>
      <Card variant="outlined">
        <CardContent>
          <Typography variant="h6" component="h3" mb={1}>
            {t('notifications.email')}
          </Typography>
          <Alert severity="info">{t('notifications.emailUnavailable')}</Alert>
        </CardContent>
      </Card>
    </Box>
  );
}
