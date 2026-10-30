import { Alert, AlertTitle, Box, CircularProgress, Typography } from '@mui/material';
import { ApiError } from '../api';
import { useI18n } from '../i18n';
import { reasonLabel } from '../labels';

/**
 * Loading, error and empty states. An error shows the server's reason class as a label in the selected language, the
 * stable English code beside it, and the server's sentence (AGENTS.md section 14; PO decision Q-38 point 3).
 */
export function ErrorPanel({ error }: { error: unknown }) {
  const i18n = useI18n();
  const e =
    error instanceof ApiError
      ? error
      : new ApiError(0, 'CLIENT_ERROR', error instanceof Error ? error.message : i18n.t('state.clientError'));
  const label = reasonLabel(i18n, e.reason);
  return (
    <Alert severity={e.status === 503 ? 'warning' : 'error'} role="alert">
      <AlertTitle>
        {label}
        {label !== e.reason && (
          <Typography component="span" variant="caption" sx={{ ml: 1, fontFamily: 'monospace', opacity: 0.8 }}>
            {e.reason}
          </Typography>
        )}
      </AlertTitle>
      {e.message}
    </Alert>
  );
}

export function Loading({ label }: { label?: string }) {
  const { t } = useI18n();
  return (
    <Box display="flex" alignItems="center" gap={1.5} py={4} aria-busy="true">
      <CircularProgress size={20} />
      <Typography color="text.secondary">{label ?? t('state.loading')}…</Typography>
    </Box>
  );
}

export function Empty({ children }: { children: React.ReactNode }) {
  return (
    <Typography color="text.secondary" py={3}>
      {children}
    </Typography>
  );
}
