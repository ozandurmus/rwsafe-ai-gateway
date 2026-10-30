import { Alert, AlertTitle, Box, CircularProgress, Typography } from '@mui/material';
import { ApiError } from '../api';

/** Loading, error and empty states. An error shows the server's reason class and sentence. */
export function ErrorPanel({ error }: { error: unknown }) {
  const e =
    error instanceof ApiError ? error : new ApiError(0, 'CLIENT_ERROR', error instanceof Error ? error.message : 'Unknown');
  return (
    <Alert severity={e.status === 503 ? 'warning' : 'error'} role="alert">
      <AlertTitle>{e.reason}</AlertTitle>
      {e.message}
    </Alert>
  );
}

export function Loading({ label = 'Loading' }: { label?: string }) {
  return (
    <Box display="flex" alignItems="center" gap={1.5} py={4} aria-busy="true">
      <CircularProgress size={20} />
      <Typography color="text.secondary">{label}…</Typography>
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
