import { Box, Button, Dialog, DialogActions, DialogContent, DialogTitle, TextField, Typography } from '@mui/material';
import { useState } from 'react';
import { useI18n } from '../i18n';
import { ErrorPanel } from './StatePanel';

export const REASON_MAX = 500;

/**
 * A change that needs a reason (PO decision Q-47: every Administration change is ledgered with one). `children` holds the
 * change's own fields; `ready` says whether they are complete. The server's refusal is shown as it comes, and the dialog
 * stays open so the administrator can correct it.
 */
export function ReasonDialog({
  open,
  title,
  hint,
  confirm,
  danger = false,
  ready = true,
  onClose,
  onSubmit,
  children,
}: {
  open: boolean;
  title: string;
  hint?: string;
  confirm: string;
  danger?: boolean;
  ready?: boolean;
  onClose: () => void;
  onSubmit: (reason: string) => Promise<void>;
  children?: React.ReactNode;
}) {
  const { t } = useI18n();
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const trimmed = reason.trim();

  function close() {
    if (!busy) {
      setReason('');
      setError(null);
      onClose();
    }
  }

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await onSubmit(trimmed);
      setReason('');
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onClose={close} fullWidth maxWidth="sm">
      <Box component="form" onSubmit={submit} noValidate>
        <DialogTitle>{title}</DialogTitle>
        <DialogContent sx={{ display: 'grid', gap: 2, pt: '8px !important' }}>
          {hint && <Typography color="text.secondary">{hint}</Typography>}
          {children}
          <TextField
            label={t('admin.reason')}
            value={reason}
            onChange={(e) => setReason(e.target.value.replace(/[\r\n]+/g, ' '))}
            helperText={t('admin.reasonHint')}
            inputProps={{ maxLength: REASON_MAX }}
            required
            fullWidth
          />
          {error !== null && <ErrorPanel error={error} />}
        </DialogContent>
        <DialogActions>
          <Button onClick={close} disabled={busy}>
            {t('admin.cancel')}
          </Button>
          <Button
            type="submit"
            variant="contained"
            color={danger ? 'error' : 'primary'}
            disabled={busy || !ready || trimmed.length === 0}
          >
            {busy ? t('admin.saving') : confirm}
          </Button>
        </DialogActions>
      </Box>
    </Dialog>
  );
}
