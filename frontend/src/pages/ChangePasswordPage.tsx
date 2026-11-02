import { Alert, Box, Button, Card, CardContent, TextField, Typography } from '@mui/material';
import { useState } from 'react';
import { MIN_PASSWORD_LENGTH } from '../api';
import { useAuth } from '../auth';
import { ErrorPanel } from '../components/StatePanel';
import { useI18n } from '../i18n';

/**
 * A local user's own password (PO decision Q-47). `forced`: the session was opened with a generated password and reaches
 * nothing else until this is done (the server holds it to that). The server checks the rule again and its refusal is
 * shown as it comes; neither password is kept after the request.
 */
export function ChangePasswordPage({ forced = false }: { forced?: boolean }) {
  const { t } = useI18n();
  const { changePassword, logout } = useAuth();
  const [current, setCurrent] = useState('');
  const [next, setNext] = useState('');
  const [repeat, setRepeat] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [saved, setSaved] = useState(false);
  const tooShort = next.length > 0 && [...next].length < MIN_PASSWORD_LENGTH;
  const mismatch = repeat.length > 0 && repeat !== next;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setSaved(false);
    try {
      await changePassword(current, next);
      setSaved(true);
    } catch (err) {
      setError(err);
    } finally {
      setCurrent('');
      setNext('');
      setRepeat('');
      setBusy(false);
    }
  }

  const form = (
    <CardContent component="form" onSubmit={submit} sx={{ display: 'grid', gap: 2 }}>
      <Typography variant="h5" component="h1" sx={{ fontWeight: 600 }}>
        {t('password.title')}
      </Typography>
      {forced && <Alert severity="info">{t('password.forcedHint')}</Alert>}
      {saved && <Alert severity="success">{t('password.saved')}</Alert>}
      {error !== null && <ErrorPanel error={error} />}
      <TextField
        label={t('password.current')}
        type="password"
        value={current}
        onChange={(e) => setCurrent(e.target.value)}
        autoComplete="current-password"
        required
      />
      <TextField
        label={t('password.new')}
        type="password"
        value={next}
        onChange={(e) => setNext(e.target.value)}
        autoComplete="new-password"
        error={tooShort}
        helperText={tooShort ? t('password.tooShort') : t('password.rule', { min: MIN_PASSWORD_LENGTH })}
        required
      />
      <TextField
        label={t('password.repeat')}
        type="password"
        value={repeat}
        onChange={(e) => setRepeat(e.target.value)}
        autoComplete="new-password"
        error={mismatch}
        helperText={mismatch ? t('password.mismatch') : ' '}
        required
      />
      <Box display="flex" gap={1} justifyContent="space-between" flexWrap="wrap">
        <Button
          type="submit"
          variant="contained"
          disabled={busy || !current || [...next].length < MIN_PASSWORD_LENGTH || next !== repeat}
        >
          {t('password.submit')}
        </Button>
        {forced && <Button onClick={() => void logout()}>{t('user.signOut')}</Button>}
      </Box>
    </CardContent>
  );

  if (!forced) {
    return (
      <Card variant="outlined" sx={{ maxWidth: 480 }}>
        {form}
      </Card>
    );
  }
  return (
    <Box minHeight="100vh" display="flex" alignItems="center" justifyContent="center" px={2} bgcolor="background.default">
      <Card variant="outlined" sx={{ width: '100%', maxWidth: 440 }}>
        {form}
      </Card>
    </Box>
  );
}
