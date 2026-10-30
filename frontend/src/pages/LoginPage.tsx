import { Box, Button, Card, CardContent, TextField, ToggleButton, ToggleButtonGroup, Typography } from '@mui/material';
import { useState } from 'react';
import { useAuth } from '../auth';
import { ErrorPanel } from '../components/StatePanel';
import { LANGUAGES, type Lang, useI18n } from '../i18n';

/** Directory (LDAP/AD) or break-glass sign-in. The language can be chosen before signing in. */
export function LoginPage() {
  const { login } = useAuth();
  const { t, lang, setLanguage } = useI18n();
  const [loginName, setLoginName] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(loginName, password);
    } catch (err) {
      setError(err);
      setPassword('');
    } finally {
      setBusy(false);
    }
  }

  return (
    <Box minHeight="100vh" display="flex" alignItems="center" justifyContent="center" px={2} bgcolor="background.default">
      <Card variant="outlined" sx={{ width: '100%', maxWidth: 380 }}>
        <CardContent component="form" onSubmit={submit} sx={{ display: 'grid', gap: 2 }}>
          <Box display="flex" justifyContent="space-between" alignItems="flex-start" gap={1}>
            <Box>
              <Typography variant="h5" component="h1" sx={{ fontWeight: 600 }}>
                {t('app.name')}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {t('app.tagline')}
              </Typography>
            </Box>
            <ToggleButtonGroup
              size="small"
              exclusive
              value={lang}
              onChange={(_, v: Lang | null) => v && setLanguage(v)}
              aria-label={t('user.language')}
            >
              {LANGUAGES.map((l) => (
                <ToggleButton key={l} value={l} lang={l} sx={{ px: 1, py: 0.25 }}>
                  {l.toUpperCase()}
                </ToggleButton>
              ))}
            </ToggleButtonGroup>
          </Box>
          {error !== null && <ErrorPanel error={error} />}
          <TextField
            label={t('login.nameField')}
            value={loginName}
            onChange={(e) => setLoginName(e.target.value)}
            autoComplete="username"
            autoFocus
            required
          />
          <TextField
            label={t('login.passwordField')}
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
          <Button type="submit" variant="contained" disabled={busy || !loginName || !password}>
            {busy ? t('login.submitting') : t('login.submit')}
          </Button>
        </CardContent>
      </Card>
    </Box>
  );
}
